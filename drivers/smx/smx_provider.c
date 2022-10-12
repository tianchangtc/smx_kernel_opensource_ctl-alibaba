#include <asm/tlbflush.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/genalloc.h>
#include <linux/if_ether.h>
#include <linux/fs.h>
#include <linux/pfn_t.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/uaccess.h>
#include <linux/hugetlb.h>

#include "smx.h"
#include "smx_internal.h"
#include "util.h"
#include "migration.h"

static int smx_provider_major;

static int smx_provider_open(struct inode *inode, struct file *file)
{
	struct smx_provider *smxp = container_of(inode->i_cdev, typeof(*smxp), cdev);

	get_device(&smxp->dev);
	file->private_data = smxp;

	return 0;
}

static long
smx_provider_ioctl_get_version(struct smx_provider *smxp, void __user *arg)
{
	/*
	 * FIXME: After we have the real hardware, we will need to read a few
	 * MMIO registers to determine the version. Currently, just assume it
	 * to be a fixed value.
	 */
	uint64_t version = SMX_VERSION;

	if (copy_to_user(arg, &version, sizeof(uint64_t)))
		return -EFAULT;

	return 0;
}

static int
smx_provider_check_2m_pages(struct smx_provider *smxp, struct smx_provider_map_info *info)
{
	struct vm_area_struct *vma = find_vma(current->mm, info->base);
	uint64_t off;
	uint64_t pgsize;

	/* Currently, SMX provider must use 2M hugetlb pages */
	pgsize = vma_kernel_pagesize(vma);
	if (pgsize != SZ_2M)
		return -EINVAL;
	for (off = SZ_2M; off < info->size; off += SZ_2M) {
		struct vm_area_struct *vma_iter;

		vma_iter = find_vma(current->mm, info->base + off);
		if (vma_iter == vma)
			continue;
		if (vma_kernel_pagesize(vma_iter) != SZ_2M)
			return -EINVAL;
		else
			vma = vma_iter;
	}

	return 0;
}

static int
smx_provider_pin_pages(struct smx_provider *smxp, struct file *file,
		       struct smx_provider_map_info *info)
{
	uint64_t n_4k_pages = info->size / PAGE_SIZE;
	uint64_t pinned;
	int rc = 0, i;
	struct smx_provider_memory_region *region =
		vzalloc(sizeof(*region) + sizeof(struct page *) * n_4k_pages);

	rc = smx_provider_check_2m_pages(smxp, info);
	if (rc)
		return rc;

	pinned = get_user_pages_fast(info->base, n_4k_pages, 1, region->pages);
	if (pinned != n_4k_pages) {
		dev_err(&smxp->dev, "cannot pin pages, expected %lld pinned %lld\n",
			n_4k_pages, pinned);
		rc = -EFAULT;

		goto err_put_pages;
	}

	rc = ida_alloc_range(&smxp->ida, 0, SMX_MAX_DEVICES, GFP_KERNEL);
	if (rc < 0) {
		dev_err(&smxp->dev, "id allocation failed\n");
		mutex_unlock(&smxp->mutex);
		goto err_put_pages;
	}
	region->id = rc;
	region->provider = smxp;
	region->size = info->size;
	region->file = file;
	info->id = rc;

	mutex_lock(&smxp->mutex);
	list_add(&region->node, &smxp->pinned_regions);
	mutex_unlock(&smxp->mutex);

	/*
	 * TODO: After having the hardware, we should configure the hardware
	 * with the physical address.
	 */

	info->dva = gen_pool_alloc(smxp->address_space, info->size);
	if (!info->dva) {
		dev_err(&smxp->dev, "unable to allocate %llu in device VA space\n",
			info->size);
		rc = -ENOMEM;
		goto err_remove_region;
	}
	region->dva = info->dva;

	return 0;

err_remove_region:
	ida_free(&smxp->ida, region->id);

	mutex_lock(&smxp->mutex);
	list_del(&region->node);
	mutex_unlock(&smxp->mutex);
err_put_pages:
	for (i = 0; i < pinned; i++) {
		put_page(region->pages[i]);
	}
	vfree(region);

	return rc;
}

static int
smx_provider_unpin_pages(struct smx_provider *smxp, struct smx_provider_map_info *info)
{
	struct smx_provider_memory_region *region;
	int i;

	mutex_lock(&smxp->mutex);
	list_for_each_entry(region, &smxp->pinned_regions, node) {
		if (region->id == info->id) {
			list_del(&region->node);
			break;
		}
	}
	mutex_unlock(&smxp->mutex);

	gen_pool_free(smxp->address_space, region->dva, region->size);
	ida_free(&smxp->ida, region->id);

	for (i = 0; i < region->size / PAGE_SIZE; i++) {
		put_page(region->pages[i]);
	}
	vfree(region);

	return 0;
}

static int
smx_provider_unpin_all_regions_file(struct smx_provider *smxp, struct file *file)
{
	struct smx_provider_memory_region *region, *tmp_region;
	int i;

	mutex_lock(&smxp->mutex);
	list_for_each_entry_safe(region, tmp_region, &smxp->pinned_regions, node) {
		if (region->file != file)
			continue;

		list_del(&region->node);
		gen_pool_free(smxp->address_space, region->dva, region->size);
		ida_free(&smxp->ida, region->id);

		for (i = 0; i < region->size / PAGE_SIZE; i++) {
			put_page(region->pages[i]);
		}

		vfree(region);
	}
	mutex_unlock(&smxp->mutex);

	return 0;
}

static long
smx_provider_ioctl_map_region(struct smx_provider *smxp, struct file *file, void __user *arg)
{
	struct smx_provider_map_info info;
	int rc;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	rc = smx_provider_pin_pages(smxp, file, &info);
	if (rc)
		return rc;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long
smx_provider_ioctl_unmap_region(struct smx_provider *smxp, void __user *arg)
{
	struct smx_provider_map_info info;
	int rc;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	rc = smx_provider_unpin_pages(smxp, &info);
	if (rc)
		return rc;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long smx_provider_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct smx_provider *smxp = file->private_data;

	dev_dbg(&smxp->dev, "ioctl cmd=%x, arg=%lx\n", cmd, arg);

	switch(cmd) {
	case SMX_PROVIDER_GET_VERSION:
		return smx_provider_ioctl_get_version(smxp, (void __user *)arg);
	case SMX_PROVIDER_MAP_REGION:
		return smx_provider_ioctl_map_region(smxp, file, (void __user *)arg);
	case SMX_PROVIDER_UNMAP_REGION:
		return smx_provider_ioctl_unmap_region(smxp, (void __user *)arg);
	default:
		return -EINVAL;
	}
}

static int smx_provider_release_file(struct inode *inode, struct file *file)
{
	struct smx_provider *smxp = container_of(inode->i_cdev, typeof(*smxp), cdev);
	int rc;

	put_device(&smxp->dev);
	rc = smx_provider_unpin_all_regions_file(smxp, file);

	if (rc) {
		dev_err(&smxp->dev, "relaseing file failed\n");
	}

	return rc;
}

static const struct file_operations smx_provider_fops = {
	.owner = THIS_MODULE,
	.open = smx_provider_open,
	.release = smx_provider_release_file,
	.unlocked_ioctl = smx_provider_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

int smx_provider_init(void)
{
	dev_t devt;
	int rc;

	rc = alloc_chrdev_region(&devt, 0, SMX_MAX_DEVICES, "smx-provider");
	if (rc)
		return rc;
	smx_provider_major = MAJOR(devt);

	return 0;
}

void smx_provider_exit(void)
{
	unregister_chrdev_region(MKDEV(smx_provider_major, 0), SMX_MAX_DEVICES);
}

static char *
smx_provider_devnode(struct device *dev, umode_t *mode, kuid_t *uid, kgid_t *gid)
{
	if (mode)
		*mode = 0666;

	return kasprintf(GFP_KERNEL, "smx/%s", dev_name(dev));
}

static void smx_provider_release(struct device *dev)
{
	dev_dbg(dev, "releasing\n");
}

static const struct device_type smx_provider_type = {
	.name = "smx_provider",
	.devnode = smx_provider_devnode,
	.release = smx_provider_release,
};

int smx_device_initialize_provider(struct smx_device *smxdev)
{
	/*
	 * TODO: A well-design hardware should expose these information
	 * through a few MMIO registers.
	 */
	const int order = ilog2(SMX_PROVIDER_GRANULARITY);
	struct smx_provider *smxp = &smxdev->provider;
	struct device *dev = &smxp->dev;
	struct cdev *cdev = &smxp->cdev;
	int rc = 0;
	struct gen_pool *pool;

	mutex_init(&smxp->mutex);
	device_initialize(dev);
	dev->parent = &smxdev->dev;
	dev->devt = MKDEV(smx_provider_major, smxdev->id);
	dev->type = &smx_provider_type;
	device_set_pm_not_required(dev);
	dev->class = smx_class;

	cdev_init(cdev, &smx_provider_fops);

	INIT_LIST_HEAD(&smxp->pinned_regions);

	rc = dev_set_name(dev, "smx%dp", smxdev->id);
	if (rc)
		goto err;

	rc = cdev_device_add(cdev, dev);
	if (rc)
		goto err_put;

	pool = devm_gen_pool_create(dev, order, NUMA_NO_NODE, dev_name(dev));
	if (IS_ERR(pool)) {
		rc = PTR_ERR(pool);
		goto err_cdev_del;
	}

	rc = gen_pool_add(pool, SMX_PROVIDER_DVA_BASE, SMX_PROVIDER_SIZE, NUMA_NO_NODE);
	if (rc)
		goto err_cdev_del;

	smxp->address_space = pool;
	smxp->address_space_size = SMX_PROVIDER_SIZE;

	ida_init(&smxp->ida);

	return 0;

err_cdev_del:
	cdev_device_del(&smxp->cdev, &smxp->dev);
err_put:
	put_device(&smxp->dev);
err:
	return rc;
}

void smx_device_uninitialize_provider(struct smx_device *smxdev)
{
	struct smx_provider *smxp = &smxdev->provider;

	cdev_device_del(&smxp->cdev, &smxp->dev);
	put_device(&smxp->dev);
}
