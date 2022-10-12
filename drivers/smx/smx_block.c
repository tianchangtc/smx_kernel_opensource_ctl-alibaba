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

#include "smx_internal.h"
#include "util.h"
#include "migration.h"

static DEFINE_IDA(smx_block_ida);
static int smx_block_major;
static struct workqueue_struct *smx_block_wq;

static int __try_allocate_address_space(struct smx_block *smxblk, uint64_t size, uint64_t *start);

int smx_block_init(void)
{
	dev_t devt;
	int rc;

	/*
	 * The work queue will be used to launch the memory migration thread.
	 * To save CPU resource, there's only one work queue for all blocks.
	 */
	smx_block_wq = alloc_ordered_workqueue("smx_block_wq", 0);
	if (!smx_block_wq)
		return -ENOMEM;

	/*
	 * The char device major must be allocated before the first block can
	 * be created, and must be freed before the module is unloaded.
	 * A major serves all blocks. Each block has a common major and a minor
	 * allocated by smx_block_ida.
	 */
	rc = alloc_chrdev_region(&devt, 0, SMX_MAX_BLOCKS, "smx-block");
	if (rc)
		return rc;
	smx_block_major = MAJOR(devt);

	return 0;
}

void smx_block_exit(void)
{
	unregister_chrdev_region(MKDEV(smx_block_major, 0), SMX_MAX_BLOCKS);
	destroy_workqueue(smx_block_wq);
}

/*
 * TODO: The below two functions need to be reimplemented after having the hardware.
 * We should use the MMIO registers to configure the destination table in SMX device.
 */
static int
smx_fill_half_slice(struct smx_block *smxblk, struct smx_half_slice *hs, uint8_t *rmac,
		    uint64_t r_half_slice_num, bool migrate)
{
	memcpy(hs->hwaddr, rmac, ETH_ALEN);
	hs->base_half_slice_num = r_half_slice_num;
	hs->configured = 1;

	if (!migrate) {
		/* TODO: program the hardware, currently unimplemented */
		smxblk->nr_configured_half_slices++;
	}

	return 0;
}

static int
smx_clear_half_slice(struct smx_block *smxblk, struct smx_half_slice *hs)
{
	memset(hs->hwaddr, 0, ETH_ALEN);
	hs->base_half_slice_num = 0;
	hs->configured = 0;

	/* TODO: program the hardware */

	smxblk->nr_configured_half_slices--;

	return 0;
}

static ssize_t
nr_full_slices_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_block *smxblk = to_smx_block(dev);

	return sprintf(buf, "%lld\n", smxblk->size / SMX_SLICE_SIZE);
}
static DEVICE_ATTR_RO(nr_full_slices);

static ssize_t
nr_half_slices_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_block *smxblk = to_smx_block(dev);

	return sprintf(buf, "%lld\n", smxblk->size / SMX_HALF_SLICE_SIZE);
}
static DEVICE_ATTR_RO(nr_half_slices);

static ssize_t
nr_configured_half_slices_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_block *smxblk = to_smx_block(dev);

	return sprintf(buf, "%lld\n", smxblk->nr_configured_half_slices);
}
static DEVICE_ATTR_RO(nr_configured_half_slices);

static ssize_t
size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_block *smxblk = to_smx_block(dev);

	return sprintf(buf, "%lld\n", smxblk->size);
}
static DEVICE_ATTR_RO(size);

static ssize_t
remote_config_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	struct smx_block *smxblk = to_smx_block(dev);
	struct smx_half_slice *hs;
	uint64_t i, last_half_slice;
	uint64_t r_addr, r_size;
	uint64_t r_half_slice_num, r_nr_half_slices, r_half_slice_num_end;
	uint8_t rmac[ETH_ALEN];
	int rc;

	if (smxblk->occupied) {
		dev_err(dev, "block in use, should not be configured\n");
		return -EBUSY;
	}

	rc = smx_parse_remote_config(buf, len, rmac, &r_addr, &r_size);
	if (rc) {
		dev_err(dev, "parsing config failed, config: %s\n", buf);
		return rc;
	}
	r_half_slice_num = r_addr / SMX_HALF_SLICE_SIZE;
	r_nr_half_slices = r_size / SMX_HALF_SLICE_SIZE;
	r_half_slice_num_end = r_half_slice_num + r_nr_half_slices;

	/*
	 * TODO: Currently, we assume provided remote memory size is aligned to a full
	 * block, as this will make migration easier, especially wrt how migration
	 * should be configured.
	 */
	if (r_nr_half_slices % 2 != 0) {
		BUG();
		return -EINVAL;
	}

	smx_block_lock_exclusive(smxblk);
	last_half_slice = smxblk->nr_configured_half_slices + r_nr_half_slices;
	for (i = smxblk->nr_configured_half_slices; i < last_half_slice; i++) {
		/* sanity check */
		BUG_ON(NR_HALF_SLICES(smxblk) < smxblk->nr_configured_half_slices);

		if (NR_HALF_SLICES(smxblk) == smxblk->nr_configured_half_slices) {
			dev_err(dev, "all half_slices are configured, ignoring [0x%llx-0x%llx]\n",
				r_half_slice_num * SMX_HALF_SLICE_SIZE,
				r_half_slice_num_end * SMX_HALF_SLICE_SIZE);
			break;
		}

		hs = GET_HALF_SLICE_BY_OFFSET(smxblk, i);
		if (!hs->configured) {
			dev_dbg(dev, "configuring hs %lld: %pM %#llx\n", i, rmac, r_half_slice_num);
			smx_fill_half_slice(smxblk, hs, rmac, r_half_slice_num, false);
			r_half_slice_num++;
		} else {
			BUG();
		}
	}
	smx_block_unlock_exclusive(smxblk);

	return len;
}
static DEVICE_ATTR_WO(remote_config);

static ssize_t
migrate_config_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	struct smx_block *smxblk = to_smx_block(dev);
	uint64_t new_r_addr, new_r_size;
	uint64_t r_half_slice_num, r_nr_half_slices, r_half_slice_num_end;
	uint64_t r_nr_slices;
	uint8_t old_rmac[ETH_ALEN], new_rmac[ETH_ALEN];
	int rc;
	uint64_t i, j, k;
	uint64_t cnt;

	smx_block_lock_exclusive(smxblk);

	if (!smxblk->occupied) {
		dev_err(dev, "block not in use, why migrate?\n");
		rc = -EINVAL;
		goto err_unlock;
	}

	if (smxblk->during_migration) {
		dev_err(dev, "something is being migrated, only one task supported at a time\n");
		rc = -EINVAL;
		goto err_unlock;
	}

	rc = smx_parse_migrate_config(buf, len, old_rmac, new_rmac, &new_r_addr, &new_r_size);
	if (rc) {
		dev_err(dev, "parsing migration configuration failed, config: %s\n", buf);
		goto err_unlock;
	}
	r_half_slice_num = new_r_addr / SMX_HALF_SLICE_SIZE;
	r_nr_half_slices = new_r_size / SMX_HALF_SLICE_SIZE;
	r_nr_slices = new_r_size / SMX_SLICE_SIZE;
	r_half_slice_num_end = r_half_slice_num + r_nr_half_slices;

	/* sanity check */
	cnt = 0;
	for (i = 0; i < NR_SLICES(smxblk); i++) {
		struct smx_full_slice *slice = &smxblk->slices[i];

		if (memcmp(slice->half[0].hwaddr, old_rmac, ETH_ALEN) ||
		    memcmp(slice->half[1].hwaddr, old_rmac, ETH_ALEN))
			continue;

		cnt += 1;
	}
	dev_dbg(&smxblk->dev, "configured slices at %pM: %lld, new slices: %lld\n",
		old_rmac, cnt, r_nr_slices);
	if (cnt != r_nr_slices) {
		dev_err(&smxblk->dev, "number of new slices not match\n");
		rc = -EINVAL;
		goto err_unlock;
	}

	for (i = 0; i < NR_SLICES(smxblk); i++) {
		struct smx_full_slice *slice = &smxblk->slices[i];
		uint64_t pa;
		void *va;

		if (memcmp(slice->half[0].hwaddr, old_rmac, ETH_ALEN) ||
		    memcmp(slice->half[1].hwaddr, old_rmac, ETH_ALEN))
			continue;

		/*
		 * The size of dirty bitmap is twice of the necessary size.
		 * We intentionally choose to do this for the same reason
		 * as KVM's live migration implementation, i.e., the second
		 * half of the dirty bitmap is used as a buffer.
		 * */
		if (slice->dirty_bitmap || slice->migration_dest)
			BUG();

		slice->dirty_bitmap = vzalloc(SMX_SLICE_DIRTY_BITMAP_SIZE * 2);
		/*
		 * After allocating the dirty bitmap, we need to mark all pages
		 * as dirty, because all pages need to be copied in the first
		 * round of pre-copy.
		 */
		memset(slice->dirty_bitmap, ~0, SMX_SLICE_DIRTY_BITMAP_SIZE * 2);

		slice->migration_dest = kzalloc(sizeof(struct smx_full_slice), GFP_KERNEL);
		slice->migration_meta =
			vzalloc(sizeof(struct smx_migration_meta) * SMX_MIG_META_PER_SLICE);
		for (k = 0; k < SMX_MIG_META_PER_SLICE; k++) {
			spin_lock_init(&slice->migration_meta[k].lock);
		}

		/*
		 * Next, we should allocate the address space for the new region.
		 */
		rc = __try_allocate_address_space(smxblk, SMX_SLICE_SIZE, &pa);
		if (rc) {
			dev_err(&smxblk->dev, "unable to find address space\n");
			goto err_unlock;
		}
		va = ioremap_cache(pa, SMX_SLICE_SIZE);
		if (!va) {
			dev_err(&smxblk->dev, "unable to map address\n");
			rc = -EINVAL;
			goto err_unlock;
		}
		slice->migration_dest->pa = pa;
		slice->migration_dest->va = va;

		dev_dbg(&smxblk->dev, "migration dest pa: %#llx, va: %#llx\n", pa, (uint64_t)va);

		/*
		 * Next, we configure the migration destination.
		 */
		for (j = 0; j < 2; j++) {
			struct smx_half_slice *old_hs = &slice->half[j];
			struct smx_half_slice *new_hs = &slice->migration_dest->half[j];

			smx_fill_half_slice(smxblk, new_hs, new_rmac, r_half_slice_num, true);
			r_half_slice_num++;

			dev_dbg(&smxblk->dev, "va %llx replacing hs %lld: %pM %#x --> %pM %#x\n",
				smx_full_slice_to_va(smxblk, slice), i * 2 + j,
				old_hs->hwaddr, old_hs->base_half_slice_num,
				new_hs->hwaddr, new_hs->base_half_slice_num);
		}

	}
	smx_block_unlock_exclusive(smxblk);

	return len;

err_unlock:
	smx_block_unlock_exclusive(smxblk);
	return rc;
}
static DEVICE_ATTR_WO(migrate_config);

static ssize_t protect_migrate_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t len)
{
	struct smx_block *smxblk = to_smx_block(dev);

	smx_block_lock_exclusive(smxblk);
	smxblk->during_migration = true;
	smx_block_unlock_exclusive(smxblk);

	/*
	 * Theoretically, the following function call can be omitted, as all
	 * pages are initially marked as dirty.
	 */
	smx_protect_migration_slices(smxblk);

	/*
	 * Launching the migration worker. The worker will be launched in
	 * a different kernel thread that does not have access to user
	 * memory directly.
	 */
	INIT_DELAYED_WORK(&smxblk->migration_work, smx_migration_work);
	queue_delayed_work(smx_block_wq, &smxblk->migration_work, 0);

	return len;
}
static DEVICE_ATTR_WO(protect_migrate);

/*
 * This function is to test kernel APIs and is not used anywhere formally.
 */
static ssize_t protect_all_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t len)
{
	struct smx_block *smxblk = to_smx_block(dev);
	struct vm_area_struct *vma = smxblk->vma;
	struct mmu_notifier_range range;
	uint64_t addr, offset;
	spinlock_t *ptl;
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep, pte;

	if (vma == NULL)
		return -EINVAL;

	printk("protect_all started\n");

	smx_block_lock_exclusive(smxblk);

	//mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
	//		vma->vm_start, vma->vm_end);
	//mmu_notifier_invalidate_range_start(&range);

	for (addr = vma->vm_start; addr < vma->vm_start + SZ_128M; addr += PMD_SIZE) {
		pgdp = pgd_offset(vma->vm_mm, addr);
		if (!pgd_present(*pgdp))
			continue;
		p4dp = p4d_offset(pgdp, addr);
		if (!p4d_present(*p4dp))
			continue;
		pudp = pud_offset(p4dp, addr);
		if (!pud_present(*pudp))
			continue;
		pmdp = pmd_offset(pudp, addr);
		if (!pmd_present(*pmdp))
			continue;
		if (pmd_large(*pmdp)) {
			ptl = pmd_lock(vma->vm_mm, pmdp);
			pmdp_huge_clear_flush_notify(vma, addr, pmdp);
			spin_unlock(ptl);
		} else {
			for (offset = 0; offset < PMD_SIZE; offset += PAGE_SIZE) {
				mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
						0, vma, vma->vm_mm,
						addr + offset, addr + offset + PAGE_SIZE);
				mmu_notifier_invalidate_range_start(&range);

				ptep = pte_offset_map_lock(vma->vm_mm, pmdp, (addr + offset), &ptl);
				if (!pte_present(*ptep)) {
					printk("pte %#llx does not exist\n", addr + offset);
					goto unlock_pte;
				}
				if (!pte_write(*ptep)) {
					printk("pte %#llx not writable\n", addr + offset);
					goto unlock_pte;
				}

				pte = ptep_clear_flush_notify(vma, (addr + offset), ptep);

				pte = pte_wrprotect(pte);
				pte = pte_mkclean(pte);
				set_pte_at_notify(vma->vm_mm, (addr + offset), ptep, pte);
unlock_pte:
				pte_unmap_unlock(ptep, ptl);
				mmu_notifier_invalidate_range_end(&range);
			}
		}
	}

	//mmu_notifier_invalidate_range_end(&range);

	smx_block_unlock_exclusive(smxblk);

	printk("protect_all finishes\n");

	return len;
}
static DEVICE_ATTR_WO(protect_all);

/*
 * This function is to test kernel APIs and is not used anywhere formally.
 */
static ssize_t
split_huge_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	struct smx_block *smxblk = to_smx_block(dev);
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t addr;

	if (vma == NULL || smxblk->pgsize != SZ_2M)
		return -EINVAL;

	smx_block_lock_exclusive(smxblk);
	smxblk->huge_splitted = true;
	for (addr = vma->vm_start; addr < vma->vm_end; addr += SZ_2M) {
		split_huge_pmd_address(vma, addr, false, NULL);
	}
	smx_block_unlock_exclusive(smxblk);

	return len;
}
static DEVICE_ATTR_WO(split_huge);

static bool is_splitted_pmd(pmd_t *pmd)
{
	if (pmd_large(*pmd))
		return false;
	else
		return true;
}

/*
 * This function is to test kernel APIs and is not used anywhere formally.
 */
static ssize_t
verify_splitted_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_block *smxblk = to_smx_block(dev);
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t addr;
	ssize_t rc;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	smx_block_lock_exclusive(smxblk);
	if (!smxblk->huge_splitted) {
		rc = sprintf(buf, "false\n");
		goto out_unlock;
	}
	for (addr = vma->vm_start; addr < vma->vm_end; addr += SZ_2M) {
		/*
		 * We should be able to optimize this because a pgd contains
		 * a bunch of p4d/pud/pmds, but this is just a test function.
		 */
		pgd = pgd_offset(vma->vm_mm, addr);
		if (!pgd_present(*pgd))
			continue;
		p4d = p4d_offset(pgd, addr);
		if (!p4d_present(*p4d))
			continue;
		pud = pud_offset(p4d, addr);
		if (!pud_present(*pud))
			continue;
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			continue;
		if (!is_splitted_pmd(pmd)) {
			rc = sprintf(buf, "false\n");
			goto out_unlock;
		}
	}
	rc = sprintf(buf, "true\n");
out_unlock:
	smx_block_unlock_exclusive(smxblk);

	return rc;
}
static DEVICE_ATTR_RO(verify_splitted);

static struct attribute *smx_block_controls[] = {
	&dev_attr_size.attr,
	&dev_attr_nr_full_slices.attr,
	&dev_attr_nr_half_slices.attr,
	&dev_attr_nr_configured_half_slices.attr,
	&dev_attr_remote_config.attr,
	NULL,
};

/*
 * TODO: These attributes are for testing purpose and should be removed from
 * the final release version.
 */
static struct attribute *smx_block_tests[] = {
	&dev_attr_split_huge.attr,
	&dev_attr_verify_splitted.attr,
	&dev_attr_protect_all.attr,
	&dev_attr_migrate_config.attr,
	&dev_attr_protect_migrate.attr,
	NULL,
};

static const struct attribute_group smx_block_control_group = {
	.name = "control",
	.attrs = smx_block_controls,
};

static const struct attribute_group smx_block_test_group = {
	.name = "test",
	.attrs = smx_block_tests,
};

static const struct attribute_group *smx_block_attribute_groups[] = {
	&smx_block_control_group,
	&smx_block_test_group,
	NULL,
};

static void smx_block_release(struct device *dev)
{
	struct smx_block *smxblk = to_smx_block(dev);
	struct smx_device *smxdev = smx_block_get_parent(smxblk);

	dev_dbg(dev, "releasing physical resource\n");

	ida_free(&smxdev->ida, smxblk->id);
	ida_free(&smx_block_ida, smxblk->global_id);
	kfree(smxblk);
}

/* This function creates the file under /dev/smx. */
static char *
smx_block_devnode(struct device *dev, umode_t *mode, kuid_t *uid, kgid_t *gid)
{
	/* Make the device accessible by everyone. */
	if (mode)
		*mode = 0666;

	return kasprintf(GFP_KERNEL, "smx/%s", dev_name(dev));
}

static const struct device_type smx_block_type = {
	.name = "smx_block",
	.release = smx_block_release,
	.devnode = smx_block_devnode,
	.groups = smx_block_attribute_groups,
};

static int smx_block_open(struct inode *inode, struct file *file)
{
	struct smx_block *smxblk = container_of(inode->i_cdev, typeof(*smxblk), cdev);
	int rc;

	/*
	 * Currently, we only allow a block to be opened by one user process
	 * for a single time.
	 */
	smx_block_lock_exclusive(smxblk);
	if (smxblk->occupied) {
		rc = -EBUSY;
	} else {
		smxblk->occupied = true;
		get_device(&smxblk->dev);
		file->private_data = smxblk;
		rc = 0;
	}
	smx_block_unlock_exclusive(smxblk);

	return rc;
}

static int smx_block_release_file(struct inode *inode, struct file *file)
{
	struct smx_block *smxblk = container_of(inode->i_cdev, typeof(*smxblk), cdev);

	smxblk->vma = NULL;

	smx_block_lock_exclusive(smxblk);
	put_device(&smxblk->dev);
	smxblk->occupied = false;
	smxblk->during_migration = false;
	smx_block_unlock_exclusive(smxblk);

	return 0;
}

static int smx_block_mmap_sanity_check(struct smx_block *smxblk, struct vm_area_struct *vma)
{
	uint64_t offset = vma->vm_pgoff << PAGE_SHIFT;
	uint64_t vma_size = vma->vm_end - vma->vm_start;
	uint64_t blk_size = smxblk->size;
	int i;

	if (offset != 0) {
		dev_err(&smxblk->dev, "offset=0x%llx not supported\n", offset);
		return -EINVAL;
	}

	if (vma_size != blk_size) {
		dev_err(&smxblk->dev,
			"vma size and block size do not match, vma_size=0x%llx, blk_size=0x%llx\n",
			vma_size, blk_size);
		return -EINVAL;
	}

	for (i = 0; i < NR_SLICES(smxblk); i++) {
		if (!smxblk->slices[i].half[0].configured ||
		    !smxblk->slices[i].half[1].configured) {
			dev_err(&smxblk->dev, "slices not configured\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int smx_block_check_fault(struct smx_block *smxblk, struct vm_fault *vmf,
				     unsigned int fault_size, const char *func)
{
	unsigned long mask = smxblk->pgsize - 1;

	if (vmf->vma->vm_start & mask || vmf->vma->vm_end & mask) {
		dev_err(&smxblk->dev, "%s: unaligned vma (%#lx - %#lx, %#lx)\n",
			func, vmf->vma->vm_start, vmf->vma->vm_end, mask);
		return -EINVAL;
	}

	if (unlikely(fault_size == PUD_SIZE)) {
		/*
		 * Control should never reach here. Huge fault with PUD_SIZE should directly
		 * result in a fallback.
		 */
		BUG();
		return -EINVAL;
	}

	return 0;
}

static vm_fault_t __smx_block_pte_fault(struct smx_block *smxblk, struct vm_fault *vmf)
{
	struct device *dev = &smxblk->dev;
	phys_addr_t phys;
	unsigned int fault_size = PAGE_SIZE;
	struct mmu_notifier_range range;
	struct vm_area_struct *vma = vmf->vma;
	pgoff_t pgoff = vmf->pgoff;
	struct smx_full_slice *slice = smx_block_get_slice_by_pgoff(smxblk, pgoff);
	pte_t *pte, entry;
	spinlock_t *ptl, *smxl;
	int stage;
	int rc = VM_FAULT_NOPAGE;
	bool during_postcopy = false;

	if (smx_block_check_fault(smxblk, vmf, fault_size, __func__))
		return VM_FAULT_SIGBUS;

	if (smxblk->during_migration) {
		stage = smx_migration_get_locked_stage(slice, pgoff, &smxl);

		printk("pgfault during mig: pgoff=%lx\n", pgoff);

		during_postcopy = (stage == SMX_MIG_STAGE_POSTCOPY);
		if (during_postcopy) {
			/*
			 * If it's during postcopy, we need to actually perform the memory copy
			 * before we can insert the PTE. Besides, we also need to clear the bitmap
			 * so the postcopy worker will not handle it again.
			 */
			bool dirty;
			uint64_t offset;

			/*
			 * We test and clear the dirty bitmap first. If the page is not dirty,
			 * and is faulted here, this is a newly accessed page, so no need to
			 * do the memory copy.
			 */
			offset = ((pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE) >> PAGE_SHIFT;
			dirty = test_and_clear_bit_le(offset, slice->dirty_bitmap);
			if (dirty) {
				void *old_va = slice->va + (pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE;
				void *new_va = slice->migration_dest->va +
					(pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE;
				memcpy(new_va, old_va, PAGE_SIZE);
			}
		}
	}

	phys = smx_block_get_pa_by_pgoff(smxblk, vmf->pgoff, fault_size, during_postcopy);
	if (phys == -1) {
		dev_err(dev, "cannot find pa for pgoff %#lx\n", vmf->pgoff);
		rc = VM_FAULT_SIGBUS;
		goto out_unlock_smxl;
	}

	pte = get_locked_pte(vma->vm_mm, vmf->address, &ptl);

	if (!pte) {
		rc = VM_FAULT_OOM;
		BUG();
		goto out_unlock_smxl;
	}
	if (!pte_none(*pte)) {
		/*
		 * If the PTE presents, it may be already handled by someone else, e.g.,
		 * the postcopy working thread or another faulting core. Handling the
		 * page fault requires holding the PTE lock, which we already hold. As a
		 * result, we can return directly.
		 * Notably, a write fault of an existing PTE should not enter here. These
		 * faults will be handled by the pfn_mkwrite callback.
		 */
		rc = VM_FAULT_NOPAGE;
		goto out_unlock_ptl;
	}

	/*
	 * We need to mark the page as devmap, since this will work around some weird
	 * checks in KVM and kernel. See smx_block_mmap() for more details.
	 */
	entry = pte_mkdevmap(pfn_pte(phys >> PAGE_SHIFT, vma->vm_page_prot));

	mmu_notifier_range_init(&range, MMU_NOTIFY_MIGRATE,
				0, vma, vma->vm_mm, vmf->address, vmf->address + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);
	set_pte_at_notify(vma->vm_mm, vmf->address, pte, entry);
	mmu_notifier_invalidate_range_end(&range);

	rc = VM_FAULT_NOPAGE;

out_unlock_ptl:
	pte_unmap_unlock(pte, ptl);
out_unlock_smxl:
	if (smxblk->during_migration)
		smx_migration_unlock(smxl);

	return rc;
}

static vm_fault_t __smx_block_pmd_fault(struct smx_block *smxblk, struct vm_fault *vmf)
{
	struct device *dev = &smxblk->dev;
	phys_addr_t phys;
	pfn_t pfn;
	unsigned int fault_size = PMD_SIZE;

	if (smxblk->pgsize < fault_size)
		return VM_FAULT_FALLBACK;

	if (smxblk->huge_splitted)
		return VM_FAULT_FALLBACK;

	/* During migration, all page fault should be handled at 4K granularity */
	if (smxblk->during_migration)
		return VM_FAULT_FALLBACK;

	if (smx_block_check_fault(smxblk, vmf, fault_size, __func__))
		return VM_FAULT_SIGBUS;

	phys = smx_block_get_pa_by_pgoff(smxblk, vmf->pgoff, fault_size, false);
	if (phys == -1) {
		dev_err(dev, "cannot find pa for pgoff %#lx\n", vmf->pgoff);
		return VM_FAULT_SIGBUS;
	}

	/* FIXME */
	pfn = phys_to_pfn_t(phys, PFN_DEV|PFN_MAP);

	return vmf_insert_pfn_pmd(vmf, pfn, true);
}

static vm_fault_t smx_block_huge_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	struct vm_area_struct *vma = vmf->vma;
	struct file *filp = vma->vm_file;
	vm_fault_t rc = VM_FAULT_SIGBUS;
	struct smx_block *smxblk = filp->private_data;

	// dev_dbg(&smxblk->dev, "%s: %s (%#lx - %#lx) offset = %#lx, size = %d\n",
	//	__func__, vmf->flags & FAULT_FLAG_WRITE ? "write" : "read",
	//	vma->vm_start, vma->vm_end, vmf->pgoff, pe_size);

	/*
	 * TODO: Using an exclusive lock here is terrible, we should have a finer
	 * granularity.
	 */
	smx_block_lock_shared(smxblk);
	switch (pe_size) {
	case PE_SIZE_PTE:
		rc = __smx_block_pte_fault(smxblk, vmf);
		break;
	case PE_SIZE_PMD:
		rc = __smx_block_pmd_fault(smxblk, vmf);
		break;
	case PE_SIZE_PUD:
		dev_dbg(&smxblk->dev, "page fault PUD size, falling back\n");
		rc = VM_FAULT_FALLBACK;
		break;
	default:
		rc = VM_FAULT_SIGBUS;
	}
	smx_block_unlock_shared(smxblk);

	return rc;
}

static vm_fault_t smx_block_fault(struct vm_fault *vmf)
{
	return smx_block_huge_fault(vmf, PE_SIZE_PTE);
}

static int smx_block_may_split(struct vm_area_struct *vma, unsigned long addr)
{
	struct file *filp = vma->vm_file;
	struct smx_block *smxblk = filp->private_data;

	if (!IS_ALIGNED(addr, smxblk->pgsize))
		return -EINVAL;
	return 0;
}

static unsigned long smx_block_pagesize(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct smx_block *smxblk = filp->private_data;

	return smxblk->pgsize;
}

static vm_fault_t smx_block_pfn_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct file *filp = vma->vm_file;
	struct smx_block *smxblk = filp->private_data;
	struct smx_full_slice *slice = smx_block_get_slice_by_pgoff(smxblk, vmf->pgoff);
	int stage;
	int rc = VM_FAULT_WRITE;
	spinlock_t *smxl;

	// printk("%s: pte=%lx pgoff=%lx\n", __func__, pte_val(*vmf->pte), vmf->pgoff);

	smx_block_lock_shared(smxblk);

	if (!smxblk->during_migration)
		goto out_blk_unlock;

	stage = smx_migration_get_locked_stage(slice, vmf->pgoff, &smxl);

	if (stage == SMX_MIG_STAGE_PRECOPY) {
		if (slice->dirty_bitmap)
			set_page_dirty_in_slice(slice, vmf->pgoff);
		//printk("mkwrite precopy marking pgoff=%lx dirty\n", vmf->pgoff);
	} else if (stage == SMX_MIG_STAGE_STOP_AND_COPY) {
		/*
		 * Theoretically, the following code can be removed. If a write-protection
		 * fault occurs during stop-and-copy, the dirty bit should already be set.
		 */
		if (slice->dirty_bitmap)
			set_page_dirty_in_slice(slice, vmf->pgoff);
		//printk("mkwrite stop-and-copy marking pgoff=%lx dirty\n", vmf->pgoff);
	} else if (stage == SMX_MIG_STAGE_POSTCOPY) {
		/*
		 * Write faults in postcopy are handled here. During postcopy, we need to
		 * actually perform the memory copy before we can insert the PTE. Besides,
		 * we also need to clear the bitmap so the postcopy worker will not handle
		 * it again.
		 */
		bool dirty;
		pte_t *pte, entry;
		spinlock_t *ptl;
		pgoff_t pgoff = vmf->pgoff;
		phys_addr_t phys;
		struct mmu_notifier_range range;
		uint64_t offset;

		//printk("mkwrite postcopy handling pgoff=%lx dirty\n", vmf->pgoff);

		offset = ((pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE) >> PAGE_SHIFT;
		dirty = test_and_clear_bit_le(offset, slice->dirty_bitmap);
		if (dirty) {
			void *old_va = slice->va + (pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE;
			void *new_va =
				slice->migration_dest->va + (pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE;
			memcpy(new_va, old_va, PAGE_SIZE);
		} else {
			/*
			 * If dirty bit is unset, this page is already handled by the
			 * post-copy worker. We don't need to do anything.
			 * Note that if a PTE does not exist, it won't enter this function;
			 * it will be handled by smx_block_fault and the PTE will be inserted
			 * with write permission. As a result, if the dirty bit is unset, the
			 * only possibility is that it's already handled by the post-copy
			 * worker.
			 */
			rc = VM_FAULT_WRITE;
			goto out_mig_unlock;
		}

		pte = get_locked_pte(vma->vm_mm, vmf->address, &ptl);
		if (!pte) {
			rc = VM_FAULT_OOM;
			goto out_mig_unlock;
		}
		if (pte_none(*pte)) {
			/*
			 * PTE should either be handled by page fault, or by migration
			 * worker. Control should never reach here.
			 */
			BUG();
			rc = VM_FAULT_OOM;
			goto unlock_pte;
		}

		phys = smx_block_get_pa_by_pgoff(smxblk, pgoff, PAGE_SIZE, true);
		entry = pte_mkdevmap(pfn_pte(phys >> PAGE_SHIFT, vma->vm_page_prot));

		mmu_notifier_range_init(&range, MMU_NOTIFY_MIGRATE,
					0, vma, vma->vm_mm, vmf->address, vmf->address + PAGE_SIZE);
		mmu_notifier_invalidate_range_start(&range);
		set_pte_at_notify(vma->vm_mm, vmf->address, pte, entry);
		mmu_notifier_invalidate_range_end(&range);

		rc = VM_FAULT_NOPAGE;

unlock_pte:
		pte_unmap_unlock(pte, ptl);
	}

out_mig_unlock:
	smx_migration_unlock(smxl);
out_blk_unlock:
	smx_block_unlock_shared(smxblk);

	return rc;
}

/*
 * TODO: huge_fault is commented because with huge pages, memory migration
 * does not work. This is a known bug to fix.
 */
static const struct vm_operations_struct smx_block_vm_ops = {
	.fault = smx_block_fault,
	//.huge_fault = smx_block_huge_fault,
	.may_split = smx_block_may_split,
	.pagesize = smx_block_pagesize,
	.pfn_mkwrite = smx_block_pfn_mkwrite,
};

static int smx_block_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct smx_block *smxblk = file->private_data;
	uint64_t size = vma->vm_end - vma->vm_start;
	int rc;

	dev_dbg(&smxblk->dev, "mmapping vma start %lx size %llx...\n", vma->vm_start, size);

	rc = smx_block_mmap_sanity_check(smxblk, vma);
	if (rc) {
		dev_err(&smxblk->dev, "sanity check failed");
		return rc;
	}

	/*
	 * TODO: When we switch to an PCIe device like Xilinx, we need to use
	 * ioremap_cache to make the memory region cacheable. Linux adopts
	 * Intel PAT, which by default mark PCIe BARs as uncacheable regions.
	 * This will overwrite the bits in the PTE/PMD and make a range of
	 * physical memory uncacheable.
	 * Cat /sys/kernel/debug/x86/pat_memtype_list and /proc/mtrr for more
	 * information.
	 */

	/*
	 * We use VM_PFNMAP here to tell everyone else that these pages do not
	 * have a page struct. Another option is to use devm_memremap_pages to
	 * create page struct for the allocated block region, or directly use
	 * the dax driver. Not sure which one is the best and need some extra
	 * investigation.
	 * TODO: Currently we do have a few ugly modifications in KVM and mm
	 * to support this. We may need a better way to handle this. In 2020,
	 * someone tried to push a patch regarding this to the upstream, but
	 * apparently the patch is not accepted. The patch can be found at
	 * https://lore.kernel.org/linux-nvdimm/20200110190313.17144-1-joao.m.martins@oracle.com/
	 */
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	/* For simplicity, for now we force all pages to be readable and writable. */
	vma->vm_flags |= VM_READ | VM_WRITE;
	vma->vm_ops = &smx_block_vm_ops;
	if ((vma->vm_start & (SZ_2M - 1)) == 0) {
		smxblk->pgsize = SZ_2M;
		vma->vm_flags |= VM_HUGEPAGE;
	} else {
		smxblk->pgsize = SZ_4K;
	}

	/* Save the vma for future reference when performing memory migration. */
	smxblk->vma = vma;

	return 0;
}

static loff_t smx_block_llseek(struct file *file, loff_t offset, int whence)
{
	struct smx_block *smxblk = file->private_data;

	return fixed_size_llseek(file, offset, whence, smxblk->size);
}

static const struct file_operations smx_block_fops = {
	.owner = THIS_MODULE,
	.open = smx_block_open,
	.release = smx_block_release_file,
	.mmap = smx_block_mmap,
	.llseek = smx_block_llseek,
};

static int __try_allocate_address_space(struct smx_block *smxblk, uint64_t size, uint64_t *start)
{
	struct smx_device *smxdev = smx_block_get_parent(smxblk);
	uint64_t addr;

	if (start == NULL) {
		BUG();
		return -EINVAL;
	}

	addr = gen_pool_alloc(smxdev->address_space, size);
	if (!addr) {
		dev_dbg(&smxdev->dev,
			"unable to allocate %lluM contiguous address space, "
			"may retry with fragmentation\n",
			size >> 20);
		return -ENOMEM;
	}
	*start = addr;

	return 0;
}

static void
__destory_address_space(struct smx_block *smxblk, uint64_t mem_region_start,
			uint64_t mem_region_size)
{
	struct smx_device *smxdev = smx_block_get_parent(smxblk);

	gen_pool_free(smxdev->address_space, mem_region_start, mem_region_size);
}

static void smx_block_destory_all_slices(void *_smxblk)
{
	struct smx_block *smxblk = _smxblk;
	struct smx_full_slice *slice;
	uint64_t i;

	smx_block_lock_exclusive(smxblk);

	for (i = 0; i < NR_SLICES(smxblk); i++) {
		slice = &smxblk->slices[i];
		if (slice->va)
			iounmap(slice->va);
		if (slice->pa)
			__destory_address_space(smxblk, slice->pa, SMX_SLICE_SIZE);
		if (slice->migration_dest) {
			struct smx_full_slice *dest = slice->migration_dest;

			if (dest->va)
				iounmap(dest->va);
			if (dest->pa)
				__destory_address_space(smxblk, dest->pa, SMX_SLICE_SIZE);
			kfree(dest);
			slice->migration_dest = NULL;
		}
		if (slice->dirty_bitmap)
			vfree(slice->dirty_bitmap);
		if (slice->migration_meta)
			vfree(slice->migration_meta);
		smx_clear_half_slice(smxblk, &slice->half[0]);
		smx_clear_half_slice(smxblk, &slice->half[1]);
	}

	smx_block_unlock_exclusive(smxblk);
}

static struct smx_block *
smx_block_alloc(struct smx_device *smxdev, uint64_t size)
{
	struct smx_block *smxblk;
	struct cdev *cdev;
	struct device *dev;
	uint64_t do_size = size;
	uint64_t allocated_size = 0;
	uint64_t start;
	uint64_t end;
	uint64_t nr_slices = size / SMX_SLICE_SIZE;
	int rc;

	dev_dbg(&smxdev->dev, "allocating block, size=0x%llx\n", size);

	smxblk = kzalloc(sizeof(*smxblk) + sizeof(struct smx_full_slice) * nr_slices, GFP_KERNEL);
	if (!smxblk) {
		dev_err(&smxdev->dev, "allocating smxblk failed\n");
		return ERR_PTR(-ENOMEM);
	}

	rc = ida_alloc_range(&smxdev->ida, 0, SMX_MAX_BLOCKS, GFP_KERNEL);
	if (rc < 0) {
		dev_err(&smxdev->dev, "allocating id failed\n");
		goto err;
	}
	smxblk->id = rc;

	rc = ida_alloc_range(&smx_block_ida, 0, SMX_MAX_BLOCKS, GFP_KERNEL);
	if (rc < 0) {
		dev_err(&smxdev->dev, "allocating global id failed\n");
		goto err;
	}
	smxblk->global_id = rc;

	smxblk->size = size;
	smxblk->occupied = false;
	smx_block_lock_init(smxblk);

	dev = &smxblk->dev;
	device_initialize(dev);
	dev->parent = &smxdev->dev;
	dev->devt = MKDEV(smx_block_major, smxblk->global_id);
	dev->type = &smx_block_type;
	device_set_pm_not_required(dev);
	dev->class = smx_class;

	cdev = &smxblk->cdev;
	cdev_init(cdev, &smx_block_fops);

	rc = dev_set_name(dev, "smx%db%d", smxdev->id, smxblk->id);
	if (rc)
		goto err;

	rc = cdev_device_add(cdev, dev);
	if (rc)
		goto err_free_put;

	/*
	 * Next, we allocate the memory space for this block. The memory space
	 * is allocated at a full slice granularity. However, because the
	 * address may be fragmented, we need to reduce the allocation size if
	 * an allocation fails, and retry with a smaller size until a threshold
	 * or the allocation seccuss.
	 */
	do {
		do_size = round_down(do_size, SMX_SLICE_SIZE);
		start = 0;
		rc = __try_allocate_address_space(smxblk, do_size, &start);
		if (rc) {
			if (do_size == SMX_SLICE_SIZE) {
				dev_err(dev, "unable to find address space\n");
				rc = -ENOMEM;
				goto err_free_all;
			} else {
				do_size = do_size / 2;
			}
		} else {
			end = start + do_size;
			for (; allocated_size < do_size; allocated_size += SMX_SLICE_SIZE) {
				struct smx_full_slice *slice =
					&smxblk->slices[allocated_size / SMX_SLICE_SIZE];
				slice->pa = start;
				slice->va = ioremap_cache(slice->pa, SMX_SLICE_SIZE);
				if (!slice->va) {
					dev_err(dev, "ioremap_cache failed\n");
					goto err_free_all;
				}
				slice->dirty_bitmap = NULL;
				start += SMX_SLICE_SIZE;
			}
		}
	} while (allocated_size != size);

	return smxblk;

err_free_all:
	smx_block_destory_all_slices(smxblk);
	cdev_device_del(&smxblk->cdev, &smxblk->dev);
err_free_put:
	put_device(&smxblk->dev);
err:
	return ERR_PTR(rc);
}

int smx_create_and_add_block(struct smx_device *smxdev, uint64_t size)
{
	struct smx_block *smxblk;

	smxblk = smx_block_alloc(smxdev, size);
	if (IS_ERR(smxblk)) {
		dev_err(&smxdev->dev, "creating block failed\n");
		return PTR_ERR(smxblk);
	}

	mutex_lock(&smxdev->block_list_mutex);
	list_add(&smxblk->node, &smxdev->block_list);
	mutex_unlock(&smxdev->block_list_mutex);

	return 0;
}

void smx_free_block(struct smx_block *smxblk)
{
	dev_dbg(&smxblk->dev, "freeing\n");

	smx_block_destory_all_slices(smxblk);

	cdev_device_del(&smxblk->cdev, &smxblk->dev);
	put_device(&smxblk->dev);
}
