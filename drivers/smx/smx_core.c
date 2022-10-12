#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>

#include "smx_internal.h"
#include "util.h"

static DEFINE_IDA(smx_device_ida);
DEFINE_MUTEX(smx_device_list_mutex);
LIST_HEAD(smx_device_list);
struct class *smx_class;

static void smx_device_release(struct device *dev)
{
	struct smx_device *smxdev = to_smx_device(dev);

	dev_dbg(dev, "releasing device\n");

	ida_free(&smx_device_ida, smxdev->id);
	kfree(smxdev);
}

static ssize_t
numa_node_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", dev_to_node(dev));
}
static DEVICE_ATTR_RO(numa_node);

static ssize_t
phys_mem_start_show(struct device *dev, struct device_attribute *attr,
		    char *buf)
{
	struct smx_device *smxdev = to_smx_device(dev);
	return sprintf(buf, "%lld\n", smxdev->phys_mem_region_start);
}
static DEVICE_ATTR_RO(phys_mem_start);

static ssize_t
phys_mem_end_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_device *smxdev = to_smx_device(dev);
	return sprintf(buf, "%lld\n",
		       smxdev->phys_mem_region_start + smxdev->phys_mem_region_size);
}
static DEVICE_ATTR_RO(phys_mem_end);

static ssize_t
phys_mem_size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct smx_device *smxdev = to_smx_device(dev);
	return sprintf(buf, "%lld\n", smxdev->phys_mem_region_size);
}
static DEVICE_ATTR_RO(phys_mem_size);

static ssize_t
create_block_store(struct device *dev, struct device_attribute *attr,
		   const char *buf, size_t count)
{
	char *endptr;
	uint64_t memsize = memparse(buf, &endptr);
	struct smx_device *smxdev = to_smx_device(dev);
	int rc;

	rc = smx_create_and_add_block(smxdev, memsize);
	if (rc)
		return rc;

	return count;
}
static DEVICE_ATTR_WO(create_block);

static ssize_t
destory_block_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct smx_device *smxdev = to_smx_device(dev);
	struct smx_block *smxblk = NULL, *mds;
	char *endptr;
	uint64_t id = simple_strtoull(buf, &endptr, 0);

	mutex_lock(&smxdev->block_list_mutex);
	list_for_each_entry(mds, &smxdev->block_list, node) {
		if (mds->id == id) {
			smxblk = mds;
			list_del(&smxblk->node);
			break;
		}
	}
	mutex_unlock(&smxdev->block_list_mutex);

	if (smxblk == NULL) {
		dev_err(dev, "smx block with id %lld not found\n", id);
		return -EINVAL;
	}

	smx_free_block(smxblk);

	return count;
}
DEVICE_ATTR_WO(destory_block);

static struct attribute *smx_device_control_attributes[] = {
	&dev_attr_create_block.attr,
	&dev_attr_destory_block.attr,
	&dev_attr_numa_node.attr,
	&dev_attr_phys_mem_start.attr,
	&dev_attr_phys_mem_end.attr,
	&dev_attr_phys_mem_size.attr,
	NULL,
};

static struct attribute_group smx_device_control_attribute_group = {
	.name = "smx_control",
	.attrs = smx_device_control_attributes,
};

static const struct attribute_group *smx_device_attribute_groups[] = {
	&smx_device_control_attribute_group,
	NULL,
};

static const struct device_type smx_device_type = {
	.name = "smx_physical_device",
	.release = smx_device_release,
	.groups = smx_device_attribute_groups,
};

struct smx_device *smx_device_alloc(uint64_t start_addr, uint64_t size)
{
	struct smx_device *smxdev;
	struct device *dev;
	int rc;

	smxdev = kzalloc(sizeof(*smxdev), GFP_KERNEL);
	if (!smxdev)
		return ERR_PTR(-ENOMEM);

	rc = ida_alloc_range(&smx_device_ida, 0, SMX_MAX_DEVICES, GFP_KERNEL);
	if (rc < 0)
		goto err;
	smxdev->id = rc;

	ida_init(&smxdev->ida);
	INIT_LIST_HEAD(&smxdev->block_list); 
	mutex_init(&smxdev->block_list_mutex);

	dev = &smxdev->dev;
	device_initialize(dev);

	/*
	 * The following line registers all callback functions for file operations
	 * under /sys/class/smxX. These files are the interface to create and destory
	 * blocks. Also, smx_device_type also defines what the kernel needs to do
	 * to free this device. In our case, the smx_device data structure and an ida
	 * allocated for the smxdev should be freed.
	 */
	dev->type = &smx_device_type;
	device_set_pm_not_required(dev);

	/*
	 * The following line allows us to find the smx device under /sys/class/smx.
	 * The class is created during module initialization.
	 */
	dev->class = smx_class;

	rc = dev_set_name(dev, "smx%d", smxdev->id);
	if (rc)
		goto err;

	rc = device_add(dev);
	if (rc)
		goto err_free_put;

	/*
	 * The address must be created after the device is added, because it
	 * uses devm_* related functions, which requires an initialized dev.
	 */
	rc = smx_create_address_space(smxdev, start_addr, size);
	if (rc < 0)
		goto err_free_del;

	/*
	 * Initialize the provider-side functionalities. Data structure for
	 * the provider is embedded in the smx_device data structure.
	 */
	rc = smx_device_initialize_provider(smxdev);
	if (rc)
		goto err_uninitialize_provider; 

	return smxdev;

err_uninitialize_provider:
	smx_device_uninitialize_provider(smxdev);
err_free_del:
	device_del(dev);
err_free_put:
	put_device(dev);
err:
	kfree(smxdev);
	return ERR_PTR(rc);
}

void smx_device_free(struct smx_device *smxdev)
{
	struct smx_block *mds, *tmp_mds;
	dev_dbg(&smxdev->dev, "freeing smx device\n");

	smx_device_uninitialize_provider(smxdev);

	mutex_lock(&smxdev->block_list_mutex);
	list_for_each_entry_safe(mds, tmp_mds, &smxdev->block_list, node) {
		dev_dbg(&smxdev->dev, "freeing %s\n", dev_name(&mds->dev));
		list_del(&mds->node);
		smx_free_block(mds);
	}
	mutex_unlock(&smxdev->block_list_mutex);

	device_unregister(&smxdev->dev);
}

static __init int smx_init(void)
{
	int rc;

	smx_class = class_create(THIS_MODULE, "smx");
	if (IS_ERR(smx_class)) {
		pr_err("smx: creating class failed\n");
		return -EBUSY;
	}

	rc = smx_block_init();
	if (rc) {
		pr_err("smx: initializing block interface failed\n");
		goto err_class_destory;
	}

	rc = smx_provider_init();
	if (rc) {
		pr_err("smx: initializing provider interface failed\n");
		goto err_free_block;
	}
	
	rc = pci_register_driver(&smx_pci_driver);
	if (rc) {
		pr_err("smx: failed to register pci driver\n");
		goto err_free_provider;
	}

	return 0;

err_free_provider:
	smx_provider_exit();
err_free_block:
	smx_block_exit();
err_class_destory:
	class_destroy(smx_class);
	return rc;
}

static void smx_exit(void)
{
	pci_unregister_driver(&smx_pci_driver);
	smx_block_exit();
	smx_provider_exit();
	class_destroy(smx_class);
}

module_init(smx_init);
module_exit(smx_exit);
MODULE_LICENSE("GPL v2");
