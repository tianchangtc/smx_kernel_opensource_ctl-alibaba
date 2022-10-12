#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <asm/cacheflush.h>

#include "smx_internal.h"
#include "board.h"

/*
 * This table includes the vendor ID and device ID of all devices drive by
 * this driver. Currently, this is the IDs of a Xilinx FPGA board.
 */
static const struct pci_device_id smx_pci_ids[] = {
	{ PCI_DEVICE(0x10EE, 0x1005) },
	{ 0 }
};

static int smx_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct smx_device *smxdev;
	int rc = 0;

	rc = pci_enable_device_mem(pdev);
	if (rc) {
		dev_err(&pdev->dev, "failed to enable pci device\n");
		goto out;
	}

	/*
	 * TODO/FIXME: Ideally, we should read some configuration registers
	 * to determine the starting address and size of the CXL window of this
	 * SMX device. However, since we don't have the device for now, we use
	 * a range of reserved host memory as CXL memory. The range is specified
	 * in /etc/default/grub, and will be applied to grub.cfg after a grub
	 * update.
	 */
	smxdev = smx_device_alloc(16ULL * SZ_1G, 16ULL * SZ_1G);
	if (smxdev == NULL) {
		dev_err(&pdev->dev, "cannot create smx device\n");
		rc = -ENODEV;
		goto out;
	}

	smxdev->pdev = pdev;
	pci_set_drvdata(pdev, smxdev);

	mutex_lock(&smx_device_list_mutex);
	list_add(&smxdev->node, &smx_device_list);
	mutex_unlock(&smx_device_list_mutex);

out:
	return rc;
}

static void smx_pci_remove(struct pci_dev *pdev)
{
	struct smx_device *smxdev = pci_get_drvdata(pdev);

	mutex_lock(&smx_device_list_mutex);
	list_del(&smxdev->node);
	mutex_unlock(&smx_device_list_mutex);

	smx_device_free(smxdev);

	pci_disable_device(pdev);
}

struct pci_driver smx_pci_driver = {
	.name = "smx",
	.id_table = smx_pci_ids,
	.probe = smx_pci_probe,
	.remove = smx_pci_remove
};
