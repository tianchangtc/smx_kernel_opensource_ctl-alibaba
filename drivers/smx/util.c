#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/genalloc.h>
#include <linux/if_ether.h>

#include "smx_internal.h"
#include "util.h"

int smx_create_address_space(struct smx_device *smxdev, uint64_t start_addr, uint64_t size)
{
	const int order = ilog2(SMX_SLICE_SIZE);
	int rc;
	struct device *dev = &smxdev->dev;
	struct gen_pool *pool;

	/*
	 * This pool does not need to be manually freed. When the reference count
	 * of smxdev->dev reduces to 0, it will be freed automatically.
	 */
	pool = devm_gen_pool_create(dev, order, NUMA_NO_NODE, dev_name(dev));
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	rc = gen_pool_add(pool, start_addr, size, NUMA_NO_NODE);
	if (rc)
		return rc;

	smxdev->address_space = pool;

	return 0;
}

int smx_config_dest_table(struct smx_device *smxdev, uint32_t offset, bool is_odd,
			  struct smx_half_slice *hs)
{
	/* TODO: Implement this function after having the hardware */
	return 0;
}

int smx_clear_dest_table(struct smx_device *smxdev, uint32_t offset, bool is_odd,
			 struct smx_half_slice *hs)
{
	/* TODO: Implement this */
	return 0;
}

/*
 * The format of the configuration is:
 * <remote mac address> <remote address> <remote size>
 */
int smx_parse_remote_config(const char *buf, size_t len, uint8_t *rmac, uint64_t *raddr,
			    uint64_t *rsize)
{
	uint64_t addr = 0, size = 0;
	char *endp;
	bool is_mac;

	if (len < 3 * ETH_ALEN - 1)
		return false;

	is_mac = mac_pton(buf, rmac);
	if (!is_mac)
		return -EINVAL;

	buf += 3 * ETH_ALEN;

	addr = memparse(buf, &endp);
	if (addr == 0)
		return -EINVAL;

	buf = endp + 1;
	size = memparse(buf, &endp);
	if (size == 0)
		return -EINVAL;

	if (addr % SMX_HALF_SLICE_SIZE != 0)
		return -EINVAL;

	if (size % SMX_HALF_SLICE_SIZE != 0)
		return -EINVAL;

	*raddr = addr;
	*rsize = size;

	return 0;
}

uint64_t smx_address_to_offset(struct smx_device *smxdev, uint64_t address)
{
	return (address - smxdev->phys_mem_region_start) / SMX_SLICE_SIZE;
}

/*
 * Currently, migration is done at a node granularity; each node is identified
 * by their mac address.
 * Format is as below:
 * <mac to be removed> <new mac> <new remote address> <new remote size>
 */
int smx_parse_migrate_config(const char *buf, size_t len, uint8_t *old_rmac, uint8_t *new_rmac,
			     uint64_t *new_raddr, uint64_t *new_rsize)
{
	bool is_mac;

	/* FIXME: this sanity check is not complete */
	if (len < 3 * ETH_ALEN * 2)
		return false;

	is_mac = mac_pton(buf, old_rmac);
	if (!is_mac)
		return -EINVAL;
	buf += 3 * ETH_ALEN;

	return smx_parse_remote_config(buf, len - 3 * ETH_ALEN, new_rmac, new_raddr, new_rsize);
}
