#ifndef __SMX__UTIL_H__
#define __SMX__UTIL_H__

#include "smx_internal.h"

int smx_create_address_space(struct smx_device *smxdev, uint64_t start_addr, uint64_t size);
int smx_config_dest_table(struct smx_device *smxdev, uint32_t offset, bool is_odd,
			  struct smx_half_slice *hs);
int smx_clear_dest_table(struct smx_device *smxdev, uint32_t offset, bool is_odd,
			  struct smx_half_slice *hs);
int smx_parse_remote_config(const char *buf, size_t len, uint8_t *rmac, uint64_t *raddr,
			    uint64_t *rsize);
int smx_parse_migrate_config(const char *buf, size_t len, uint8_t *old_rmac, uint8_t *new_rmac,
			     uint64_t *new_raddr, uint64_t *new_rsize);
uint64_t smx_address_to_offset(struct smx_device *smxdev, uint64_t address);

/*
 * Get the physical address from a page offset. When migration is true, use the
 * value from migration_dest.
 */
static inline phys_addr_t
smx_block_get_pa_by_pgoff(struct smx_block *smxblk, pgoff_t pgoff, unsigned long size,
			  bool migration)
{
	phys_addr_t pa, pa_down, pa_base;

	if ((pgoff << PAGE_SHIFT) > smxblk->size) {
		dev_err(&smxblk->dev, "pgoff=%#lx out of range\n", pgoff);
		return -1;
	}

	if (!migration)
		pa_base = smxblk->slices[(pgoff << PAGE_SHIFT) / SMX_SLICE_SIZE].pa;
	else
		pa_base = smxblk->slices[(pgoff << PAGE_SHIFT) / SMX_SLICE_SIZE].migration_dest->pa;
	pa = pa_base + (pgoff << PAGE_SHIFT) % SMX_SLICE_SIZE;
	pa_down = round_down(pa, (uint64_t)size);

	return pa_down;
}

static inline struct smx_full_slice *
smx_block_get_slice_by_pgoff(struct smx_block *smxblk, pgoff_t pgoff)
{
	return &smxblk->slices[(pgoff << PAGE_SHIFT) / SMX_SLICE_SIZE];
}

static inline uint64_t
smx_full_slice_to_va(struct smx_block *smxblk, struct smx_full_slice *slice)
{
	if (!smxblk->occupied || !smxblk->vma)
		return -EINVAL;

	return smxblk->vma->vm_start + (slice - smxblk->slices) * SMX_SLICE_SIZE;
}

static inline uint64_t
smx_full_slice_to_pgoff(struct smx_block *smxblk, struct smx_full_slice *slice)
{
	return ((slice - smxblk->slices) * SMX_SLICE_SIZE) >> PAGE_SHIFT;
}

#endif
