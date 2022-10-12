#ifndef __SMX_MIGRATION__
#define __SMX_MIGRATION__

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
#include <linux/atomic.h>

#include "smx_internal.h"
#include "util.h"
#include "migration.h"

static inline void set_page_dirty_in_slice(struct smx_full_slice *slice, pgoff_t pgoff)
{
	uint64_t offset = pgoff % (SMX_SLICE_SIZE / PAGE_SIZE);
	set_bit_le(offset, slice->dirty_bitmap);
}

static inline int test_page_dirty_in_slice(struct smx_full_slice *slice, pgoff_t pgoff)
{
	uint64_t offset = pgoff % (SMX_SLICE_SIZE / PAGE_SIZE);
	return test_bit_le(offset, slice->dirty_bitmap);
}

static inline int test_and_set_dirty_in_slice(struct smx_full_slice *slice, pgoff_t pgoff)
{
	uint64_t offset = pgoff % (SMX_SLICE_SIZE / PAGE_SIZE);
	return test_and_set_bit_le(offset, slice->dirty_bitmap);
}

static inline uint64_t *get_second_dirty_bitmap(struct smx_full_slice *slice)
{
	uint64_t bytes = SMX_SLICE_DIRTY_BITMAP_SIZE;
	return slice->dirty_bitmap + bytes / sizeof(slice->dirty_bitmap);
}

static inline struct smx_migration_meta *
smx_migration_get_meta(struct smx_full_slice *slice, pgoff_t pgoff)
{
	uint64_t offset = pgoff % (SMX_SLICE_SIZE / PAGE_SIZE);
	uint64_t nr = offset / SMX_NR_PAGES_PER_META;
	return &slice->migration_meta[nr];
}

static inline int
smx_migration_get_locked_stage(struct smx_full_slice *slice, pgoff_t pgoff, spinlock_t **lock)
{
	struct smx_migration_meta *meta = smx_migration_get_meta(slice, pgoff);
	*lock = &meta->lock;
	spin_lock(*lock);
	return meta->stage;
}

static inline spinlock_t *
smx_migration_lock(struct smx_full_slice *slice, pgoff_t pgoff)
{
	struct smx_migration_meta *meta = smx_migration_get_meta(slice, pgoff);
	spinlock_t *lock = &meta->lock;
	spin_lock(lock);
	return lock;
}

static inline void
smx_migration_set_locked_stage(struct smx_full_slice *slice, pgoff_t pgoff, int stage,
			       spinlock_t **lock)
{
	struct smx_migration_meta *meta = smx_migration_get_meta(slice, pgoff);
	*lock = &meta->lock;
	spin_lock(*lock);
	meta->stage = stage;
}

static inline struct smx_migration_meta *
smx_migration_get_locked_meta(struct smx_full_slice *slice, pgoff_t pgoff, spinlock_t **lock)
{
	struct smx_migration_meta *meta = smx_migration_get_meta(slice, pgoff);
	*lock = &meta->lock;
	spin_lock(*lock);
	return meta;
}

static inline void smx_migration_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}

#define PGOFF_IS_META_START(pgoff) ((pgoff % SMX_NR_PAGES_PER_META) == 0)

int smx_protect_migration_slices(struct smx_block *smxblk);
void smx_copy_dirty_bitmap(struct smx_full_slice *slice);
uint64_t smx_do_precopy(struct smx_block *smxblk, int round);
void smx_migration_work(struct work_struct *work);

#endif
