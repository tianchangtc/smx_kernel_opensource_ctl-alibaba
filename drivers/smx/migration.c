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
#include <linux/pagewalk.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

#include "smx_internal.h"
#include "util.h"
#include "migration.h"

struct smx_slice_protect_metadata {
	struct vm_area_struct *target_vma;
	struct smx_block *smxblk;
	struct smx_full_slice *slice;
	uint64_t va_start;
};

/*
 * This function is here to work around a few weird restrictions in page table walker.
 * Without this function registered, the page table walker does not walk devmap pages.
 */
static int smx_slice_test_walk(unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	return 0;
}

static int smx_slice_protect_pmd(pmd_t *pmdp, unsigned long start, unsigned long end,
				 struct mm_walk *walk)
{
	pte_t *ptep, pte;
	spinlock_t *ptl, *smxl;
	struct vm_area_struct *vma = walk->vma;
	struct smx_slice_protect_metadata *meta = walk->private;
	struct smx_full_slice *slice = meta->slice;
	struct mmu_notifier_range range;
	unsigned long index;
	pgoff_t pgoff;
	uint64_t va_start = vma->vm_start;

	if (pmd_none_or_trans_huge_or_clear_bad(pmdp))
		return 0;

	mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
				0, vma, vma->vm_mm, start, start + PMD_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	if (pmd_large(*pmdp)) {
		/*
		 * Theoretically, we need to split huge page for protection
		 * purpose. In practice, we only need to clear the page table
		 * entry, and the page fault handler will split the page and
		 * set the protection.
		 * TODO: This function may be related to a bug. We never test
		 * this function.
		 */
		ptl = pmd_lock(vma->vm_mm, pmdp);
		pmdp_huge_clear_flush_notify(vma, start, pmdp);
		spin_unlock(ptl);
		goto out;
	}

	for (index = start; index < end; index += PAGE_SIZE) {
		if (index < meta->va_start)
			continue;
		if (index >= meta->va_start + SMX_SLICE_SIZE)
			break;

		pgoff = (start - va_start) >> PAGE_SHIFT;
		smx_migration_set_locked_stage(slice, pgoff, SMX_MIG_STAGE_PRECOPY, &smxl);

		ptep = pte_offset_map_lock(vma->vm_mm, pmdp, index, &ptl);
		if (!pte_present(*ptep) || !pte_write(*ptep))
			goto unlock_pte;

		pte = ptep_clear_flush_notify(vma, index, ptep);
		pte = pte_wrprotect(pte);
		pte = pte_mkclean(pte);
		set_pte_at_notify(vma->vm_mm, index, ptep, pte);
unlock_pte:
		pte_unmap_unlock(ptep, ptl);
		smx_migration_unlock(smxl);
	}

out:
	mmu_notifier_invalidate_range_end(&range);
	walk->action = ACTION_CONTINUE;

	return 0;
}

static struct mm_walk_ops smx_slice_protect_ops = {
	.pmd_entry = smx_slice_protect_pmd,
	.test_walk = smx_slice_test_walk,
};

static int smx_protect_slice(struct smx_block *smxblk, struct smx_full_slice *slice)
{
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t va_start = smx_full_slice_to_va(smxblk, slice);
	uint64_t va_end = va_start + SMX_SLICE_SIZE;
	struct smx_slice_protect_metadata meta = {
		.target_vma = smxblk->vma,
		.smxblk = smxblk,
		.slice = slice,
		.va_start = va_start,
	};
	int rc;

	mmap_read_lock(vma->vm_mm);
	rc = walk_page_range(vma->vm_mm, va_start, va_end, &smx_slice_protect_ops, &meta);
	if (rc) {
		dev_err(&smxblk->dev, "walk_page_range failed with %d\n", rc);
	}
	mmap_read_unlock(vma->vm_mm);

	return rc;
}

int smx_protect_migration_slices(struct smx_block *smxblk)
{
	unsigned long index;
	uint64_t time_begin, time_end;

	time_begin = ktime_get_real_ns() / 1000000;

	smx_block_lock_shared(smxblk);
	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];

		if (slice->migration_dest != NULL)
			smx_protect_slice(smxblk, slice);
	}
	smx_block_unlock_shared(smxblk);

	time_end = ktime_get_real_ns() / 1000000;

	dev_dbg(&smxblk->dev, "initial protection: time: %lldms\n", time_end - time_begin);

	return 0;
}

void smx_copy_dirty_bitmap_and_protect(struct smx_block *smxblk, struct smx_full_slice *slice, int round)
{
	uint64_t *dirty_bitmap = slice->dirty_bitmap;
	uint64_t *dirty_bitmap_buffer = get_second_dirty_bitmap(slice);
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t va_start = vma->vm_start;
	uint64_t address;
	pgoff_t pgoff_base = smx_full_slice_to_pgoff(smxblk, slice);
	pgoff_t pgoff;
	spinlock_t *smxl;
	int i;

	for (i = 0; i < SMX_SLICE_DIRTY_BITMAP_SIZE / sizeof(uint64_t); i++) {
		uint64_t mask;
		pte_t *pte, entry;
		spinlock_t *ptl;
		struct mmu_notifier_range range;

		/*
		 * It's OK to set the stage for multiple times. It's protected by the lock
		 * and the page fault handler and pfn_mkwrite handler will get the correct
		 * value.
		 */
		smx_migration_set_locked_stage(slice, pgoff_base, SMX_MIG_STAGE_PRECOPY, &smxl);

		mask = xchg(&dirty_bitmap[i], 0);
		dirty_bitmap_buffer[i] = mask;

		if (!mask)
			goto smxl_unlock;

		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE, 0, vma, vma->vm_mm, 
					va_start + (pgoff_base << PAGE_SHIFT),
					va_start + (pgoff_base << PAGE_SHIFT) + PAGE_SIZE * sizeof(uint64_t) * 8);
		mmu_notifier_invalidate_range_start(&range);

		/*
		 * This function is adapted from a similar function in KVM. It's faster
		 * than a for loop.
		 */
		while (mask) {
			/* __ffs get the first none-zero bit in an integer. */
			pgoff = pgoff_base + __ffs(mask);
			address = va_start + (pgoff << PAGE_SHIFT);
			pte = get_locked_pte(vma->vm_mm, address, &ptl);
			if (!pte) {
				dev_err(&smxblk->dev, "cannot allodate pte page, fatal error\n");
				BUG();
				goto next;
			}
			if (!pte_present(*pte) || !pte_write(*pte))
				goto next_unlock;

			entry = ptep_clear_flush_notify(vma, address, pte);
			entry = pte_wrprotect(entry);
			entry = pte_mkclean(entry);
			set_pte_at_notify(vma->vm_mm, address, pte, entry);

			//printk("precopy %d protect pgoff=%lx\n", round, pgoff);
next_unlock:
			pte_unmap_unlock(pte, ptl);
next:
			/* clear the first none-zero bit */
			mask &= mask - 1;
		}

		mmu_notifier_invalidate_range_end(&range);
smxl_unlock:
		smx_migration_unlock(smxl);

		pgoff_base += sizeof(uint64_t) * 8;
	}
}

uint64_t smx_do_pre_copy(struct smx_block *smxblk, int round)
{
	int index;
	uint64_t dirty_count = 0;
	uint64_t time_begin, time_mid, time_end;

	time_begin = ktime_get_real_ns() / 1000000;

	/*
	 * First, we copy the dirty bitmap to a buffer, and re-protect all pages
	 * that were touched by the user process and marked as dirty.
	 */
	smx_block_lock_shared(smxblk);
	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];

		if (!slice->migration_dest)
			continue;

		smx_copy_dirty_bitmap_and_protect(smxblk, slice, round);
	}
	smx_block_unlock_shared(smxblk);

	time_mid = ktime_get_real_ns() / 1000000;

	/*
	 * Secondly, we copy the memory contents of the dirty pages to the destination.
	 * TODO: This can be offloaded to an DMA engine like Intel IOAT to reduce CPU
	 * usage.
	 */
	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];
		//pgoff_t pgoff_base = smx_full_slice_to_pgoff(smxblk, slice);
		uint64_t *dirty_bitmap;
		uint64_t offset;

		if (!slice->migration_dest)
			continue;

		dirty_bitmap = get_second_dirty_bitmap(slice);
		for (offset = 0; offset < SMX_SLICE_SIZE/PAGE_SIZE; offset++) {
			if (!test_bit_le(offset, dirty_bitmap))
				continue;
			dirty_count++;

			//printk("precopy %d copying pgoff=%llx\n", round, pgoff_base + offset);
			memcpy(slice->migration_dest->va + offset * PAGE_SIZE,
			       slice->va + offset * PAGE_SIZE,
			       PAGE_SIZE);
		}
	}

	time_end = ktime_get_real_ns() / 1000000;

	dev_dbg(&smxblk->dev, "precopy round %d: dirty_pages: %lld, "
		"copy-and-protect time: %lldms, copy time: %lldms\n",
		round, dirty_count, time_mid - time_begin, time_end - time_mid);

	return dirty_count;
}

/*
 * The following four events will happen in sequential order:
 * 1. Kernel start handling a write protection fault (before 2)
 * 2. smx_block_pfn_mkwrite, which sets the dirty bitmap
 * 3. migration module performs stop-and-copy based on the bitmap
 * 4. Kernel actually sets the W bit in the PTE
 *
 * Obviously, 1 < 2 < 4. 3 won't be after 4. When 3 is before 1, it's obviously correct.
 *
 * When 3 occurs in between 1/2 or 2/4, things become more complex.
 *
 * If 1 < 3 < 2 < 4:
 * During 3, the current faulted page won't be in the bitmap. However, 3 will replace
 * all old pages with new ones, and after 4, the faulted memory write will re-occur on
 * the new page.
 *
 * If 1 < 2 < 3 < 4:
 * During 4, kernel will find that the PTE is changed by 3, and will use the new PTE.
 *
 * As a result, if we can make 3 atomic, we don't need to worry about the ordering among
 * events.
 */

static int smx_slice_stop_and_copy_do_pmd(pmd_t *pmdp, unsigned long start, unsigned long end,
					  struct mm_walk *walk)
{
	pte_t *ptep, old_pte, new_pte;
	spinlock_t *ptl, *smxl;
	struct vm_area_struct *vma = walk->vma;
	struct smx_slice_protect_metadata *meta = walk->private;
	struct smx_block *smxblk = meta->smxblk;
	struct smx_full_slice *slice = meta->slice;
	/* Note we only need the original dirty bitmap */
	uint64_t *dirty_bitmap = slice->dirty_bitmap;
	uint64_t slice_base_va = smx_full_slice_to_va(smxblk, slice);
	uint64_t slice_base_pfn_new = slice->migration_dest->pa >> PAGE_SHIFT;
	struct mmu_notifier_range range;
	unsigned long index;
	uint64_t offset;
	pgoff_t pgoff;

	if (pmd_none_or_trans_huge_or_clear_bad(pmdp))
		return 0;

	if (pmd_large(*pmdp)) {
		BUG();
		goto out;
	}

	for (index = start; index < end; index += PAGE_SIZE) {
		if (index < meta->va_start)
			continue;
		if (index >= meta->va_start + SMX_SLICE_SIZE)
			break;

		pgoff = (index - vma->vm_start) >> PAGE_SHIFT;
		smx_migration_set_locked_stage(slice, pgoff, SMX_MIG_STAGE_STOP_AND_COPY, &smxl);

		ptep = pte_offset_map_lock(vma->vm_mm, pmdp, index, &ptl);
		if (!pte_present(*ptep))
			goto unlock_pte;

		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
					0, vma, vma->vm_mm, index, index + PAGE_SIZE);
		mmu_notifier_invalidate_range_start(&range);

		old_pte = ptep_clear_flush_notify(vma, index, ptep);

		offset = (index - slice_base_va) >> PAGE_SHIFT;
		if (!test_bit_le(offset, dirty_bitmap)) {
			/*
			 * For clean pages, we can directly update the PTE to the new
			 * destination, and we are basically done for these pages.
			 */
			pgprot_t prot = pte_pgprot(old_pte);
			new_pte = pfn_pte(slice_base_pfn_new + offset, prot);
			new_pte = pte_mkwrite(new_pte);
			set_pte_at_notify(vma->vm_mm, index, ptep, new_pte);
			//printk("stop-and-copy update pgoff=%lx\n", pgoff);
		} else {
			/*
			 * If the page is still dirty after the last round of precopy,
			 * we write protect the page, and handle it in postcopy.
			 */
			new_pte = pte_wrprotect(old_pte);
			set_pte_at_notify(vma->vm_mm, index, ptep, new_pte);
			//printk("stop-and-copy protect pgoff=%lx\n", pgoff);
		}

		mmu_notifier_invalidate_range_end(&range);
unlock_pte:
		pte_unmap_unlock(ptep, ptl);
		smx_migration_unlock(smxl);
	}

out:
	walk->action = ACTION_CONTINUE;

	return 0;
}

static struct mm_walk_ops smx_slice_stop_and_copy_ops = {
	.pmd_entry = smx_slice_stop_and_copy_do_pmd,
	.test_walk = smx_slice_test_walk,
};

static void smx_do_stop_and_copy_slice(struct smx_block *smxblk, struct smx_full_slice *slice)
{
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t va_start = smx_full_slice_to_va(smxblk, slice);
	uint64_t va_end = va_start + SMX_SLICE_SIZE;
	struct smx_slice_protect_metadata meta = {
		.target_vma = smxblk->vma,
		.smxblk = smxblk,
		.slice = slice,
		.va_start = va_start,
	};
	int rc;

	mmap_read_lock(vma->vm_mm);
	rc = walk_page_range(vma->vm_mm, va_start, va_end, &smx_slice_stop_and_copy_ops, &meta);
	if (rc) {
		dev_err(&smxblk->dev, "walk_page_range failed with %d\n", rc);
	}
	mmap_read_unlock(vma->vm_mm);
}

void smx_do_stop_and_copy(struct smx_block *smxblk)
{
	int index;
	uint64_t time_begin, time_end;

	time_begin = ktime_get_real_ns() / 1000000;

	smx_block_lock_shared(smxblk);
	dev_dbg(&smxblk->dev, "entering stop-and-copy\n");

	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];

		if (!slice->migration_dest)
			continue;

		smx_do_stop_and_copy_slice(smxblk, slice);
	}

	smx_block_unlock_shared(smxblk);

	time_end = ktime_get_real_ns() / 1000000;

	dev_dbg(&smxblk->dev, "stop-and-copy: time: %lldms\n", time_end - time_begin);
}

static void smx_do_post_copy_slice(struct smx_block *smxblk, struct smx_full_slice *slice)
{
	struct vm_area_struct *vma = smxblk->vma;
	uint64_t va_start = smx_full_slice_to_va(smxblk, slice);
	pgoff_t pgoff_base = smx_full_slice_to_pgoff(smxblk, slice);
	uint64_t address;
	struct mmu_notifier_range range;
	phys_addr_t phys;
	pte_t *pte, entry;
	spinlock_t *ptl, *smxl;
	pgoff_t pgoff;
	void *old_va, *new_va;
	bool dirty;
	int i;

	dev_dbg(&smxblk->dev, "doing postcopy on slice %lx\n", slice - smxblk->slices);

	for (i = 0; i < SMX_SLICE_SIZE / PAGE_SIZE; i++) {
		pgoff = pgoff_base + i;
		smx_migration_set_locked_stage(slice, pgoff, SMX_MIG_STAGE_POSTCOPY, &smxl);

		dirty = test_and_clear_bit_le(i, slice->dirty_bitmap);
		if (!dirty) {
			/*
			 * If it's not marked dirty, it can either be already handled in a
			 * previous round of precopy, or be handled by the page fault handler.
			 */
			goto unlock_smxl;
		}

		pte = get_locked_pte(vma->vm_mm, va_start + (i << PAGE_SHIFT), &ptl);
		if (!pte) {
			/*
			 * This should only happen in really rare cases where the kernel
			 * has no more memory to be allocated as a page table page. In a
			 * page fault handler we can simply kill the process. How should
			 * we handle it here?
			 */
			dev_err(&smxblk->dev, "cannot allocate pte page, fatal error\n");
			BUG();
			goto unlock_smxl;
		}

		if (pte_none(*pte)) {
			/*
			 * This should never happen. If the PTE does not exist, the dirty
			 * bit should be 0.
			 */
			BUG();
			goto unlock_pte;
		}

		address = va_start + (i << PAGE_SHIFT);
		mmu_notifier_range_init(&range, MMU_NOTIFY_MIGRATE, 0, vma, vma->vm_mm,
					address, address + PAGE_SIZE);
		if (pte_write(*pte)) {
			/*
			 * If the PTE is writeable and dirty, it means during stop-and-copy
			 * or post-copy, after the dirty page is write-protected, the user
			 * process writes the page. In this case, we need to write-protect
			 * it again, copy it to the destination, and set the PTE to the new
			 * location.
			 */

			//printk("post-copy handle pgoff=%lx type1\n", pgoff);

			mmu_notifier_invalidate_range_start(&range);

			entry = ptep_clear_flush_notify(vma, address, pte);
			entry = pte_wrprotect(entry);
			entry = pte_mkclean(entry);
			set_pte_at_notify(vma->vm_mm, address, pte, entry);

			mmu_notifier_invalidate_range_end(&range);
		} else {
			/*
			 * If the PTE is not writeable and dirty, the page is dirty and not
			 * written during stop-and-copy, and is not handled by pfn_mkwrite
			 * handler during post-copy. So we directly copy it to the destination
			 * and set the PTE to the new location. So do nothing here.
			 */
			//printk("post-copy handle pgoff=%lx type2\n", pgoff);
		}

		/* Perform the copy */
		old_va = slice->va + (i << PAGE_SHIFT);
		new_va = slice->migration_dest->va + (i << PAGE_SHIFT);
		memcpy(new_va, old_va, PAGE_SIZE);

		/* Set the PTE */
		phys = slice->migration_dest->pa + (i << PAGE_SHIFT);
		entry = pte_mkdevmap(pfn_pte(phys >> PAGE_SHIFT, vma->vm_page_prot));

		mmu_notifier_invalidate_range_start(&range);

		ptep_clear_flush_notify(vma, address, pte);
		set_pte_at_notify(vma->vm_mm, va_start + (i << PAGE_SHIFT), pte, entry);

		mmu_notifier_invalidate_range_end(&range);

unlock_pte:
		pte_unmap_unlock(pte, ptl);
unlock_smxl:
		smx_migration_unlock(smxl);
	}
}

void smx_do_post_copy(struct smx_block *smxblk)
{
	int index;
	uint64_t time_begin, time_end;
	struct smx_device *smxdev = smx_block_get_parent(smxblk);

	time_begin = ktime_get_real_ns() / 1000000;

	dev_dbg(&smxblk->dev, "entering postcopy\n");

	smx_block_lock_shared(smxblk);
	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];

		if (!slice->migration_dest)
			continue;

		smx_do_post_copy_slice(smxblk, slice);
	}
	smx_block_unlock_shared(smxblk);

	dev_dbg(&smxblk->dev, "starting cleanup\n");


	smx_block_lock_exclusive(smxblk);
	smxblk->during_migration = false;
	for (index = 0; index < NR_SLICES(smxblk); index++) {
		struct smx_full_slice *slice = &smxblk->slices[index];

		if (!slice->migration_dest)
			continue;

		/*
		 * These data structures must be freed after migration. Otherwise
		 * it will trigger kernel warnings (because gen_pool leakage) and
		 * crash the kernel.
		 */
		gen_pool_free(smxdev->address_space, slice->pa, SMX_SLICE_SIZE);
		slice->pa = slice->migration_dest->pa;
		iounmap(slice->va);

		slice->va = slice->migration_dest->va;
		slice->migration_dest->pa = 0;
		slice->migration_dest->va = 0;

		memcpy(&slice->half, &slice->migration_dest->half,
				sizeof(struct smx_half_slice) * 2);

		kfree(slice->migration_dest);
		vfree(slice->dirty_bitmap);
		vfree(slice->migration_meta);

		slice->migration_dest = NULL;
		slice->dirty_bitmap = NULL;
		slice->migration_meta = NULL;
	}
	smx_block_unlock_exclusive(smxblk);

	time_end = ktime_get_real_ns() / 1000000;

	dev_dbg(&smxblk->dev, "post-copy: time: %lldms\n", time_end - time_begin);
}

void smx_migration_work(struct work_struct *work)
{
	struct smx_block *smxblk = container_of(work, struct smx_block, migration_work.work);
	int i;

	smx_block_lock_exclusive(smxblk);
	smxblk->during_migration = true;
	dev_dbg(&smxblk->dev, "entering precopy\n");
	smx_block_unlock_exclusive(smxblk);

	/*
	 * TODO: 5 rounds of pre-copy may not be enough. We should use a while
	 * loop and have some heuristics of when we should stop pre-copy.
	 */
	for (i = 0; i < 5; i++) {
		smx_do_pre_copy(smxblk, i);
	}

	smx_do_stop_and_copy(smxblk);

	smx_do_post_copy(smxblk);

	smx_block_lock_exclusive(smxblk);
	smxblk->during_migration = false;
	smx_block_unlock_exclusive(smxblk);
}
