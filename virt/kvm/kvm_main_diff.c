//commit1
//replace 2504
pte_t *ptep = NULL;
pmd_t *pmdp = NULL;

//replace 2508
r = follow_pte_or_huge_pmd(vma->vm_mm, addr, &ptep, &pmdp, &ptl);

//replace 2523
r = follow_pte_or_huge_pmd(vma->vm_mm, addr, &ptep, &pmdp, &ptl);

//replace 2528-2531
	if (ptep) {
		if (write_fault && !pte_write(*ptep)) {
			pfn = KVM_PFN_ERR_RO_FAULT;
			goto out;
		}
//replace 2533-2535
		if (writable)
			*writable = pte_write(*ptep);
		pfn = pte_pfn(*ptep);
	} else {
		BUG_ON(pmdp == NULL);
		if (write_fault && !pmd_write(*pmdp)) {
			pfn = KVM_PFN_ERR_RO_FAULT;
			goto out;
		}

		if (writable)
			*writable = pmd_write(*pmdp);

		/*
		 * We have to handle the PFN of a huge page specially, because KVM
		 * assmes 4K pages when calling this function. The huge mapping will
		 * be fixed later in KVM.
		 */
		pfn = pmd_pfn(*pmdp) | ((addr & ~pmd_pfn_mask(*pmdp)) >> PAGE_SHIFT);
	}
//replace 2558
	if (ptep)
		pte_unmap_unlock(ptep, ptl);
	else
		spin_unlock(ptl);


//commit2
//add after 2503
bool unhandled = false;

// add after 2514
	unhandled = true;
	} else if (write_fault &&
		   ((ptep && !pte_write(*ptep)) || (pmdp && !pmd_write(*pmdp)))) {
		/*
		 * If it's a write fault and the pte is not writable, it's possible
		 * that the page is write protected by someone. Need a retry.
		 */
		if (ptep)
			pte_unmap_unlock(ptep, ptl);
		else if (pmdp)
			spin_unlock(ptl);

		unhandled = true;
	}

	if (unhandled) {