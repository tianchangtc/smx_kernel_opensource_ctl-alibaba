//add after 1753
EXPORT_SYMBOL_GPL(__get_locked_pte);

//add after 5046
int follow_pte_or_huge_pmd(struct mm_struct *mm, unsigned long address,
			   pte_t **ptepp, pmd_t **pmdpp, spinlock_t **ptlp)
{
	return follow_invalidate_pte(mm, address, NULL, ptepp, pmdpp, ptlp);
}
EXPORT_SYMBOL_GPL(follow_pte_or_huge_pmd);