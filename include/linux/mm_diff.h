//add after 1852
int follow_pte_or_huge_pmd(struct mm_struct *mm, unsigned long address,
			   pte_t **ptepp, pmd_t **pmdpp, spinlock_t **ptlp);