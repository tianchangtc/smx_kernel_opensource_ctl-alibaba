//add  after 170
#ifndef arch_io_reserve_memtype_wb
static inline int arch_io_reserve_memtype_wb(resource_size_t base,
					     resource_size_t size)
{
	return 0;
}

static inline void arch_io_free_memtype_wb(resource_size_t base,
					   resource_size_t size)
{
}
#endif