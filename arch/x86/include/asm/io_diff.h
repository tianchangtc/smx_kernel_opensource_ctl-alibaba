//add after 375
extern int arch_io_reserve_memtype_wb(resource_size_t start, resource_size_t size);
extern void arch_io_free_memtype_wb(resource_size_t start, resource_size_t size);
#define arch_io_reserve_memtype_wb arch_io_reserve_memtype_wb