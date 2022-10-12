//add after 821
int arch_io_reserve_memtype_wb(resource_size_t start, resource_size_t size)
{
	enum page_cache_mode type = _PAGE_CACHE_MODE_WB;

	return memtype_reserve_io(start, start + size, &type);
}
EXPORT_SYMBOL(arch_io_reserve_memtype_wb);

void arch_io_free_memtype_wb(resource_size_t start, resource_size_t size)
{
	memtype_free_io(start, start + size);
}
EXPORT_SYMBOL(arch_io_free_memtype_wb);