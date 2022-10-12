//replace 2791
if (pfn_valid(pfn) &&
	    !PageCompound(pfn_to_page(pfn)) && !kvm_is_zone_device_pfn(pfn))
//replace 2875
if (is_error_noslot_pfn(fault->pfn))
