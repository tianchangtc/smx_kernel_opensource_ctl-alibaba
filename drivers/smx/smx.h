#ifndef _SMX_H_
#define _SMX_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <inttypes.h>
#endif

#define SMX_PROVIDER_MAGIC 0xBB
#define SMX_PROVIDER_BASE  0x00

#define SMX_PROVIDER_GET_VERSION  _IO(SMX_PROVIDER_MAGIC, SMX_PROVIDER_BASE + 0)
#define SMX_PROVIDER_MAP_REGION   _IO(SMX_PROVIDER_MAGIC, SMX_PROVIDER_BASE + 1)
#define SMX_PROVIDER_UNMAP_REGION _IO(SMX_PROVIDER_MAGIC, SMX_PROVIDER_BASE + 2)

struct smx_provider_map_info {
	uint64_t base;
	uint64_t size;
	uint64_t dva;
	uint64_t id;
};

#endif
