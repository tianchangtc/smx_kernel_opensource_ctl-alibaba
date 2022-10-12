#ifndef __SMX_INTERNAL_H__
#define __SMX_INTERNAL_H__

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/uuid.h>
#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>

#include "smx.h"

#define SMX_VERSION 0x20220808

#define SMX_MAX_DEVICES 65536
#define SMX_MAX_BLOCKS 65536

#define SMX_PROVIDER_SIZE (SZ_32G*8L)
#define SMX_PROVIDER_GRANULARITY SZ_2M
#define SMX_PROVIDER_NR_SLOTS (SMX_PROVIDER_SIZE/SMX_PROVIDER_GRANULARITY)

/*
 * A DVA space starting at 0 would confuse the memory allocator. We
 * work around it by allocating memory starting from a base address.
 */
#define SMX_PROVIDER_DVA_BASE SMX_PROVIDER_SIZE

#define SMX_MAX_NAME_SIZE 32

typedef enum {
	SMX_REG_VERSION_NAIVE,
	SMX_REG_VERSION_MBOX
} smx_regs_version_t;

struct smx_regs {
	smx_regs_version_t version;
	void __iomem *csrs;
};

struct smx_migration_meta {
	spinlock_t lock;
	enum {
		SMX_MIG_STAGE_NONE = 0, /* not being migrated */
		SMX_MIG_STAGE_PRECOPY, /* during precopy */
		SMX_MIG_STAGE_STOP_AND_COPY, /* during stop-and-copy */
		SMX_MIG_STAGE_POSTCOPY, /* during postcopy */
		SMX_MIG_STAGE_FINISH, /* during finishing */
	} stage;
};

/*
 * A full slice is 256M; however, in the SMX hardware odd and even cachelines
 * are handled by two independent caches.
 */
#define SMX_HALF_SLICE_SIZE SZ_128M
#define SMX_SLICE_SIZE (2 * SMX_HALF_SLICE_SIZE)
#define SMX_CACHE_GRANULARITY SZ_2M

/*
 * Defines how many pages share a stage and lock. SZ_2M can be changed to
 * any power of 2 less than SMX_SLICE_SIZE but greater than 64*4K.
 */
#define SMX_MIG_META_GRANULARITY SZ_2M
#define SMX_NR_PAGES_PER_META (SMX_MIG_META_GRANULARITY / PAGE_SIZE)
#define SMX_MIG_META_PER_SLICE (SMX_SLICE_SIZE / SMX_MIG_META_GRANULARITY)

/*
 * Slice is the minimal manageable granularity in SMX. Each full slice is 256MB.
 * A full slice is divided into two half slices for odd and even cachelines.
 * Each half slice must be located in a single remote machine, as a physically
 * contiguous range of memory aligned to 128M.
 * TODO: Do we force the whole full slice to be on the same remote machine? As
 * that will make memory management and migration easier. (Currently we do.)
 */
struct smx_half_slice {
	u8 hwaddr[6];
	u16 configured:1;
	/* The reserved 15 bits can be used to do a number of things in the future. */
	u16 reserved:15;
	/* This is a slice-offset, which equals device_va / SMX_HALF_SLICE_SIZE */
	u32 base_half_slice_num;
};
struct smx_full_slice {
	uint64_t pa;
	void *va; /* kernel-mapped virtual address, only used during migration */
	struct smx_half_slice half[2];

	/*
	 * To access dirty_bitmap or per-meta stage variable, you need acquire:
	 * 1. smxblk exclusive lock, or
	 * 2. smxblk shared lock + meta lock.
	 */
	struct smx_migration_meta *migration_meta;
	/*
	 * dirty bitmap used in migration. It's twice the needed size since the
	 * second half will be used as a buffer during pre-copy.
	 */
	uint64_t *dirty_bitmap;
	/*
	 * The migration destination if the slice is under migration. It's also
	 * used to indicate whether a slice is under migration.
	 */
	struct smx_full_slice *migration_dest;
};
#define SMX_SLICE_DIRTY_BITMAP_SIZE (SMX_SLICE_SIZE/PAGE_SIZE/8)

/*
 * A block is the minimal mappable memory, and will show under /dev as a char
 * device. QEMU/KVM are expected to map a block.
 */
struct smx_block {
	struct device dev;
	struct cdev cdev;

	/*
	 * id is allocated by the ida in parent smx_device, global_id is a globally
	 * unique id allocated by smx_block_ida.
	 */
	int id;
	int global_id;

	/* All smx_blocks are added to a linked list in their parent device. */
	struct list_head node;

	/*
	 * The vma data structure of the block. Currently, we only allo a block
	 * to be mapped once. When mapping, vma will be set.
	 */
	struct vm_area_struct *vma;

	bool occupied;
	bool during_migration;
	bool huge_splitted;
	uint64_t size;
	uint32_t pgsize;

	/*
	 * The read/write semaphore used to protect various fields in the data
	 * structure. See smx_full_slice for more details about locking.
	 */
	struct rw_semaphore rwsem;

	struct delayed_work migration_work;

	/*
	 * This is an array appended at the tail of smx_block. Each element of
	 * the array is a full slice.
	 */
	uint64_t nr_configured_half_slices;
	struct smx_full_slice slices[0];
};
#define NR_SLICES(smxblk) ((smxblk)->size / SMX_SLICE_SIZE)
#define NR_HALF_SLICES(smxblk) ((smxblk)->size / SMX_HALF_SLICE_SIZE)
#define GET_HALF_SLICE_BY_OFFSET(smxblk, offset) (&(smxblk)->slices[(offset)/2].half[(offset)%2])

/*
 * Data structure used in the provider. Each pinned user space memory
 * region will have a smx_provider_memory_region in the driver, organized
 * in a linked list in smx_provider.
 */
struct smx_provider_memory_region {
	struct list_head node;
	struct smx_provider *provider;
	struct file *file;
	uint64_t id;
	uint64_t size;
	uint64_t dva;
	struct page *pages[0];
};

/* The provider data structure. */
struct smx_provider {
	struct device dev;
	struct cdev cdev;

	/*
	 * The address space allocator. Note that the allocated address space
	 * does not start from 0, because a 0 address will confuse the code,
	 * making the code believe the allocation fails.
	 */
	struct gen_pool *address_space;
	uint64_t address_space_size;

	struct mutex mutex;
	bool occupied;
	struct ida ida;
	struct list_head pinned_regions;
};

struct smx_device {
	struct device dev;
	struct pci_dev *pdev;
	int id;

	/* Address space allocator for the CXL window. */
	struct gen_pool *address_space;
	uint64_t phys_mem_region_start;
	uint64_t phys_mem_region_size;

	/* ida used to allocate block id */
	struct ida ida;

	struct list_head block_list;
	struct mutex block_list_mutex;

	/* All smx_device will be in smx_device_list */
	struct list_head node;

	/*
	 * TODO: This field is not currently implemented. It's a placeholder
	 * that we can put the MMIO registers in.
	 */
	struct smx_regs regs;

	struct smx_provider provider;
};

extern struct class *smx_class;
extern struct list_head smx_device_list;
extern struct mutex smx_device_list_mutex;
extern struct pci_driver smx_pci_driver;

static inline struct smx_device *to_smx_device(struct device *dev)
{
	return container_of(dev, struct smx_device, dev);
}

static inline struct smx_block *to_smx_block(struct device *dev)
{
	return container_of(dev, struct smx_block, dev);
}


static inline struct smx_device *smx_block_get_parent(struct smx_block *smxblk)
{
	struct device *parent = smxblk->dev.parent;

	return parent ? to_smx_device(parent) : NULL;
}

static inline void smx_block_lock_init(struct smx_block *smxblk)
{
	init_rwsem(&smxblk->rwsem);
}

static inline void smx_block_lock_shared(struct smx_block *smxblk) 
{
	down_read(&smxblk->rwsem);
}

static inline void smx_block_unlock_shared(struct smx_block *smxblk)
{
	up_read(&smxblk->rwsem);
}

//static inline void smx_block_lock_shared(struct smx_block *smxblk)
//{
//	down_write(&smxblk->rwsem);
//}
//
//static inline void smx_block_unlock_shared(struct smx_block *smxblk)
//{
//	up_write(&smxblk->rwsem);
//}

static inline void smx_block_lock_exclusive(struct smx_block *smxblk)
{
	down_write(&smxblk->rwsem);
}

static inline void smx_block_unlock_exclusive(struct smx_block *smxblk)
{
	up_write(&smxblk->rwsem);
}

struct smx_device *smx_device_alloc(uint64_t pa, uint64_t size);
void smx_device_free(struct smx_device *smxdev);
int smx_block_init(void);
void smx_block_exit(void);
int smx_create_and_add_block(struct smx_device *smxdev, uint64_t size);
void smx_free_block(struct smx_block *smxblk);

int smx_provider_init(void);
void smx_provider_exit(void);
int smx_device_initialize_provider(struct smx_device *smxdev);
void smx_device_uninitialize_provider(struct smx_device *smxdev);

#endif
