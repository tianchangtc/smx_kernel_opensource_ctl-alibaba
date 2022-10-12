/*
 *
 */
#ifndef __BOARD_H__
#define __BOARD_H__

/*
 * Fence write combine memory.
 */
#define	WC_FENCE()					\
	do {						\
		asm volatile("sfence" ::: "memory");	\
	} while (0)

/*
 * DMA Alignment.
 */
#define DMA_ALIGNMENT	4096

/*
 * IMEM
 */
#define IMEM_ADDR	0x00000000
#define IMEM_SIZE	(512 * 1024)

/*
 * DMEM
 */
#define DMEM_ADDR	0x00800000
#define DMEM_SIZE	(512 * 1024)

/*
 * URAM 0-3
 */
#define URAM_0_ADDR	0x03000000
#define URAM_0_SIZE	(4096 * 1024)

#define URAM_1_ADDR	0x03400000
#define URAM_1_SIZE	(4096 * 1024)

#define URAM_2_ADDR	0x03800000
#define URAM_2_SIZE	(4096 * 1024)

#define URAM_3_ADDR	0x03C00000
#define URAM_3_SIZE	(4096 * 1024)

/*
 * DDR
 */
#define DDR_0_ADDR	0x10000000000
#define DDR_0_SIZE	0x2000000000

#define DDR_1_ADDR	0x12000000000
#define DDR_1_SIZE	0x2000000000

#define DDR_2_ADDR	0x14000000000
#define DDR_2_SIZE	0x2000000000

#define DDR_3_ADDR	0x16000000000
#define DDR_3_SIZE	0x2000000000

/*
 * CSR Registers.
 */
#define CSR_REGS_ADDR	0xC0000000
#define CSR_REGS_SIZE	4096

/*
 * CSR Register bits.
 */
#define CSR_CPU_RESET	(1 << 0)

/*
 * Window REGS
 */
#define WINDOW_REGS_ADDR	0x04000000
#define WINDOW_REGS_SIZE	4096

#define WINDOW_0_ADDR		0x100000000
#define WINDOW_0_SIZE		0x40000000

#define WINDOW_1_ADDR		0x140000000
#define WINDOW_1_SIZE		0x40000000

#define WINDOW_2_ADDR		0x180000000
#define WINDOW_2_SIZE		0x40000000

#define WINDOW_3_ADDR		0x100000000
#define WINDOW_3_SIZE		0x40000000

/*
 * HOST Memory write region.
 */
#define HOST_MEM_WADDR		0x10000000000

#endif /* __BOARD_H__ */
