obj-$(CONFIG_SMX) += smx.o
smx-y := smx_core.o util.o smx_block.o smx_pcie.o smx_provider.o migration.o

KDIR ?= ../../

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	rm -rf *.order *.symvers *.o *.ko *.mod *.mod.c
