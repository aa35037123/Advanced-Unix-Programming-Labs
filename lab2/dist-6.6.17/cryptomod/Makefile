
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB
CPIO=rootfs.cpio.bz2

all: crypto 
	make -C ../dist/modulebuild M=$(PWD) modules

crypto: crypto.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f crypto
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp crypto cryptomod.ko ../rootfs/modules
