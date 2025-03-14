cd rootfs && find . | cpio -o -H newc | bzip2 > ../rootfs.cpio.bz2
cp ../rootfs.cpio.bz2 ../dist/rootfs.cpio.bz2