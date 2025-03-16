#!/bin/bash

bunzip2 rootfs.cpio.bz2;
mkdir -p rootfs;
cd rootfs && cpio -idmv < ../rootfs.cpio;
