#!/bin/bash
export PATH=/opt/toolchains/arm-cortex_a15-linux-gnueabihf_5.3/bin:$PATH
export ARCH=arm
export CROSS_COMPILE=/opt/toolchains/arm-cortex_a15-linux-gnueabihf_5.3/bin/arm-cortex_a15-linux-gnueabihf-
env KCONFIG_NOTIMESTAMP=true
rm -rf $(pwd)/build
mkdir $(pwd)/build
cp $(pwd)/arch/arm/configs/mxconfig $(pwd)/build/.config;
make ARCH=arm -j6 O=$(pwd)/build oldconfig;
make ARCH=arm -S -s -j6 O=$(pwd)/build $(pwd)/drivers/input/touchscreen/;
