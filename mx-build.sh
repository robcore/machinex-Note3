#!/bin/bash
export PATH=/opt/toolchains/arm-cortex_a15-linux-gnueabihf_5.3/bin:$PATH
# kernel build script for Samsung Galaxy Note 3.
#
# Originally written by jcadduono @ xda
#
# Updated by frequentc @ xda
# - Modified to support command line arguments
# - Made script more generic and customizable
# - Other minor changes
#
# Updated by robcore
# -really just specific stuff for my needs

################### BEFORE STARTING ################
#
# download a working toolchain and extract it somewhere and configure this file
# to point to the toolchain's root directory.
# I highly recommend Christopher83's Linaro GCC 4.9.x Cortex-A15 toolchain.
# Download it here: http://forum.xda-developers.com/showthread.php?t=2098133
#
# once you've set up the config section how you like it, you can simply run
# ./dl-build.sh
#
###################### CONFIG ######################

# root directory of kernel's git repo (default is this script's location)
RDIR=$(pwd)

[ -z $VARIANT ] && \
# device variant/carrier, possible options:
#	can = N900W8	(Canadian, same as T-Mobile)
#	eur = N9005	(Snapdragon International / hltexx / Europe)
#	spr = N900P	(Sprint)
#	tmo = N900T	(T-Mobile, same as Canadian)
#	kor = N900K/L/S	(Unified Korean / KT Corporation, LG Telecom, South Korea Telecom)
# not currently possible options (missing cm12.1 support!):
#	att = N900A	(AT&T)
#	usc = N900R4	(US Cellular)
#	vzw = N900V	(Verizon)
VARIANT=can
[ -z $VER ] && \
# version number
VER=MarkOne
# KERNEL_NAME should NOT contain any spaces
KERNEL_NAME=machinex
# kernel version string appended to 3.4.x-${KERNEL_NAME}-kernel-hlte-
# (shown in Settings -> About device)
KERNEL_VERSION=${KERNEL_NAME}-$VER-$VARIANT
# output directory of flashable kernel
OUT_DIR=$RDIR

# output filename of flashable kernel
OUT_NAME=${KERNEL_NAME}-$KERNEL_VERSION-hlte

# should we make a TWRP flashable zip? (1 = yes, 0 = no)
MAKE_ZIP=1

# should we make an Odin flashable tar.md5? (1 = yes, 0 = no)
MAKE_TAR=0

# amount of cpu threads to use in kernel make process
THREADS=6

############## SCARY NO-TOUCHY STUFF ###############

# Used as the prefix for the ramdisk and zip folders. Also used to prefix the defconfig files in arch/arm/configs/.
FILE_PREFIX=mx
KERNEL_AUTHOR=robcore

RAMDISK_FOLDER=${FILE_PREFIX}.ramdisk
ZIP_FOLDER=${FILE_PREFIX}.zip
DEFCONFIG=mxconfig
VARIANT_DEFCONFIG=mxconfig

export ARCH=arm
export CROSS_COMPILE=/opt/toolchains/arm-cortex_a15-linux-gnueabihf_5.3/bin/arm-cortex_a15-linux-gnueabihf-
export LOCALVERSION=$KERNEL_VERSION
env KCONFIG_NOTIMESTAMP=true

if [ ! -f $RDIR"/arch/arm/configs/${VARIANT_DEFCONFIG}" ] ; then
	echo "Device ${VARIANT_DEFCONFIG} not found in arm configs!"
	exit -1
fi

if [ ! -d $RDIR/${RAMDISK_FOLDER} ] ; then
	echo "${RAMDISK_FOLDER} not found!"
	exit -1
fi

KDIR=$RDIR/build/arch/arm/boot

CLEAN_MAKE()
{
	make clean;
	make distclean;
	make mrproper;
}

CLEAN_BUILD()
{
	echo "Cleaning build..."
	# clean up leftover junk
	find . -type f \( -iname \*.rej \
					-o -iname \*.orig \
					-o -iname \*.bkp \
					-o -iname \*.ko \) \
						| parallel rm -fv {};
	cd $RDIR
	rm -rf build
	echo "Removing old boot.img..."
	rm -f ${ZIP_FOLDER}/boot.img
	echo "Removing old zip/tar.md5 files..."
	rm -f $OUT_DIR/$OUT_NAME.zip
	rm -f $OUT_DIR/$OUT_NAME.tar.md5

	echo "Removing old scripts/mkqcdtbootimg/mkqcdtbootimg..."
	make -C $RDIR/scripts/mkqcdtbootimg clean
	rm -rf $RDIR/scripts/mkqcdtbootimg/mkqcdtbootimg 2>/dev/null
}

BUILD_KERNEL_CONFIG()
{
	echo "Creating kernel config..."
	cd $RDIR
	mkdir -p build
	cp $(pwd)/arch/arm/configs/mxconfig $(pwd)/build/.config
	make ARCH=arm -C $RDIR O=build -j6 oldconfig
}

BUILD_KERNEL()
{
	echo "Starting build..."
	make ARCH=arm -S -s -C $RDIR O=build -j6
}

BUILD_RAMDISK()
{
	echo "Building ramdisk structure..."
	cd $RDIR
	rm -rf build/ramdisk 2>/dev/null
	mkdir -p build/ramdisk
	cp -ar ${RAMDISK_FOLDER}/* build/ramdisk
	echo "Building ramdisk.img..."
	cd $RDIR/build/ramdisk
	mkdir -pm 755 dev proc sys system
	mkdir -pm 771 data
	find | fakeroot cpio -o -H newc | gzip -9 > $KDIR/ramdisk.cpio.gz
	cd $RDIR
}

BUILD_BOOT_IMG()
{
	echo "Generating boot.img..."

	if [ ! -f $RDIR/scripts/mkqcdtbootimg/mkqcdtbootimg ] ; then
		make -C $RDIR/scripts/mkqcdtbootimg
	fi

	$RDIR/scripts/mkqcdtbootimg/mkqcdtbootimg --kernel $KDIR/zImage \
		--ramdisk $KDIR/ramdisk.cpio.gz \
		--dt_dir $KDIR \
		--cmdline "console=null androidboot.hardware=qcom user_debug=23 msm_rtb.filter=0x37 ehci-hcd.park=3" \
		--base 0x00000000 \
		--pagesize 2048 \
		--ramdisk_offset 0x02000000 \
		--tags_offset 0x01e00000 \
		--output $RDIR/${ZIP_FOLDER}/boot.img
}

CREATE_ZIP()
{
	if [ $MAKE_ZIP != 1 ]; then return; fi

	echo "Compressing to TWRP flashable zip file..."
	cd $RDIR/${ZIP_FOLDER}
	zip -r -9 - * > $OUT_DIR/$OUT_NAME.zip
	cd $RDIR
}

CREATE_TAR()
{
	if [ $MAKE_TAR != 1 ]; then return; fi

	echo "Compressing to Odin flashable tar.md5 file..."
	cd $RDIR/${ZIP_FOLDER}
	tar -H ustar -c boot.img > $OUT_DIR/$OUT_NAME.tar
	cd $OUT_DIR
	md5sum -t $OUT_NAME.tar >> $OUT_NAME.tar
	mv $OUT_NAME.tar $OUT_NAME.tar.md5
	cd $RDIR
}

function SHOW_HELP()
{
	SCRIPT_NAME=`basename "$0"`

	cat << EOF
${KERNEL_NAME} by ${KERNEL_AUTHOR}. To configure this script for your build, edit the top of mx-build.sh before continuing.

usage: ./$SCRIPT_NAME [OPTION]

Common options:
  -a|--all		Do a complete build (starting at the beginning)
  -c|--clean		Remove everything this build script has done
  -m|--clean_make	Perform make proper|clean|distclean in one sweep
  -k|--kernel		Try the build again starting at compiling the kernel
  -r|--ramdisk		Try the build again starting at the ramdisk

Other options that only complete 1 part of the build:
 -ko|--kernel-only	Recompile only the kernel

Build script by jcadduono, frequentc & robcore
EOF

	exit -1
}

function BUILD_RAMDISK_CONTINUE()
{
	BUILD_RAMDISK && BUILD_BOOT_IMG && CREATE_ZIP && CREATE_TAR
}

function BUILD_KERNEL_CONTINUE()
{
	BUILD_KERNEL && BUILD_RAMDISK_CONTINUE
}

function BUILD_ALL()
{
	CLEAN_BUILD && BUILD_KERNEL_CONFIG && BUILD_KERNEL_CONTINUE
}

if [ $# = 0 ] ; then
	SHOW_HELP
fi

while [[ $# > 0 ]]
	do
	key="$1"

	case $key in
	     -a|--all)
		if ! BUILD_ALL; then
			echo "Failed!"
			exit -1
		else
			echo "Finished!"
		fi
		break
	    	;;

	     -c|--clean)
	    	CLEAN_BUILD
	    	break
	    	;;

	     -m|--clean_make)
	    	CLEAN_MAKE
	    	break
	    	;;

	     -k|--kernel)
	    	if ! BUILD_KERNEL_CONTINUE; then
			echo "Failed!"
			exit -1
		else
			echo "Finished!"
		fi
	    	break
	    	;;

	    -ko|--kernel-only)
	    	if ! BUILD_KERNEL; then
			echo "Failed!"
			exit -1
		else
			echo "Finished!"
		fi
	    	break
	    	;;

	     -r|--ramdisk)
	     	if ! BUILD_RAMDISK_CONTINUE; then
			echo "Failed!"
			exit -1
		else
			echo "Finished!"
		fi
	    	break
	    	;;

	    *)
	    	SHOW_HELP
	    	break;
	    	;;
	esac
	shift # past argument or value
done
