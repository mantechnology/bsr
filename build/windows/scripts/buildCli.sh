#!/bin/bash
arch=$1

script=$(readlink -f $0)
scriptpath=`dirname $script`

cd $scriptpath
cd ../../../bsr-utils

tr -d '\015' < autogen.sh > autogen_windows.sh
chmod +x autogen_windows.sh
./autogen_windows.sh
ac_cv_path_DPKG_BUILDPACKAGE=false ./configure --without-bsrcon --without-udev --with-distro=generic --with-initscripttype=none --with-systemdunitdir=no
cd user/v9
pwd
make clean
WIN_EXTRA_CFLAGS="-Wno-unused-variable -Wno-unused-function -Wno-unused-value"
if [ $arch = "x64" ]
then
	make EXTRA_CFLAGS="$WIN_EXTRA_CFLAGS" $arch'=1'
else
	make EXTRA_CFLAGS="$WIN_EXTRA_CFLAGS"
fi

mkdir -p ../../../build/windows/$arch/bin/
cp -uv *.exe ../../../build/windows/$arch/bin/

exit $?
