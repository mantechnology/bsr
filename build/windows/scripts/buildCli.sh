#!/bin/bash
arch=$1

script=$(readlink -f $0)
scriptpath=`dirname $script`

cd $scriptpath
cd ../../../bsr-utils

tr -d '\015' < autogen.sh > autogen_windows.sh
chmod +x autogen_windows.sh
./autogen_windows.sh
./configure --without-bsrcon
cd user/v9
pwd
make clean
if [ $arch = "x64" ]
then
	make $arch'=1'
else
	make
fi

mkdir -p ../../../build/windows/$arch/bin/
cp -uv *.exe ../../../build/windows/$arch/bin/

exit $?
