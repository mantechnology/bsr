#!/bin/bash
arch=$1
#cd -P "$( dirname "$0" )"
#cd ../../..
#cd drbdpkg/user
sed -i 's/^M//g' ./autogen.sh
./autogen
./configure
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
