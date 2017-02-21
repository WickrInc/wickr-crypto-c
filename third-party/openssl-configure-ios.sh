#!/bin/sh
echo PREFIX=$1
./Configure --prefix=$1 darwin64-x86_64-cc 
sed -ie "s!^CFLAG=!CFLAG=-isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK} !" "Makefile"	
echo DONE CONFIGURING
