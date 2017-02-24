#!/bin/sh
echo PREFIX=$1
./Configure --prefix=$1 ${CONFIGURE_FOR} 
sed -ie "s!^CFLAG=!CFLAG=-isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK} !" "Makefile"	
echo DONE CONFIGURING
