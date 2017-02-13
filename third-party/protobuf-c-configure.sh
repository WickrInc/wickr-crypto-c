#!/bin/sh
if test ! -f ./Makefile ; then
    PKG_CONFIG_PATH=`pwd`/../../lib/pkgconfig
    export PKG_CONFIG_PATH
    ./configure --prefix=`pwd`/../.. CFLAGS="-g -O0" CXXFLAGS="-g -O0"
fi
