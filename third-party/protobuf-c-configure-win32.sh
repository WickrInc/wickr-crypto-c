#!/bin/sh
if NOT EXIST ./Makefile ; then
    PKG_CONFIG_PATH=`pwd`/../../lib/pkgconfig
    export PKG_CONFIG_PATH
    configure --prefix=`pwd`/../..
fi
