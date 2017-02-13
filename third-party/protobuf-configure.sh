#!/bin/sh
if test ! -f ./Makefile ; then
    ./configure --prefix=$1 CFLAGS="-g -O0" CXXFLAGS="-g -O0"
fi
