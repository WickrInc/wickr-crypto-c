#!/bin/sh
if NOT EXIST ./Makefile ; then
    PKG_CONFIG_PATH=%1
    export PKG_CONFIG_PATH
    configure --prefix=%1
fi
