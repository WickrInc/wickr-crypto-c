#!/bin/sh
#
# Arguments:
# $1 is the prefix
# $2 is the protoc executable full path and filename
# $3 is the ABI
#

if test ! -f ./Makefile ; then
    echo $0 : "$CROSS_COMPILE"
    LIBDIR="$ANDROID_DEV"/lib
    PATH=$PATH:$ANDROID_TOOLCHAIN

    #TODO SET THE ABI in the path appropriately!!!

    ./configure --with-protoc=$2 --disable-shared --enable-cross-compile --target=arm-linux-androideabi --host=x86_64-darwin --prefix=$1 --with-sysroot="$ANDROID_DEV"/lib \
CC="$CROSS_COMPILE"gcc AR="$CROSS_COMPILE"ar LD="$CROSS_COMPILE"ld RANLIB="$CROSS_COMPILE"ranlib LDFLAGS=-L$LIBDIR \
CFLAGS="-g -O0 -march=armv7-a --sysroot=$ANDROID_SYSROOT" \
CXX="$CROSS_COMPILE"g++ CXXFLAGS="-g -O0 -march=armv7-a --sysroot=$ANDROID_SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.9/include -I$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.9/libs/$3/include" \
CPP="$CROSS_COMPILE"cpp CPPFLAGS="-g -O0 -march=armv7-a --sysroot=$ANDROID_SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.9/include -I$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.9/libs/$3/include"

#    ./configure --with-protoc=$2 --enable-cross-compile --target=arm-linux-androideabi --host=x86_64-darwin --prefix=$1 --with-sysroot="$ANDROID_DEV"/lib CC="$CROSS_COMPILE"gcc AR="$CROSS_COMPILE"ar LD="$CROSS_COMPILE"ld RANLIB="$CROSS_COMPILE"ranlib LDFLAGS=-L$LIBDIR CFLAGS="-g -O0 -march=arm7-a --sysroot=$ANDROID_SYSROOT" CXX="$CROSS_COMPILE"g++ CXXFLAGS="-g -O0 -march=arm7-a --sysroot=$ANDROID_SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/system/include -I$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/stlport"

#    ./configure --with-protoc=$2 --enable-cross-compile --target=arm-linux-androideabi --host=x86_64-darwin --prefix=$1 --with-sysroot="$ANDROID_DEV"/lib CC="$CROSS_COMPILE"gcc AR="$CROSS_COMPILE"ar LD="$CROSS_COMPILE"ld RANLIB="$CROSS_COMPILE"ranlib LDFLAGS=-L$LIBDIR CFLAGS="-g -O0 --sysroot=$ANDROID_SYSROOT"
#CPP="$CROSS_COMPILE"cpp CPPFLAGS="-g -O0 --sysroot=$ANDROID_SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/system/include -I$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/stlport"
#CXX="$CROSS_COMPILE"g++ CXXFLAGS="-g -O0 --sysroot=$ANDROID_SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/system/include -I$ANDROID_NDK_ROOT/sources/cxx-stl/stlport/stlport"
fi

