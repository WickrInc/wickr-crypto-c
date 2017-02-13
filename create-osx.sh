#!/bin/bash

if [ $# -eq 0 ]
then
    BUILD_TYPE="Debug"
elif [ "$1" == "debug" ]
then
    BUILD_TYPE="Debug"
elif [ "$1" == "release" ]
then
    BUILD_TYPE="Release"
else
    echo "Invalid build type specified, choose one of debug or release"
    exit 1
fi

echo "Build type is $BUILD_TYPE"

cur_path=`pwd`

mkdir -p build-osx
cd build-osx

cmake -DCMAKE_TOOLCHAIN_FILE=./Toolchain-MacOS.cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_CONFIGURATION_TYPES="Release;Debug;MinSizeRel;RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=$cur_path/../localRepo/wickr-crypto/osx -G "Xcode" ..
