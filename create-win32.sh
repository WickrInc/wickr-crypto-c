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
echo $cur_path

mkdir -p build-win32
cd build-win32

#cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_CONFIGURATION_TYPES=$BUILD_TYPE -DCMAKE_INSTALL_PREFIX=$cur_path/../localRepo/wickr-crypto/win32 -G "Visual Studio 12 2013" .. > create.log 2>&1
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_CONFIGURATION_TYPES="Release;Debug;MinSizeRel;RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=$cur_path/../localRepo/wickr-crypto/win32 -G "Visual Studio 14 2015" .. > create.log 2>&1
