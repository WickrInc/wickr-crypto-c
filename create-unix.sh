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

mkdir -p build-unix
cd build-unix
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCMAKE_INSTALL_PREFIX="../../localRepo/wickr-crypto/unix" -G "Unix Makefiles" ..
