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

cd build-unix
#cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl -DOPENSSL_LIBRARIES=/usr/lib/x86_64-linux-gnu --build .
#cmake -DOPENSSL_LIBRARIES=/usr/lib/x86_64-linux-gnu --build .

cmake --build .

cmake -DCMAKE_INSTALL_PREFIX="../../localRepo/wickr-crypto/unix" -P cmake_install.cmake
