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

cd build-win32
cmake --build . --target ALL_BUILD --config $BUILD_TYPE > install.log

cmake -DCMAKE_INSTALL_CONFIG_NAME=$BUILD_TYPE -P cmake_install.cmake >> install.log

# ONLY WORKS FOR DEBUG RIGHT NOW!!
#msbuild Crypto.sln /p:Configuration=Release >> install.log
#cmake -DCMAKE_INSTALL_CONFIG_NAME=Release -P cmake_install.cmake >> install.log
