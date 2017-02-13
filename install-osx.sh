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

cd build-osx
xcodebuild -target install -configuration $BUILD_TYPE
