#!/bin/bash

export ARCH=$1; shift

export IOS_SDK_VERSION=`xcodebuild -version -sdk iphoneos 2>/dev/null | grep SDKVersion | cut -f2 -d ':' | tr -d '[[:space:]]'`

DEVELOPER_DIR=`xcode-select -print-path`
SDKVERSION=`xcrun --sdk iphoneos --show-sdk-version 2> /dev/null`
MINSDKVERSION="8.0"

if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ] ;
then
    export IOS_PLATFORM="iPhoneSimulator"
    if [ "${ARCH}" == "x86_64" ]; then
      export CONFIGURE_FOR="darwin64-x86_64-cc"
    else
      export CONFIGURE_FOR="iphoneos-cross"
    fi
else
    export IOS_PLATFORM="iPhoneOS"
    export CONFIGURE_FOR="iphoneos-cross"
fi

export IOS_PLATFORM_LOCATION="${IOS_PLATFORM}.platform"
export CROSS_TOP="${DEVELOPER_DIR}/Platforms/${IOS_PLATFORM_LOCATION}/Developer"

export CROSS_SDK="${IOS_PLATFORM}${IOS_SDK_VERSION}.sdk"

echo CROSS_TOP=$CROSS_TOP
echo CROSS_SDK=$CROSS_SDK

export CC="${DEVELOPER_DIR}/usr/bin/gcc -arch ${ARCH} -miphoneos-version-min=${MINSDKVERSION}"

echo "Going to run: $*"

$*
