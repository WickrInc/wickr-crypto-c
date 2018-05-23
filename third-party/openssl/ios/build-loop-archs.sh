#!/bin/sh

#  Automatic build script for libssl and libcrypto
#  for iPhoneOS and iPhoneSimulator
#
#  Created by Felix Schulze on 16.12.10.
#  Copyright 2010-2016 Felix Schulze. All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

ARCHS=$1

DEVELOPER=$(xcode-select -print-path)
if [ ! -d "${DEVELOPER}" ]; then
  echo "Xcode path is not set correctly ${DEVELOPER} does not exist"
  echo "run"
  echo "sudo xcode-select -switch <Xcode path>"
  echo "for default installation:"
  echo "sudo xcode-select -switch /Applications/Xcode.app/Contents/Developer"
  exit 1
fi

# Determine relevant SDK version
SDKVERSION=${IOS_SDKVERSION}

for ARCH in ${ARCHS}
do

  # Determine platform

  if [[ "${ARCH}" == "i386" ]]; then
    PLATFORM="iPhoneSimulator"
    TARGET="iphoneos-cross"
    ARCH_FLAG="-arch i386"
  elif [[ "${ARCH}" == "x86_64" ]]; then
    PLATFORM="iPhoneSimulator"
    TARGET="iphoneos-cross"
    ARCH_FLAG="-arch x86_64"
  elif [[ "${ARCH}" == armv7 ]]; then
    TARGET="ios-cross"
    PLATFORM="iPhoneOS"
    ARCH_FLAG=""
  else
    TARGET="ios64-cross"
    PLATFORM="iPhoneOS"
    ARCH_FLAG=""
  fi

  # Set env vars for Configure
  export CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
  export CROSS_SDK="${PLATFORM}${SDKVERSION}.sdk"
  export CC=clang
  export PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"

  # Prepare TARGETDIR
  echo "Building to target directory: ${TARGETDIR}"
  mkdir -p ${TARGETDIR}/${ARCH}
  
  LOCAL_CONFIG_OPTIONS="${CONFIG_OPTIONS}"
 
  # Only relevant for 64 bit builds
  if [[ "${CONFIG_ENABLE_EC_NISTP_64_GCC_128}" == "true" && "${ARCH}" == *64  ]]; then
    LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} enable-ec_nistp_64_gcc_128"
  fi

  # Add --prefix option
  LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} no-async no-shared -fembed-bitcode -miphoneos-version-min=${IOS_MIN_SDK_VERSION} --prefix=${TARGETDIR}/${ARCH}"

  # Run Configure
  if [ -z "${ARCH_FLAG}" ]; then
    ./Configure ${TARGET} ${LOCAL_CONFIG_OPTIONS}
  else 
    ./Configure ${TARGET} ${LOCAL_CONFIG_OPTIONS} "${ARCH_FLAG}"
  fi

  # Run make
  make -j $(sysctl hw.ncpu | awk '{print $2}')

  # Run make install
  set -e
  make install_sw

  # Keep reference to first build target for include file
  if [ -z "${INCLUDE_DIR}" ]; then
    INCLUDE_DIR="${TARGETDIR}/${ARCH}/include"
  fi

  LIBCRYPTO_IOS+=("${TARGETDIR}/${ARCH}/lib/libcrypto.a")

  make distclean
done

cp -R ${INCLUDE_DIR} ${TARGETDIR}/include

mkdir ${TARGETDIR}/lib
lipo -create ${LIBCRYPTO_IOS[@]} -output "${TARGETDIR}/lib/libcrypto.a"


