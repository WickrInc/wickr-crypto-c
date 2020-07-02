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

export FIPS_SIG=${FIPSDIR}/iOS/incore_macho

DEVELOPER=$(xcode-select -print-path)
if [ ! -d "${DEVELOPER}" ]; then
  echo "Xcode path is not set correctly ${DEVELOPER} does not exist"
  echo "run"
  echo "sudo xcode-select -switch <Xcode path>"
  echo "for default installation:"
  echo "sudo xcode-select -switch /Applications/Xcode.app/Contents/Developer"
  exit 1
fi

for ARCH in ${ARCHS}
do
  # Determine relevant SDK version
  if [[ "$ARCH" == tv* ]]; then
    SDKVERSION=${TVOS_SDKVERSION}
  else
    SDKVERSION=${IOS_SDKVERSION}
  fi

  # Determine platform, override arch for tvOS builds
  if [[ "${ARCH}" == "i386" || "${ARCH}" == "x86_64" ]]; then
    PLATFORM="iPhoneSimulator"
  elif [ "${ARCH}" == "tv_x86_64" ]; then
    ARCH="x86_64"
    PLATFORM="AppleTVSimulator"
  elif [ "${ARCH}" == "tv_arm64" ]; then
    ARCH="arm64"
    PLATFORM="AppleTVOS"
  else
    PLATFORM="iPhoneOS"
  fi

  # Set env vars for Configure
  export CROSS_TOP="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
  export CROSS_SDK="${PLATFORM}${SDKVERSION}.sdk"
  export BUILD_TOOLS="${DEVELOPER}"
  export CC="${BUILD_TOOLS}/usr/bin/gcc -arch ${ARCH}"

  # Prepare TARGETDIR
  echo "Building to target directory: ${TARGETDIR}"
  mkdir -p ${TARGETDIR}/${ARCH}
  
  # Add optional enable-ec_nistp_64_gcc_128 configure option for 64 bit builds
  LOCAL_CONFIG_OPTIONS="${CONFIG_OPTIONS}"
  if [ "${CONFIG_ENABLE_EC_NISTP_64_GCC_128}" == "true" ]; then
    case "${ARCH}" in
      *64*)
        LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} enable-ec_nistp_64_gcc_128"
      ;;
    esac
  fi

  case "${ARCH}" in
    *armv7*)
      if [ -z ${APPLIED_PATCH} ]; then
          patch -p3 < "${SOURCEDIR}/armv7-frame-pointer-xcode9.patch" Configure
          APPLIED_PATCH=true
      fi
    ;;
    *arm64*)
      if [ ! -z ${APPLIED_PATCH} ]; then
          patch -R < "${SOURCEDIR}/armv7-frame-pointer-xcode9.patch" Configure
          APPLIED_PATCH=""
      fi
    ;;
  esac


  # Embed bitcode for SDK >= 9
  if [ "${CONFIG_DISABLE_BITCODE}" != "true" ]; then
    if [[ "${SDKVERSION}" == 9.* || "${SDKVERSION}" == [0-9][0-9].* ]]; then
      LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} -fembed-bitcode"
    fi
  fi

  # Add platform specific config options
  if [[ "${PLATFORM}" == AppleTV* ]]; then
    LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} -DHAVE_FORK=0 -mtvos-version-min=${TVOS_MIN_SDK_VERSION}"
    echo "  Patching Configure..."
    LC_ALL=C sed -i -- 's/D\_REENTRANT\:iOS/D\_REENTRANT\:tvOS/' "./Configure"
  else
    LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} -miphoneos-version-min=${IOS_MIN_SDK_VERSION}"
  fi

  if [[ "${PLATFORM}" == iPhoneSimulator ]]; then
    LOCAL_CONFIG_OPTIONS="${LOCAL_CONFIG_OPTIONS} no-engine no-apps"
  fi

  # Add --openssldir option
  LOCAL_CONFIG_OPTIONS="--openssldir=${TARGETDIR}/${ARCH} --with-fipsdir=${FIPSDIR}/${ARCH} ${LOCAL_CONFIG_OPTIONS}"

  # Determine configure target
  if [ "${ARCH}" == "x86_64" ]; then
    LOCAL_CONFIG_OPTIONS="fips darwin64-x86_64-cc no-asm ${LOCAL_CONFIG_OPTIONS}"
  else
    LOCAL_CONFIG_OPTIONS="fips iphoneos-cross ${LOCAL_CONFIG_OPTIONS}"
  fi

  # Run Configure
  export COMMAND_MODE=unix2003
  ./Configure ${LOCAL_CONFIG_OPTIONS}

  # Only required for Darwin64 builds (-isysroot is automatically added by iphoneos-cross target)
  if [ "${ARCH}" == "x86_64" ]; then
    echo "  Patching Makefile..."
    sed -ie "s!^CFLAG=!CFLAG=-isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK} !" "Makefile"
  fi

  # Run make depend if relevant
  if [[ ! -z "${CONFIG_OPTIONS}" ]]; then
    echo "  Make depend...\c"
    export COMMAND_MODE=unix2003
    make depend
  fi

  # Run make
  BUILD_THREADS=$(sysctl hw.ncpu | awk '{print $2}')
  export COMMAND_MODE=unix2003
  make -j ${BUILD_THREADS}

  # Run make install
  set -e
  make install_sw

  # Keep reference to first build target for include file
  if [ -z "${INCLUDE_DIR}" ]; then
    INCLUDE_DIR="${TARGETDIR}/${ARCH}/include/openssl"
  fi

  LIBCRYPTO_IOS+=("${TARGETDIR}/${ARCH}/lib/libcrypto.a")
  LIBSSL_IOS+=("${TARGETDIR}/${ARCH}/lib/libssl.a")

  make distclean
done

rm -rf ${TARGETDIR}/include/openssl

echo "COPYING ${INCLUDE_DIR} to ${TARGETDIR}"
mkdir -p ${TARGETDIR}/include
cp -R ${INCLUDE_DIR} ${TARGETDIR}/include

mkdir -p ${TARGETDIR}/lib
lipo -create ${LIBCRYPTO_IOS[@]} -output "${TARGETDIR}/lib/libcrypto.a"
lipo -create ${LIBSSL_IOS[@]} -output "${TARGETDIR}/lib/libssl.a"
