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

export HOSTCC=/usr/bin/cc
chmod +x Configure && ./Configure darwin64-x86_64-cc --prefix=${TARGETDIR}
make
if [ "${BUILD_FIPS_TESTS}" == "true" ]; then
  make build_tests && make build_algvs
fi
cd iOS
make incore_macho
cd ..
mkdir -p ${TARGETDIR}
cp -R iOS ${TARGETDIR}/iOS
make install
make clean

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

  MACHINE=`echo "${ARCH}" | sed -e 's/^-//'`
  
  if [[ "${PLATFORM}" == "iPhoneOS" ]]; then
      SYSTEM="iphoneos"
  else
    SYSTEM="darwin"
  fi

  BUILD="build"

  export MACHINE
  export SYSTEM
  export BUILD

  export HOSTCC=/usr/bin/cc
  export HOSTCFLAGS="-arch x86_64"

  # Prepare TARGETDIR
  echo "Building to target directory: ${TARGETDIR}"
  mkdir -p ${TARGETDIR}/${ARCH}
  
  # Add optional enable-ec_nistp_64_gcc_128 configure option for 64 bit builds
  LOCAL_CONFIG_OPTIONS="${CONFIG_OPTIONS}"

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

  # Add --prefix option
  LOCAL_CONFIG_OPTIONS="--prefix=${TARGETDIR}/${ARCH} ${LOCAL_CONFIG_OPTIONS}"

  echo "INSTALLING TO PREFIX: ${TARGETDIR}/${ARCH}"

  # Determine configure target
  if [ "${ARCH}" == "x86_64" ]; then
    LOCAL_CONFIG_OPTIONS="darwin64-x86_64-cc no-asm ${LOCAL_CONFIG_OPTIONS}"
  else 
    LOCAL_CONFIG_OPTIONS="iphoneos-cross ${LOCAL_CONFIG_OPTIONS}"
  fi

  chmod +x Configure && ./Configure ${LOCAL_CONFIG_OPTIONS}

  # Run make
  make
  make install
  make clean

done
