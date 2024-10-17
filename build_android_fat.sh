#!/bin/bash
set -e

if [ -z ${FIPS} ]; then
    FIPS=false
fi

mkdir -p build_android/output_fat && cd build_android

# Build all the native modules
for ARCH in armeabi-v7a x86 x86_64 arm64-v8a  
do
    mkdir build_android_${ARCH}
    cd build_android_${ARCH}

    if [ "${ARCH}" != "arm64-v8a" ]; then
        _FIPS=false
    else
        _FIPS=${FIPS}
    fi

    _FLAGS="-s"

    echo "Building for arch ${ARCH}. FIPS=${_FIPS} FLAGS=${_FLAGS}"

    cmake -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
    -DBUILD_OPENSSL=true \
    -DANDROID_NATIVE_API_LEVEL=26 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS=${_FLAGS} \
    -DFIPS=${_FIPS} \
    -DANDROID_ABI=${ARCH} \
    -DCMAKE_INSTALL_PREFIX=../output_fat \
    -DBUILD_JAVA=ON ../../

    make
    make install

    cd ..
done

cd output_fat/android
chmod +x gradlew
./gradlew assembleRelease || exit $?

if [ "$1" == "--push" ]; then
    ./gradlew artifactoryPublish || exit $?
fi

exit $?
