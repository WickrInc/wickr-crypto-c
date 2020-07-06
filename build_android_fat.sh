#!/bin/bash

if [ -z ${FIPS} ]; then
    FIPS=false
fi

mkdir -p build_android/output_fat && cd build_android

# Build all the native modules
for ARCH in armeabi-v7a x86 x86_64 arm64-v8a  
do
    mkdir build_android_${ARCH}
    cd build_android_${ARCH}

    if [ "${ARCH}" = "x86" ] || [ "${ARCH}" = "x86_64" ]; then
        _FIPS=false
    else
        _FIPS=${FIPS}
    fi

    cmake -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
    -DBUILD_OPENSSL=true \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DCMAKE_BUILD_TYPE=Release \
    -DFIPS=${_FIPS} \
    -DOSSL_SUPPORT_UNAME="${OSSL_SUPPORT_UNAME}" \
    -DOSSL_SUPPORT_PASS="${OSSL_SUPPORT_PASS}" \
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
