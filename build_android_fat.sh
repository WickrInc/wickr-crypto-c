#!/bin/bash

mkdir -p build_android/output_fat && cd build_android

# Build all the native modules
for ARCH in armeabi-v7a arm64-v8a x86 x86_64 
do
    mkdir build_android_${ARCH}
    cd build_android_${ARCH}

    cmake -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
    -DBUILD_OPENSSL=true \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DCMAKE_BUILD_TYPE=Release \
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
