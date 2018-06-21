
mkdir -p build_android/output_fat && cd build_android

# Build all the native modules
for ARCH in armeabi armeabi-v7a x86
do
    mkdir build_android_${ARCH}
    cd build_android_${ARCH}

    cmake -DCMAKE_TOOLCHAIN_FILE=../../Toolchain-Android.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_ANDROID_NDK=${ANDROID_NDK} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=../output_fat \
    -DBUILD_JAVA=ON ../../

    make
    make install

    cd ..
done

cd output_fat/android
./gradlew assembleRelease
