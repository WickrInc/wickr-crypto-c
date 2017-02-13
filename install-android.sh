export ANDROID_NDK_ROOT=~/android-ndk-r13
export PREFIX=~/usr/Crypto/Android

cd build-android

#for abi in "armeabi"
for abi in "armeabi-v7a" "armeabi" "x86"
do
    cd $abi
    cmake --build .
    cmake -DCMAKE_INSTALL_CONFIG_NAME=Release -DCMAKE_TOOLCHAIN_FILE=./Toolchain-Android.cmake -P cmake_install.cmake
    cd ..
done
