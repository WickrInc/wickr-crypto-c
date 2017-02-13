export ANDROID_NDK=~/android-ndk-r13
export ANDROID_NATIVE_API_LEVEL=android-17

cur_path=`pwd`

mkdir -p build-android
cd build-android

#for abi in "armeabi"
for abi in "armeabi-v7a" "armeabi" "x86"
do
  mkdir -p $abi
  cd $abi
  cmake -DCMAKE_SYSTEM_NAME=Android \
        -DCMAKE_TOOLCHAIN_FILE=./Toolchain-Android.cmake \
        -DANDROID_NDK=~/android-ndk-r13 \
        -DANDROID_NATIVE_API_LEVEL=android-17 \
        -DCMAKE_BUILD_TYPE=Release \
        -DANDROID_ABI="$abi" \
        -DCMAKE_INSTALL_PREFIX=$cur_path/../localRepo/wickr-crypto/android/$abi \
        ../..
  cd ..
done
