set -e

if [ -z ${FIPS} ]; then
    FIPS=false
fi

git submodule update --init --recursive
mkdir build_device
cd build_device

cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/../Toolchain-iOS.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_BITCODE=NO \
    -DIOS_PLATFORM=OS64 \
    -DFIPS=${FIPS} \
    -DIOS_DEPLOYMENT_TARGET=13.0 \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_device ../
make
make install
cd ..


# Does not support fips
mkdir build_sim
cd build_sim
cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/../Toolchain-iOS.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_BITCODE=NO \
    -DIOS_PLATFORM=SIMULATOR64 \
    -DIOS_DEPLOYMENT_TARGET=13.0 \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_sim ../
make
make install
cd ..


# Does not support FIPS
mkdir build_arm_sim
cd build_arm_sim
cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/../Toolchain-iOS.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_BITCODE=NO \
    -DIOS_PLATFORM=SIMULATORARM64 \
    -DIOS_DEPLOYMENT_TARGET=13.0 \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_arm_sim ../
make
make install
cd ..

mkdir -p output_fat/lib
mkdir -p output_fat/include
mkdir -p output_sim_fat
cp -R output_device/include output_fat
rm -rf output_fat/include/wickrcrypto

mkdir output_device/lib/libcrypto.framework
mkdir output_sim/lib/libcrypto.framework
mkdir output_arm_sim/lib/libcrypto.framework

cp third-party/openssl/aws-lc/CryptoInfo.plist output_device/lib/libcrypto.framework/Info.plist
cp third-party/openssl/aws-lc/CryptoInfo.plist output_sim/lib/libcrypto.framework/Info.plist
cp third-party/openssl/aws-lc/CryptoInfo.plist output_arm_sim/lib/libcrypto.framework/Info.plist

mkdir output_device/lib/libssl.framework
mkdir output_sim/lib/libssl.framework
mkdir output_arm_sim/lib/libssl.framework

cp third-party/openssl/aws-lc/SslInfo.plist output_device/lib/libssl.framework/Info.plist
cp third-party/openssl/aws-lc/SslInfo.plist output_sim/lib/libssl.framework/Info.plist
cp third-party/openssl/aws-lc/SslInfo.plist output_arm_sim/lib/libssl.framework/Info.plist

lipo -create output_device/lib/libcrypto.dylib -output output_device/lib/libcrypto.framework/libcrypto
lipo -create output_sim/lib/libcrypto.dylib output_arm_sim/lib/libcrypto.dylib -output output_sim/lib/libcrypto.framework/libcrypto

lipo -create output_device/lib/libssl.dylib -output output_device/lib/libssl.framework/libssl
lipo -create output_sim/lib/libssl.dylib output_arm_sim/lib/libssl.dylib -output output_sim/lib/libssl.framework/libssl

install_name_tool -id @rpath/libcrypto.framework/libcrypto output_device/lib/libcrypto.framework/libcrypto
install_name_tool -id @rpath/libcrypto.framework/libcrypto output_sim/lib/libcrypto.framework/libcrypto

install_name_tool -id @rpath/libssl.framework/libssl output_device/lib/libssl.framework/libssl
install_name_tool -id @rpath/libssl.framework/libssl output_sim/lib/libssl.framework/libssl

install_name_tool -change @rpath/libcrypto.dylib @rpath/libcrypto.framework/libcrypto output_device/lib/libssl.framework/libssl
install_name_tool -change @rpath/libcrypto.dylib @rpath/libcrypto.framework/libcrypto output_sim/lib/libssl.framework/libssl

xcodebuild -create-xcframework -framework output_device/lib/libcrypto.framework -framework output_sim/lib/libcrypto.framework -output output_fat/lib/libcrypto.xcframework
xcodebuild -create-xcframework -framework output_device/lib/libssl.framework -framework output_sim/lib/libssl.framework -output output_fat/lib/libssl.xcframework

lipo -create output_sim/lib/libprotobuf-c.a output_arm_sim/lib/libprotobuf-c.a -output output_sim_fat/libprotobuf-c.a
lipo -create output_sim/lib/libscrypt.a output_arm_sim/lib/libscrypt.a -output output_sim_fat/libscrypt.a
lipo -create output_sim/lib/libbcrypt.a output_arm_sim/lib/libbcrypt.a -output output_sim_fat/libbcrypt.a

xcodebuild -create-xcframework -library output_device/lib/libprotobuf-c.a -library output_sim_fat/libprotobuf-c.a -output output_fat/lib/libprotobuf-c.xcframework
xcodebuild -create-xcframework -library output_device/lib/libscrypt.a -library output_sim_fat/libscrypt.a -output output_fat/lib/libscrypt.xcframework
xcodebuild -create-xcframework -library output_device/lib/libbcrypt.a -library output_sim_fat/libbcrypt.a -output output_fat/lib/libbcrypt.xcframework
