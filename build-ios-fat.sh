set -e

if [ -z ${FIPS} ]; then
    FIPS=false
fi

if [ -z ${AWS_LC} ]; then
    AWS_LC=false
fi

git submodule update --init --recursive
mkdir build_device
cd build_device
cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/../Toolchain-iOS.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_BITCODE=NO \
    -DIOS_PLATFORM=OS64 \
    -DFIPS=${FIPS} \
    -DAWS_LC=${AWS_LC} \
    -DIOS_DEPLOYMENT_TARGET=11.0 \
    -DOSSL_SUPPORT_UNAME="${OSSL_SUPPORT_UNAME}" \
    -DOSSL_SUPPORT_PASS="${OSSL_SUPPORT_PASS}" \
    -DOSSL_FIPS_URL="${OSSL_FIPS_URL}" \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_device ../
make
make install

cd ..

if [ "$(uname -m)" == "x86_64" ]; then
    SIM_ARCH=SIMULATOR64
else
    SIM_ARCH=SIMULATORARM64
fi

mkdir build_sim
cd build_sim
cmake -DCMAKE_TOOLCHAIN_FILE=$(pwd)/../Toolchain-iOS.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_BITCODE=NO \
    -DIOS_PLATFORM=${SIM_ARCH} \
    -DIOS_DEPLOYMENT_TARGET=11.0 \
    -DFIPS=${FIPS} \
    -DAWS_LC=${AWS_LC} \
    -DOSSL_SUPPORT_UNAME="${OSSL_SUPPORT_UNAME}" \
    -DOSSL_SUPPORT_PASS="${OSSL_SUPPORT_PASS}" \
    -DOSSL_FIPS_URL="${OSSL_FIPS_URL}" \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_sim ../
make 
make install
cd ..
mkdir -p output_fat/lib
mkdir -p output_fat/include
cp -R output_device/include output_fat
rm -rf output_fat/include/wickrcrypto
xcodebuild -create-xcframework -library output_device/lib/libprotobuf-c.a -library output_sim/lib/libprotobuf-c.a -output output_fat/lib/libprotobuf-c.xcframework
xcodebuild -create-xcframework -library output_device/lib/libcrypto.* -library output_sim/lib/libcrypto.* -output output_fat/lib/libcrypto.xcframework
xcodebuild -create-xcframework -library output_device/lib/libscrypt.a -library output_sim/lib/libscrypt.a -output output_fat/lib/libscrypt.xcframework
xcodebuild -create-xcframework -library output_device/lib/libbcrypt.a -library output_sim/lib/libbcrypt.a -output output_fat/lib/libbcrypt.xcframework

if [ ${FIPS} == true ] && [ ${AWS_LC} == false ]; then
    mkdir -p output_fat/bin
    cp build_device/third-party/openssl/1.0.2-fips/fips_output/iOS/incore_macho output_fat/bin/incore_macho
fi
