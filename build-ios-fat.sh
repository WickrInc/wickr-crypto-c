if [ -z ${FIPS} ]; then
    FIPS=false
fi

git submodule update --init --recursive
mkdir build_device
cd build_device
cmake -DCMAKE_TOOLCHAIN_FILE=../Toolchain-iOS.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_BUILD_TYPE=Release \
    -DIOS_PLATFORM=OS \
    -DFIPS=${FIPS} \
    -DOSSL_SUPPORT_UNAME="${OSSL_SUPPORT_UNAME}" \
    -DOSSL_SUPPORT_PASS="${OSSL_SUPPORT_PASS}" \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_device ../
make
make install

cd ..
mkdir build_sim
cd build_sim
cmake -DCMAKE_TOOLCHAIN_FILE=../Toolchain-iOS.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_BUILD_TYPE=Release \
    -DIOS_PLATFORM=SIMULATOR \
    -DFIPS=${FIPS} \
    -DOSSL_SUPPORT_UNAME="${OSSL_SUPPORT_UNAME}" \
    -DOSSL_SUPPORT_PASS="${OSSL_SUPPORT_PASS}" \
    -DDEPS_ONLY=true \
    -DCMAKE_INSTALL_PREFIX=../output_sim ../
make
make install
cd ..
mkdir -p output_fat/lib
mkdir -p output_fat/include
cp -R output_device/include output_fat
rm -rf output_fat/include/wickrcrypto
lipo -create output_device/lib/libprotobuf-c.a output_sim/lib/libprotobuf-c.a -output output_fat/lib/libprotobuf-c.a
lipo -create output_device/lib/libcrypto.a output_sim/lib/libcrypto.a -output output_fat/lib/libcrypto.a 
lipo -create output_device/lib/libscrypt.a output_sim/lib/libscrypt.a -output output_fat/lib/libscrypt.a
lipo -create output_device/lib/libbcrypt.a output_sim/lib/libbcrypt.a -output output_fat/lib/libbcrypt.a

if [ ${FIPS} == true ]; then
    mkdir -p output_fat/bin
    cp build_device/third-party/openssl/1.0.2-fips/fips_output/iOS/incore_macho output_fat/bin/incore_macho
fi
