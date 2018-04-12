git submodule update --init --recursive
mkdir build_device
cd build_device
cmake -DCMAKE_TOOLCHAIN_FILE=../Toolchain-iOS.cmake \
    -DBUILD_OPENSSL=true \
    -DCMAKE_BUILD_TYPE=Release \
    -DIOS_PLATFORM=OS \
    -DIOS_DEPLOYMENT_TARGET=9.0 \
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
    -DIOS_DEPLOYMENT_TARGET=9.0 \
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
