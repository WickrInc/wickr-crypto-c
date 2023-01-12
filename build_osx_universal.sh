set -e

make_universal () {
  lipo -create macos_x86_64/lib/$1 macos_arm64/lib/$1 -macos macos_universal/lib/$1 
}

build_library () {
  cd $1 

  cmake -DCMAKE_OSX_ARCHITECTURES=$1 -DAWS_LC=ON -DCMAKE_INSTALL_PREFIX=../macos_$1 ../.. 
  make
  make install 
 
  cd ..
}


mkdir build && cd build 
mkdir x86_64 && mkdir arm64

build_library x86_64
build_library arm64

mkdir -p macos_universal/lib

make_universal libcrypto.dylib
make_universal libssl.dylib
make_universal libscrypt.a
make_universal libwickrcrypto.a
make_universal libbcrypt.a
make_universal libprotobuf-c.a

cp -R macos_x86_64/include macos_universal



