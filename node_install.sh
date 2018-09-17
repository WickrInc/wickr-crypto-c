mkdir -p node/build
cd node/build
cmake -DBUILD_NODE=ON -DCMAKE_INSTALL_LIBDIR='lib' -DCMAKE_POSITION_INDEPENDENT_CODE=true -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../ ../../ 
make
make install

cd ..
