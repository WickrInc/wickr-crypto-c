mkdir -p node/build
cd node/build
cmake -DBUILD_NODE=ON -DCMAKE_POSITION_INDEPENDENT_CODE=true -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../ ../../ 
make
make install

cd ..

if [ ! -d lib ] && [ -d lib64 ]; then
    mkdir lib && cd lib
    ln -s ../lib64/wickrcrypto.node wickrcrypto.node
fi
