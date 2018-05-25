mkdir build_node
cd build_node
cmake -DBUILD_NODE=ON -DCMAKE_POSITION_INDEPENDENT_CODE=true -DCMAKE_BUILD_TYPE=Release ../
make