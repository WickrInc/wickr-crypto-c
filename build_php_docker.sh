docker build --quiet -t crypto-php-ubuntu-focal -f docker/ubuntu_focal_php/Dockerfile .

docker run \
    --name crypto-php-ubuntu-focal-instance -it crypto-php-ubuntu-focal \
    /bin/sh -c "mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_PHP=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTS=ON .. && make && ctest"
if [ "$?" != "0" ]
then
    exit $?
fi