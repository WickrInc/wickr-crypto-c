#!/bin/bash

DISTRO=android
BUILD_COMMAND="./build_android_fat.sh $*"
echo $BUILD_COMMAND

docker build -t crypto-${DISTRO} -f docker/${DISTRO}/Dockerfile .
docker run \
    -e ARTIFACTORY_URL=${ARTIFACTORY_URL} \
    -e ARTIFACTORY_USER=${ARTIFACTORY_USER} \
    -e ARTIFACTORY_PASS=${ARTIFACTORY_PASS} \
    --name crypto-${DISTRO}-instance -it crypto-${DISTRO} \
    /bin/sh -c "${BUILD_COMMAND}"

exit $?
