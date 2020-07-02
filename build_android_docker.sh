#!/bin/bash

if [ -z ${FIPS} ]; then
    DISTRO=android
    BUILD_COMMAND="./build_android_fat.sh $*"
else
    DISTRO=android-fips
    BUILD_COMMAND="FIPS=true ./build_android_fat.sh $*"
fi

echo $BUILD_COMMAND

docker build -t crypto-${DISTRO} -f docker/${DISTRO}/Dockerfile .
docker run \
    -e ARTIFACTORY_URL=${ARTIFACTORY_URL} \
    -e ARTIFACTORY_USER=${ARTIFACTORY_USER} \
    -e ARTIFACTORY_PASS=${ARTIFACTORY_PASS} \
    -e OSSL_SUPPORT_UNAME=${OSSL_SUPPORT_UNAME} \
    -e OSSL_SUPPORT_PASS=${OSSL_SUPPORT_PASS} \
    --name crypto-${DISTRO}-instance crypto-${DISTRO} \
    /bin/sh -c "${BUILD_COMMAND}"

exit $?
