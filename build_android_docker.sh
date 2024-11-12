#!/bin/bash

if [ -z ${FIPS} ]; then
    FIPS=false
fi

BUILD_COMMAND="FIPS=${FIPS} ./build_android_fat.sh $*"

echo "Building android using distro: $DISTRO and command $BUILD_COMMAND"

if [[ "$OSTYPE" == "darwin"* ]]; then
    BUILDX_COMMAND="buildx"
    PLATFORM_FLAG="--platform linux/amd64"
fi

docker ${BUILDX_COMMAND} build ${PLATFORM_FLAG} -t crypto-android -f docker/android/Dockerfile .

docker run ${PLATFORM_FLAG} \
    -e ARTIFACTORY_URL=${ARTIFACTORY_URL} \
    -e ARTIFACTORY_USER=${ARTIFACTORY_USER} \
    -e ARTIFACTORY_PASS=${ARTIFACTORY_PASS} \
    --name crypto-android-instance crypto-android \
    /bin/sh -c "${BUILD_COMMAND}"

exit $?
