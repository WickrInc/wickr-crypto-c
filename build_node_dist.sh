for DISTRO in centos8 debian alpine ubuntu_bionic ubuntu_focal
do
    docker build --quiet -t crypto-${DISTRO} -f docker/${DISTRO}/Dockerfile .
    echo "Building distribution package for ${DISTRO}"
    docker run \
        -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
        -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
        --name crypto-${DISTRO}-instance -it crypto-${DISTRO} \
        /bin/sh -c "npm install --build-from-source --unsafe-perm && npm test && ./node_modules/@mapbox/node-pre-gyp/bin/node-pre-gyp --target_platform='${DISTRO}' package publish"
    if [ "$?" != "0" ]
    then
        exit $?
    fi
done
