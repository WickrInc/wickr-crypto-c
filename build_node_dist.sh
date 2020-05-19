for DISTRO in debian ubuntu_bionic centos7 alpine
do
    docker build --quiet -t crypto-${DISTRO} -f docker/${DISTRO}/Dockerfile .
    echo "Building distribution package for ${DISTRO}"
    docker run \
        -e node_pre_gyp_accessKeyId=${node_pre_gyp_accessKeyId} \
        -e node_pre_gyp_secretAccessKey=${node_pre_gyp_secretAccessKey} \
        --name crypto-${DISTRO}-instance -it crypto-${DISTRO} \
        /bin/sh -c "npm install --build-from-source --unsafe-perm && npm test && ./node_modules/node-pre-gyp/bin/node-pre-gyp --target_platform='${DISTRO}' package publish"
    if [ "$?" != "0" ]
    then
        exit $?
    fi
done
