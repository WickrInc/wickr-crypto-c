docker build -t crypto-ubuntu -f docker/ubuntu-18.04/Dockerfile .
docker run \
    -e node_pre_gyp_accessKeyId=${node_pre_gyp_accessKeyId} \
    -e node_pre_gyp_secretAccessKey=${node_pre_gyp_secretAccessKey} \
    --name crypto-ubuntu-instance -it crypto-ubuntu \
    /bin/sh -c "npm install --unsafe-perm && npm test && ./node_modules/node-pre-gyp/bin/node-pre-gyp --target_platform='ubuntu_xenial' package publish"
