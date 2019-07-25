FROM centos:centos7

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION 10.16.0

RUN yum -y update
RUN yum -y install epel-release
RUN yum -y install cmake3 bison gcc gcc-c++ make git autoconf automake
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.0 && ./autogen.sh && ./configure && make && make install
RUN ln -s /usr/bin/cmake3 /usr/bin/cmake
RUN mkdir -p $NVM_DIR && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash

RUN . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default \
    && ls $NVM_DIR

ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

RUN node -v
RUN npm -v

