FROM ubuntu:18.04

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION 10.16.0

RUN apt -qq update 
RUN apt -qq -y install curl git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.0 && ./autogen.sh && ./configure && make && make install
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
