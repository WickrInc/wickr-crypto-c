FROM node:10-alpine

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apk update && apk upgrade
RUN apk add git cmake make g++ pcre-dev bison autoconf automake 
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.1 && ./autogen.sh && ./configure && make -j4 && make install

RUN node -v
RUN npm -v

