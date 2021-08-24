FROM node:14-alpine

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apk update && apk upgrade
RUN apk add git cmake make g++ pcre-dev bison autoconf automake 
RUN git clone https://github.com/yegorich/swig.git && cd swig && git checkout 0ea6a3bdbf3184d230bf17d2c17704dbc2ec7aac && ./autogen.sh && ./configure && make && make install

RUN node -v
RUN npm -v

