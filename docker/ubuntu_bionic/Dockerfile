FROM ubuntu:18.04

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt-get -qq update && apt-get -qq -y install curl
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash - 
RUN apt-get -qq -y install nodejs curl git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/yegorich/swig.git && cd swig && git checkout 0ea6a3bdbf3184d230bf17d2c17704dbc2ec7aac && ./autogen.sh && ./configure && make && make install

RUN node -v
RUN npm -v
