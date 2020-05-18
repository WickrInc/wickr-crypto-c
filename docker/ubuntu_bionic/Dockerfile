FROM ubuntu:18.04

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt-get -qq update && apt-get -qq -y install curl
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - 
RUN apt-get -qq -y install nodejs curl git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.1 && ./autogen.sh && ./configure && make && make install

RUN node -v
RUN npm -v
