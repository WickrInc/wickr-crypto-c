FROM node:10-stretch-slim

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt-get update && apt-get -qq -y install curl libssl-dev git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.1 && ./autogen.sh && ./configure && make -j$(nproc --all) && make install

# CMake Upgrade 

RUN echo "fc77324c4f820a09052a7785549b8035ff8d3461ded5bbd80d252ae7d1cd3aa5 cmake-3.17.2.tar.gz" > cmake-3.17.2-sha256.txt
 
RUN curl -fLs https://github.com/Kitware/CMake/releases/download/v3.17.2/cmake-3.17.2.tar.gz --output cmake-3.17.2.tar.gz \
    && sha256sum -c cmake-3.17.2-sha256.txt \
    && tar -xzf cmake-3.17.2.tar.gz && cd cmake-3.17.2 \
    && ./bootstrap && make && make -j$(nproc --all) install

# Cleanup

RUN rm -rf swig cmake-3.17.2.tar.gz cmake-3.17.2 cmake-3.17.2-sha256.txt

RUN node -v
RUN npm -v
