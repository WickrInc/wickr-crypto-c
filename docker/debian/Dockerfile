FROM node:10-stretch-slim

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt-get update && apt-get -qq -y install curl git build-essential autoconf automake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.1 && ./autogen.sh && ./configure && make -j$(nproc --all) && make install

# CMake Upgrade 

RUN echo "f6c240f52e82cdc2000ba6ce517f176b3b6f0d948453a400ef92148bcd8a3040  cmake-3.17.2-Linux-x86_64.sh" > cmake-3.17.2-sha256.txt
 
RUN curl -fLs https://github.com/Kitware/CMake/releases/download/v3.17.2/cmake-3.17.2-Linux-x86_64.sh --output cmake-3.17.2-Linux-x86_64.sh \
    && sha256sum -c cmake-3.17.2-sha256.txt \
    && chmod +x cmake-3.17.2-Linux-x86_64.sh \
    && ./cmake-3.17.2-Linux-x86_64.sh --skip_license --prefix=/ --exclude-subdir

# Cleanup

RUN node -v
RUN npm -v
