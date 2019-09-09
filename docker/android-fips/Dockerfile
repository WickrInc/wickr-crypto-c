FROM tleavy/android-sdk-ndk:api28ndk20

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt -qq update 
RUN apt -qq -y install curl git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.0 && ./autogen.sh && ./configure && make -j8 && make install

# FIPS can only build with Android NDK r15 and lower
RUN wget -q https://dl.google.com/android/repository/android-ndk-r15c-linux-x86_64.zip
RUN unzip -q android-ndk-r15c-linux-x86_64.zip -d /usr/opt/android && rm android-ndk-r15c-linux-x86_64.zip

ENV ANDROID_NDK_HOME ${ANDROID_HOME}/android-ndk-r15c
