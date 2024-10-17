FROM tleavy/android-sdk-ndk:api33ndk27

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt -qq update 
RUN apt -qq -y install curl git build-essential ninja-build swig autoconf automake bison libpcre3-dev software-properties-common > /dev/null
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
RUN apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"
RUN add-apt-repository ppa:longsleep/golang-backports && apt update && apt install -qq -y cmake golang-go

ENV PATH $PATH:/usr/local/go/bin
RUN go env -w GOPROXY=direct
