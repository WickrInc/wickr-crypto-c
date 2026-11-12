FROM tleavy/android-sdk-ndk:api33ndk28

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt -qq update 
RUN apt -qq -y install curl git build-essential ninja-build swig autoconf automake bison libpcre3-dev software-properties-common > /dev/null
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
RUN apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"
RUN apt update && apt install -qq -y cmake

# AWS-LC's FIPS tools need Go 1.16+, newer than the distro package; install a pinned official release
ARG GO_VERSION=1.22.12
ARG GO_SHA256=4fa4f869b0f7fc6bb1eb2660e74657fbf04cdd290b5aef905585c86051b34d43
RUN curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz

ENV PATH /usr/local/go/bin:$PATH
RUN go env -w GOPROXY=direct
