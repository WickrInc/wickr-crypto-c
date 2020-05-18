FROM centos:centos7

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN yum -y update && yum -y install curl
RUN curl -sL https://rpm.nodesource.com/setup_10.x | bash - && yum -y update
RUN yum -y install epel-release
RUN yum -y install nodejs cmake3 bison gcc gcc-c++ make git autoconf automake pcre-devel
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.1 && ./autogen.sh && ./configure && make && make install
RUN ln -s /usr/bin/cmake3 /usr/bin/cmake

RUN node -v
RUN npm -v

