FROM centos:centos8

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN yum -y update && yum -y install curl
RUN curl -sL https://rpm.nodesource.com/setup_14.x | bash - && yum -y update
RUN yum -y install epel-release
RUN yum -y groupinstall "Development Tools"
RUN yum -y install nodejs cmake3 bison make git autoconf automake pcre-devel
RUN git clone https://github.com/yegorich/swig.git && cd swig && git checkout 0ea6a3bdbf3184d230bf17d2c17704dbc2ec7aac && ./autogen.sh && ./configure && make && make install
RUN node -v
RUN npm -v

