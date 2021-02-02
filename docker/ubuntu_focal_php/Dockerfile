FROM ubuntu:20.04

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:ondrej/php
RUN apt-get -qq update

RUN apt-get install -y --allow-downgrades --allow-remove-essential --allow-change-held-packages \
                php7.2-bcmath php7.2-bz2 php7.2-cli php7.2-common php7.2-curl \
                php7.2-dev php7.2-fpm php7.2-gd php7.2-gmp php7.2-imap php7.2-intl \
                php7.2-json php7.2-ldap php7.2-mbstring php7.2-mysql \
                php7.2-odbc php7.2-opcache php7.2-pgsql php7.2-phpdbg php7.2-pspell \
                php7.2-readline php7.2-recode php7.2-soap php7.2-sqlite3 \
                php7.2-tidy php7.2-xml php7.2-xmlrpc php7.2-xsl php7.2-zip

RUN apt-get -y -qq install phpunit curl git build-essential autoconf automake cmake swig bison libpcre3-dev > /dev/null