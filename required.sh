#!/bin/sh
# pre-requirements needed for various platforms
# can either specify platform as arg1, or autodetect.

# for macos we assume macports by default

uname="$1"
if test -z "$uname" ; then
	uname=`uname` ; fi
case "$uname" in
darwin|Darwin|macx|macosx|macos|macports)
	sudo port install automake autoconf libtool pkgconfig
	;;
esac
