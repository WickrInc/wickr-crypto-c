#!/bin/bash
# Cross-compile environment for Android on ARMv7 and x86
#
# Contents licensed under the terms of the OpenSSL license
# http://www.openssl.org/source/license.html
#
# See http://wiki.openssl.org/index.php/FIPS_Library_and_Android
#   and http://wiki.openssl.org/index.php/Android

#####################################################################

export PATH=${ANDROID_TOOLCHAIN}/bin:${PATH}

echo "PATH: ${PATH}"

echo "Going to run: $*"

$*
