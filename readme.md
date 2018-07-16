# wickr-crypto-c

[![Build Status](https://travis-ci.org/WickrInc/wickr-crypto-c.svg?branch=master)](https://travis-ci.org/WickrInc/wickr-crypto-c)
[![Build status](https://ci.appveyor.com/api/projects/status/jb36tviaypjch87a/branch/master?svg=true)](https://ci.appveyor.com/project/tomleavy/wickr-crypto-c-vsd9i/branch/master)

## About
**wickr-crypto-c** is an implementation of the Wickr Secure Messaging Protocol in C, which provides a platform for secure communications across all Wickr products. 

A white paper describing details of the protocol and its security model can be found [here](https://www.wickr.com/security). A markdown version of the white paper can also be found in the wiki. 

**Please Note**

This crypto lib is released for public review for educational, academic, and code audit purposes only (*this is not an open source license, more on license [here](LICENSE)). We strongly believe in the value of the open source movement and are looking forward to collaborating with the community on this and other future projects, including under the GNU license. 

## Issue Reporting

Please keep the issue tracker of this repo limited to code level bugs found in the implementation of the protocol as described in the white paper. Pull requests are always welcome! 

Any questions regarding the protocol itself (i.e: crypto design ideas, suggestions,  high-level conceptual critique) can be be directed at github@wickr.com. 

For all other security issues, please contact Wickr’s bug bounty program [here](https://wickr.com/about-us/blog/2014/01/15/calling-all-hackers-wickr-s-bug-bounty-begins).

## Goals
Starting with this crypto lib, Wickr is opening its source code to its customers, partners, and the larger community—here is why:

* **Transparency:** It is important for us to share with Wickr Professional customers how the Wickr crypto is designed in a way that is easy to review

* **Security:** While Wickr is not a new tool for peer-to-peer encrypted ephemeral messaging, this protocol represents a new generation crypto in Wickr products. We are confident that the GitHub community will have ideas and constructive suggestions on how we can further evolve our protocol to make it stronger against emerging attacks (and, of course, fix a bug or two)

* **Team:** The core crypto team has long been a strong internal advocate for opening the source code, and they have finally prevailed ☺. Joking aside, we believe it is a good time in Wickr’s development as a company to share the core crypto with the public in addition to the regular external security audits that all Wickr products undergo

## Features

A faithful implementation of the Wickr protocol enables confidentiality of message content in transit and in storage. It powers the following capabilities:
 
* End-to-End Encryption – Message encryption keys are available only within Wickr clients and are not disclosed to network attackers or Wickr server operators;  
* Perfect Forward Secrecy – Old message content is not compromised if the long-term key of a user or device is compromised. Backward secrecy is also provided against passive adversaries.  

### [Crypto Engine](src/crypto/crypto_engine.h)

A struct that represents a set of cryptographic functions that the library can utilize. The goal of its design is expose security primitives in an organized and generic way. This allows for the protocol implementation to not be bound to a single dependency such as OpenSSL. It is also designed to be easy to use, and to provide a high level interface that enforces best practices. 

#### [OpenSSL Crypto Suite](src/crypto/openssl_suite.h)

The current default implementation of crypto engine is based primarily off the EVP interface from OpenSSL 1.1.0

##### Supported Algorithms

* AES 256 GCM
* AES 256 CTR
* SHA256
* SHA384
* SHA512
* ECDH (NIST P521 Curve)
* ECDSA (NIST P521 Curve)
* HKDF
* HMAC
* SCRYPT
* BCRYPT

### [Protocol](src/crypto/protocol.h)

Low level implementation of the encoding and decoding of encrypted message packets

### [Context](src/crypto/wickr_ctx.h)

High level interface for managing an endpoint that can send and receive encrypted message packets. This is the way the front end client apps integrate with the crypto library.

#### Features

* Randomly generated endpoint with new keys
* Secure import/export of key material encrypted with a random recovery key
* Secure import/export of recovery keys with scrypt
* Generation of signed messaging key pairs
* Message packet encoding / decoding

### [Stream Cipher](src/crypto/stream_cipher.h)

A state machine to help with the encryption of continuous streams of data. This is used for encoding / decoding data within a live voice / video stream between users on a 1:1 or conference call. It is seeded with a key that was negotiated prior by the messaging protocol. Each stream of data within a particular call has its own stream_cipher object to hold it's state.

#### Features

* Understanding of position within a sequence of protected data, to assist with key rotation done via symmetric ratcheting
* Generation of IV's using a sequence number and a private random seed to prevent collisions
* Support for authenticating additional information during serialization using AES-GCM + AAD
* Rotation of key material and key rotation seed at a predetermined interval (defaults to 512 packets)

# Steps to build and test

The library is built with CMake on all platforms. Currently iOS, Android, Windows, macOS, and Linux are supported. See platform specific instructions and CMake options below for more information

## macOS

### macOS Requirements

- CMake 3.1 or higher
- xcode 9.0
- xcode command line tools
- OpenSSL >= 1.0.2 development package from homebrew (optional)

### macOS CMake Configuration

The macOS build can be configured follows:

```
mkdir build
cd build
cmake -DBUILD_OPENSSL=true -DCMAKE_INSTALL_PREFIX=USER_INSTALL_LOCATION ../
```

If a development version of OpenSSL => 1.0.2 is on the system, the BUILD_OPENSSL option can be eliminated in favor of OPENSSL_ROOT_DIR

## Windows

### Windows Requirements

- CMake 3.1 or higher
- You will need to have an installation of NASM (http://www.nasm.us/doc/nasmdoc1.html)
- Microsoft Visual Studio version 2015 is the current CMake Generator that is officially supported, although other windows CMake generators may also work

### Windows CMake Configuration

The windows build can be configured using the MSVC generator as follows

```
mkdir build
cd build
cmake -DBUILD_OPENSSL=true -DCMAKE_INSTALL_PREFIX=USER_INSTALL_LOCATION -G "Visual Studio 14 2015" ..
```

### Building, Installing, and Testing (Windows)

The windows build can't be generated with the standard `make` command documented below. Instead it relies on the Visual Studio commands directly as follows:

```
msbuild WickrCryptoC.sln /p:Configuration=Release
```

To run tests call the following from the build directory

```
ctest
```

To install the library to the configured install prefix

```
msbuild INSTALL.vcxproj /p:Configuration=Release
```

## Linux

### Linux Requirements

- CMake 3.1 or higher
- Clang
- OpenSSL => 1.0.2 (Optional)

### Linux CMake Configuration

The linux build can be configured using the standard CMake flow with a few options

```
mkdir build
cd build
cmake -DBUILD_OPENSSL=true \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_INSTALL_PREFIX=USER_INSTALL_LOCATION ../
```

If a development version of OpenSSL => 1.0.2 is on the system, the BUILD_OPENSSL option can be eliminated

## Android

Currently, the CMake project has been tested on armeabi-v7a, armeabi and x86 ABIs. Running tests for Android is currently not directly supported by CMake, although the test target can be compiled and uploaded to a device via ADB manually

### Android Requirements

- CMake 3.9 or higher
- Android NDK (r14b is recomended)

### Android CMake Configuration

The default Android API level is 18 as defined in the Toolchain-Android.cmake file in the root directory. Modifying this is currently not recomended

To configure CMake for building the Android NDK target you can do the following:

```
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../Toolchain-Android.cmake \
-DCMAKE_ANDROID_NDK=USER_NDK_LOCATION \
-DBUILD_OPENSSL=true \
-DCMAKE_ANDROID_ARCH_ABI=OUTPUT_ARCH_AB \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_INSTALL_PREFIX=USER_INSTALL_LOCATION ../
```

## iOS

A provided toolchain can support simulator and device builds for iOS > 9.0 as fat libraries. x86 + x86_64 fat libraries are generated for the simulator and armv7, armv7s, and arm64 fat libraries are created for the device

### iOS Requirements

- CMake 3.1 or higher
- XCode 8.0 or higher
- XCode command line tools

### iOS CMake Configuration

To configure CMake for building the iOS SDK target you can do the following:

```
cmake -DCMAKE_TOOLCHAIN_FILE=../Toolchain-iOS.cmake \
-DBUILD_OPENSSL=true \
-DCMAKE_BUILD_TYPE=Release \
-DIOS_PLATFORM=OS|SIMULATOR \
-DIOS_DEPLOYMENT_TARGET=9.0 \
-DCMAKE_INSTALL_PREFIX=USER_INSTALL_LOCATION ../
```

## CMake Options

| CMake Option | Description | Target | 
| ------------ | ----------- | ------ |
| BUILD_OPENSSL | Tells CMake to build OpenSSL 1.1.0 as part of the build process | All |
| OPENSSL_AUTO_BUILD | Tells CMake to build OpenSSL if it fails to automatically find it in the target system. Overridden by BUILD_OPENSSL. TRUE by default on macOS, iOS, Android and Windows, FALSE by default on other systems | All |
| OPENSSL_ROOT_DIR | Tells CMake to look for prebuilt OpenSSL development files at a specified location | All |
| FIPS | Tells CMake to build OpenSSL in FIPS mode. This will force BUILD_OPENSSL to true | All |
| CMAKE_BUILD_TYPE | Release or Debug build | All |
| CMAKE_INSTALL_PREFIX | The location to install headers and built libraries when `make install` is called | All |
| CMAKE_TOOLCHAIN_FILE | Tells CMake to target the Android NDK cross compile toolchain | Android / iOS |
| CMAKE_ANDROID_ARCH_ABI | The ABI to target for this build. Supported values are armeabi, armeabi-v7a, x86 | Android |
| CMAKE_ANDROID_NDK | The location of the root directory of an NDK installation | Android |
| IOS_PLATFORM | Set to OS for armv7,armv7s,arm64 builds or SIMULATOR for x86,x86_64 builds | iOS |
| IOS_DEPLOYMENT_TARGET | The minimum target for the iOS build (9.0+ Recomended) | iOS |

## Building, Installing, and Testing

__Note:__ For windows builds see the windows section

To build the library
```
make
```

To install the library to the configured install prefix
```
make install
``` 

To run the bundled test target (macOS, Windows, Linux)

```
make test
```

# Legal

## License

Copyright © 2012-2017 Wickr Inc.  All rights reserved.

This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details, please see the LICENSE.

THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM. 

## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, use, and re-export of encryption software, to see if this is permitted. See http://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.
