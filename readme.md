# wickr-crypto-c

## About
**wickr-crypto-c** is an implementation of the Wickr Secure Messaging Protocol in C, which provides a platform for secure communications on **Wickr Professional**. 

**Please Note**

This crypto lib is released for public review for educational, academic, and code audit purposes only (*this is not an open source license, more on license [here](LICENSE)). We strongly believe in the value of the open source movement and are looking forward to contributing to it with this and other future projects including under the GNU license. 

## Goals
Starting with this crypto lib, Wickr is opening its source code to its customers, partners, and the larger community—here is why:

* **Transparency:** It is important for us to share with Wickr Professional customers how the Wickr crypto is designed and why in a way that is easy to review

* **Security:** While Wickr is not a new tool for peer-to-peer encrypted ephemeral messaging, this protocol represents a new generation crypto in Wickr products. We are confident that the GitHub community will have ideas and constructive suggestions on how we can further evolve our protocol to make it stronger against emerging attacks (and, of course, fix a bug or two)

* **Team:** The core crypto team has long been a strong internal advocate for opening the source code, and they have finally prevailed ☺. Joking aside, we believe it is a good time in Wickr’s development as a company to share the core crypto with the public in addition to the regular external security audits that all Wickr products undergo

## Features

A faithful implementation of the Wickr protocol enables confidentiality of message content in transit and in storage. It powers the following capabilities:
 
* End-to-End Encryption – Message encryption keys are available only within Wickr clients and are not disclosed to network attackers or Wickr server operators;  
* Perfect Forward Secrecy – Old message content is not compromised if the long-term key of a user or device is compromised. Backward secrecy is also provided against passive adversaries.  

### [Crypto Engine] (src/crypto/crypto_engine.h)

A struct that represents a set of cryptographic functions that the library can utilize. The goal of its design is expose security primitives in an organized and generic way. This allows for the protocol implementation to not be bound to a single dependency such as OpenSSL. It is also designed to be easy to use, and to provide a high level interface that enforces best practices. 

#### [OpenSSL Crypto Suite] (src/crypto/openssl_suite.h)

The current default implementation of crypto engine is based primarily off the EVP interface from OpenSSL 1.0.2

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

### [Protocol] (src/crypto/protocol.h)

Low level implementation of the encoding and decoding of encrypted message packets

### [Context] (src/crypto/wickr_ctx.h)

High level interface for managing an endpoint that can send and receive encrypted message packets. This is the way the front end client apps integrate with the crypto library.

#### Features

* Randomly generated endpoint with new keys
* Secure import/export of key material encrypted with a random recovery key
* Secure import/export of recovery keys with scrypt
* Generation of signed messaging key pairs
* Message packet encoding / decoding

# Steps to build and test

There are makefiles included in the repository for each of the target operating systems:
* makefile.osx to build the macOS targets
* makefile.win32 to build the Windows 32bit targets
* makefile.linux to build the Linux targets
* makefile.android to build the Android targets

Each of the makefiles will contain the following targets:
* release: used to build the release version
* debug: used to build the debug version
* clean: used to remove the build directories and files
* test.release: used to run the unit test program from the release build
* test.debug: used to run the unit test program from the debug build

Some of the makefiles contain the _install_ target which is used to copy the built files to a target directory. This target directory is configurable.

All of the makefiles have an option to run unit tests against the crypto library, except for the Android makefile.

The following subsections will describe the build process for each of the target operating systems.

## macOS

### macOS Build Instructions
The makefile.osx make file contains an option to copy the built libraries and include files to a target directory.  You will need to modify the INSTALL_PREFIX value in the makefile.osx file to identify where you want to files to be copied to. The files will be copied at the end of the build.

To build the release version do the following:

```
make -f makefile.osx
```

or
```
make -f makefile.osx release
```

To build the debug version do the following:

```
make -f makefile.osx debug
```

To clean up the build directory and files do the following:

```
make -f makefile.osx clean
```

To run the included unit tests, you will need to specify whether to run the debug or release version.  To run the release version do the following:

```
make -f makefile.osx test.release
```

To run the debug version do the following:

```
make -f makefile.osx test.debug
```

## Windows

### Windows Requirements
* You will need to have an installation of NASM (http://www.nasm.us/doc/nasmdoc1.html)
* Microsoft Visual Studio version 2013 is the current version that is used, but this can be easily changed to use another version if desired. Change the makefile.win32 make file to use a different version.

### Windows Build Instructions
The makefile.win32 make file contains an option to copy the built libraries and include files to a target directory.  You will need to modify the INSTALL_PREFIX value in the makefile.win32 file to identify where you want to files to be copied to. The files will be copied at the end of the build.

To build the release version do the following:

```
make -f makefile.win32
```

or
```
make -f makefile.win32 release
```

To build the debug version do the following:

```
make -f makefile.win32 debug
```

To clean up the build directory and files do the following:

```
make -f makefile.win32 clean
```

To run the included unit tests, you will need to specify whether to run the debug or release version.  To run the release version do the following:

```
make -f makefile.win32 test.release
```

To run the debug version do the following:

```
make -f makefile.win32 test.debug
```

## Linux

### Linux Requirements
* OpenSSL libraries must be installed.

### Linux Build Instructions
Linux does not have a _test.release_ and _test.debug_ target in the makefile.linux.  Only the _test_ target is supported, it will run the unit test binary associated with the last build done (release or debug).

The makefile.linux make file contains an option to copy the built libraries and include files to a target directory.  You will need to modify the INSTALL_PREFIX value in the makefile.linux file to identify where you want to files to be copied to.

To build the release version do the following:

```
make -f makefile.linux
```

or
```
make -f makefile.linux release
```

To build the debug version do the following:

```
make -f makefile.linux debug
```


To clean up the build directory and files do the following:

```
make -f makefile.linux clean
```

To run the included unit tests do the following:

```
make -f makefile.linux test
```

To copy the build library files and any associated include files to the INSTALL_PREFIX location do the following:
```
make -f makefile.linux install
```

## Android
The current version does not contain unit testing code that works in an Android environment.

Currently, the makefile.android make file is setup to build the armeabi-va7, armeabi and x86 API versions.  If you want to build other API's then modify the makefile.android file appropriately.

### Android Requirements
In order to build Android you will need to have a version of the Android NDK on you build system.  We have been testing with version r13 of the Android NDK.

### Android Build Instructions
Currently the Android build will only build the release version.

There are several values that you will need to modify before using the makefile.android file.
* The location of the Android NDK
* The Android API level you are targeting
* The installation directory to copy include and lib files to (optional)

The default location of the NDK is defined in the makefile.android file.  You will need to modify the ANDROID_NDK value in the makefile.android file to point to the location of where you have installed the NDK. 

The default Android API level is defined in the makefile.android file.  You will need to modify the ANDROID_NATIVE_API_LEVEL value in the makefile.android file to identify the Android API level you intend to target.

The makefile.android make file contains an option to copy the build lib and include files to a target directory.  You will need to modify the INSTALL_PREFIX value in the makefile.android file to identify where you want to files to be copied to.

To Build the release version do the following:

```
make -f makefile.android
```

or

```
make -f makefile.android release
```

To clean up the build directory and files do the following:

```
make -f makefile.android clean
```

To copy the build library files and any associated include files to the INSTALL_PREFIX location do the following:
```
make -f makefile.android install
```
# Legal

## License

Copyright © 2012-2017 Wickr Inc.  All rights reserved.This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details, please see the LICENSE.

THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM. 

## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, use, and re-export of encryption software, to see if this is permitted. See http://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

