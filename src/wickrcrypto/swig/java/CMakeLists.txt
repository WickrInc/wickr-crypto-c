# Setup Java JNI SWIG wrapper
find_package(Java REQUIRED)
include(UseJava)

if (NOT ANDROID)
    include(FindJNI)
else ()
    include(AndroidFindJNI)
endif ()

set(PACKAGE_NAME com.wickr.crypto)
set(ENTRY_POINT com/wickr/crypto)
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/${ENTRY_POINT})

# Build JNI code with SWIG   
include_directories(${JNI_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set(CMAKE_SWIG_FLAGS -package ${PACKAGE_NAME} ${CMAKE_SWIG_FLAGS})

# Configure the swig target for java
if (FIPS)
    set(_ORIGINAL_C_COMPILER ${CMAKE_C_COMPILER})
    set(CMAKE_C_COMPILER ${OPENSSL_FIPSLD_COMPILER} CACHE LOCAL "" FORCE)
endif ()

setup_swig_library("java" "")

# Build JAR File

set(JAVA_SOURCES 
    ${CMAKE_SWIG_OUTDIR}/Cipher.java 
    ${CMAKE_SWIG_OUTDIR}/CipherID.java 
    ${CMAKE_SWIG_OUTDIR}/CipherKey.java
    ${CMAKE_SWIG_OUTDIR}/CipherResult.java
    ${CMAKE_SWIG_OUTDIR}/Context.java
    ${CMAKE_SWIG_OUTDIR}/ContextDecodeResult.java
    ${CMAKE_SWIG_OUTDIR}/ContextEncodeResult.java
    ${CMAKE_SWIG_OUTDIR}/ContextGenResult.java
    ${CMAKE_SWIG_OUTDIR}/ContextParseResult.java
    ${CMAKE_SWIG_OUTDIR}/CryptoEngine.java
    ${CMAKE_SWIG_OUTDIR}/CurveID.java 
    ${CMAKE_SWIG_OUTDIR}/DecodeError.java 
    ${CMAKE_SWIG_OUTDIR}/DeviceInfo.java
    ${CMAKE_SWIG_OUTDIR}/Digest.java
    ${CMAKE_SWIG_OUTDIR}/DigestID.java
    ${CMAKE_SWIG_OUTDIR}/DigestType.java
    ${CMAKE_SWIG_OUTDIR}/ECCurve.java
    ${CMAKE_SWIG_OUTDIR}/ECDHCipherContext.java
    ${CMAKE_SWIG_OUTDIR}/ECDSAResult.java
    ${CMAKE_SWIG_OUTDIR}/ECKey.java
    ${CMAKE_SWIG_OUTDIR}/EphemeralInfo.java 
    ${CMAKE_SWIG_OUTDIR}/EphemeralKeypair.java
    ${CMAKE_SWIG_OUTDIR}/Fingerprint.java 
    ${CMAKE_SWIG_OUTDIR}/FingerprintOutputType.java
    ${CMAKE_SWIG_OUTDIR}/FingerprintType.java
    ${CMAKE_SWIG_OUTDIR}/Identity.java
    ${CMAKE_SWIG_OUTDIR}/IdentityChain.java
    ${CMAKE_SWIG_OUTDIR}/IdentityChainStatus.java
    ${CMAKE_SWIG_OUTDIR}/IdentityType.java
    ${CMAKE_SWIG_OUTDIR}/KDFAlgo.java
    ${CMAKE_SWIG_OUTDIR}/KDFAlgoID.java
    ${CMAKE_SWIG_OUTDIR}/KDFID.java
    ${CMAKE_SWIG_OUTDIR}/KDFMeta.java
    ${CMAKE_SWIG_OUTDIR}/KDFResult.java 
    ${CMAKE_SWIG_OUTDIR}/KeyExchange.java 
    ${CMAKE_SWIG_OUTDIR}/KeyExchangeSet.java
    ${CMAKE_SWIG_OUTDIR}/Node.java
    ${CMAKE_SWIG_OUTDIR}/Packet.java
    ${CMAKE_SWIG_OUTDIR}/PacketMeta.java
    ${CMAKE_SWIG_OUTDIR}/PacketSignatureStatus.java
    ${CMAKE_SWIG_OUTDIR}/ParseResult.java
    ${CMAKE_SWIG_OUTDIR}/Payload.java
    ${CMAKE_SWIG_OUTDIR}/RootKeys.java
    ${CMAKE_SWIG_OUTDIR}/StorageKeys.java
    ${CMAKE_SWIG_OUTDIR}/WickrArray.java
    ${CMAKE_SWIG_OUTDIR}/WickrCrypto.java
    ${CMAKE_SWIG_OUTDIR}/WickrCryptoConstants.java
    ${CMAKE_SWIG_OUTDIR}/WickrCryptoJNI.java
)

add_jar(wickrcryptojava
    SOURCES ${JAVA_SOURCES}
    VERSION "${VERSION_STRING}"
    ENTRY_POINT ${ENTRY_POINT}
)

get_target_property(_jarFile wickrcryptojava JAR_FILE)

add_dependencies(wickrcryptojava wickrcryptoswig)

if (ANDROID)
    set(ANDROID_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/android)
    install(FILES ${JAVA_SOURCES} DESTINATION ${ANDROID_INSTALL_PATH}/src/main/java)
    install(FILES $<TARGET_FILE:wickrcryptoswig> DESTINATION ${ANDROID_INSTALL_PATH}/src/main/jniLibs/${CMAKE_ANDROID_ARCH_ABI})
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/build.gradle DESTINATION ${ANDROID_INSTALL_PATH})

    if (FIPS)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/settings.gradle "rootProject.name = \"wickrcrypto-fips\"\ngradle.ext.versionNumber = \"${VERSION_STRING}\"")
    else () 
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/settings.gradle "rootProject.name = \"wickrcrypto\"\ngradle.ext.versionNumber = \"${VERSION_STRING}\"")
    endif ()

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/settings.gradle DESTINATION ${ANDROID_INSTALL_PATH})
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/gradlew DESTINATION ${ANDROID_INSTALL_PATH})
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/gradle DESTINATION ${ANDROID_INSTALL_PATH})
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/AndroidManifest.xml DESTINATION ${ANDROID_INSTALL_PATH}/src/main)
else ()
    install(FILES ${JAVA_SOURCES} DESTINATION ${CMAKE_INSTALL_PREFIX}/java)
    install(FILES $<TARGET_FILE:wickrcryptoswig> DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ${_jarFile} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if (BUILD_TESTS)

    set(JAVA_TEST_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/junit-4.12.jar:${CMAKE_CURRENT_SOURCE_DIR}/hamcrest-core-1.3.jar)
    set(JAVA_CLASS_PATH .:${_jarFile}:${JAVA_TEST_INCLUDES})

    file(GLOB TestSources ${CMAKE_CURRENT_SOURCE_DIR}/${ENTRY_POINT}/tests/*.java) 
    
    add_custom_command(
        TARGET wickrcryptojava
        POST_BUILD
        COMMAND javac -d ${CMAKE_CURRENT_BINARY_DIR} -cp ${JAVA_CLASS_PATH} ${TestSources}
    )

    add_test(NAME wickrcryptojavatests 
        COMMAND ${Java_JAVA_EXECUTABLE} -Djava.library.path=${CMAKE_CURRENT_BINARY_DIR} -cp ${JAVA_CLASS_PATH} ${ENTRY_POINT}/tests/WickrRunner
    )
    
endif ()