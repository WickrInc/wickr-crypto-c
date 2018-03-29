if (BUILD_OPENSSL)

    include(ExternalProject)

    set(OSSL_VERSION "1.0.2n")
    set(OSSL_HASH "370babb75f278c39e0c50e8c4e7493bc0f18db6867478341a832a982fd15a8fe")
    set(OSSL_URL "https://www.openssl.org/source/openssl-${OSSL_VERSION}.tar.gz")
    set(OSSL_OPTIONS shared no-ssl2 no-ssl3 no-comp enable-ec_nistp_64_gcc_128 --openssldir=${CMAKE_CURRENT_BINARY_DIR})

    if (APPLE)
        if (IOS)
            string(REPLACE ";" " " ARCHS "${IOS_ARCH}")
            set(OSSL_CONFIGURE echo "Building OpenSSL for ${IOS_ARCH}")
            set(OSSL_IOS_OPTIONS "no-ssl2 no-ssl3 no-comp")
            set(OSSL_BUILD  export CONFIG_OPTIONS=${OSSL_IOS_OPTIONS} && SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}/ios CONFIG_ENABLE_EC_NISTP_64_GCC_128=true TARGETDIR=${CMAKE_CURRENT_BINARY_DIR} IOS_MIN_SDK_VERSION=${IOS_DEPLOYMENT_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/ios/build-loop-archs.sh "${ARCHS}")
            set(OSSL_INSTALL "")
        else ()
            set(OSSL_CC "/usr/bin/clang -mmacosx-version-min=${OPENSSL_OSX_DEPLOYMENT_TARGET}")
            set(OSSL_CONFIGURE export CC=${OSSL_CC} && ./Configure darwin64-x86_64-cc ${OSSL_OPTIONS})
            set(OSSL_BUILD make depend && make)
            set(OSSL_INSTALL make install_sw)
        endif ()
    elseif (ANDROID)
        string(REPLACE "enable-ec_nistp_64_gcc_128" "" ANDROID_OSSL_OPTIONS "${OSSL_OPTIONS}")
        if(${CMAKE_ANDROID_ARCH} MATCHES "arm")
            set(_ANDROID_EABI "_ANDROID_EABI=arm-linux-androideabi-${CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION}")
        else()
            set(_ANDROID_EABI "_ANDROID_EABI=x86-${CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION}")
        endif()
        set(_ANDROID_ARCH "_ANDROID_ARCH=arch-${CMAKE_ANDROID_ARCH}")
        set(ANDROID_NDK_ROOT "ANDROID_NDK_ROOT=${CMAKE_ANDROID_NDK}")
        set(_ANDROID_API "_ANDROID_API=android-${CMAKE_SYSTEM_VERSION}")
        set(ANDROID_ENV ${_ANDROID_EABI} ${_ANDROID_ARCH} ${ANDROID_NDK_ROOT} ${_ANDROID_API} ${CMAKE_CURRENT_SOURCE_DIR}/android/setenv-android.sh)
        set(OSSL_CONFIGURE ${ANDROID_ENV} ./config ${ANDROID_OSSL_OPTIONS})
        set(OSSL_BUILD ${ANDROID_ENV} make depend && ${ANDROID_ENV} make)
        set(OSSL_INSTALL ${ANDROID_ENV} make install_sw)
    elseif (WIN32)
        if(CMAKE_GENERATOR MATCHES "(Win64)")
            set(OSSL_CONFIGURE perl Configure VC-WIN64 enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-comp --prefix=${CMAKE_CURRENT_BINARY_DIR})
        else()
            set(OSSL_CONFIGURE perl Configure VC-WIN32 no-ssl2 no-ssl3 no-comp --prefix=${CMAKE_CURRENT_BINARY_DIR})
        endif()

        set(OSSL_BUILD ms\\do_nasm.bat)
        set(OSSL_INSTALL nmake -f ms\\nt.mak install)
    elseif (UNIX)
        set(OSSL_CONFIGURE ./config ${OSSL_OPTIONS})
        set(OSSL_BUILD make depend && make)
        set(OSSL_INSTALL make install_sw)
    endif ()

    ExternalProject_add(
        openssl
        URL ${OSSL_URL}
        URL_HASH SHA256=${OSSL_HASH}
        CONFIGURE_COMMAND ${OSSL_CONFIGURE}
        BUILD_COMMAND ${OSSL_BUILD}
        INSTALL_COMMAND ${OSSL_INSTALL}
        BUILD_IN_SOURCE 1)

    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_BINARY_DIR}" CACHE INTERNAL "")
    set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include" CACHE INTERNAL "")

    if(APPLE OR ANDROID)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")
    elseif(WIN32)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libeay32.lib" CACHE INTERNAL "")
    elseif(UNIX)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so" CACHE INTERNAL "")
    endif()

    install(FILES ${OPENSSL_INCLUDE_DIR}/openssl DESTINATION include)
    install(FILES ${OPENSSL_CRYPTO_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})

else (BUILD_OPENSSL)

    include(FindOpenSSL)

    if (!OPENSSL_FOUND)
        Message(FATAL_ERROR "OpenSSL was not found")
    endif (!OPENSSL_FOUND)

endif (BUILD_OPENSSL)

Message("Using OpenSSL: ${OPENSSL_ROOT_DIR}")
Message("OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
Message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
Message("OpenSSL libcrypto: ${OPENSSL_CRYPTO_LIBRARY}")
