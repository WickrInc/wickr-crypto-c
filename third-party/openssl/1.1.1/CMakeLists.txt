macro(build_openssl)

    include(ExternalProject)
    include(ProcessorCount)
    ProcessorCount(N)

    if (NOT N EQUAL 0)
        set(MAKE_OPS "-j${N}")
    endif ()

    set(OSSL_VERSION "1.1.1a")
    set(OSSL_HASH "fc20130f8b7cbd2fb918b2f14e2f429e109c31ddd0fb38fc5d71d9ffed3f9f41")
    set(OSSL_URL "https://www.openssl.org/source/openssl-${OSSL_VERSION}.tar.gz")
    set(OSSL_OPTIONS no-ssl2 no-ssl3 no-comp enable-ec_nistp_64_gcc_128 --prefix=${CMAKE_CURRENT_BINARY_DIR})

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
            set(OSSL_BUILD make ${MAKE_OPS})
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
        set(OSSL_BUILD ${ANDROID_ENV} make)
        set(OSSL_INSTALL ${ANDROID_ENV} make install_sw)
    elseif (WIN32)
        if(CMAKE_GENERATOR MATCHES "(Win64)")
            set(OSSL_CONFIGURE perl Configure VC-WIN64 ${OSSL_OPTIONS})
        else()
            string(REPLACE "enable-ec_nistp_64_gcc_128" "" WIN32_OSSL_OPTIONS "${OSSL_OPTIONS}")
            set(OSSL_CONFIGURE perl Configure VC-WIN32 ${WIN32_OSSL_OPTIONS})
        endif()

        set(OSSL_BUILD nmake)
        set(OSSL_INSTALL nmake install_sw)
    elseif (UNIX)
        set(OSSL_CONFIGURE ./config ${OSSL_OPTIONS})
        set(OSSL_BUILD make ${MAKE_OPS})
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

    if(APPLE)
        if (IOS)
            set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")
        else ()
            set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.dylib" CACHE INTERNAL "")
            set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.1.1.dylib" CACHE INTERNAL "")
        endif ()
    elseif(WIN32)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.lib" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/bin/libcrypto-1_1.dll" CACHE INTERNAL "")
    elseif(ANDROID)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")
    elseif(UNIX)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so.1.1" CACHE INTERNAL "")
    endif()

endmacro()

# if the BUILD_OPENSSL flag supplied by the user run the build
if (BUILD_OPENSSL)
    build_openssl()
endif ()
