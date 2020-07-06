include(ExternalProject)

macro(setup_android_env)

    if(${ANDROID_ABI} MATCHES "arm64")
        set(OSSL_ANDROID_ARCH arm64)
        set(OSSL_EABI "aarch64-linux-android-4.9")
    elseif(${ANDROID_ABI} MATCHES "arm")
        set(OSSL_ANDROID_ARCH arm)
        set(OSSL_EABI "arm-linux-androideabi-4.9")
    elseif(${ANDROID_ABI} MATCHES "x86_64")
        set(OSSL_ANDROID_ARCH ${ANDROID_ABI})
        set(OSSL_EABI "${ANDROID_ABI}-4.9")
    elseif(${ANDROID_ABI} MATCHES "x86")
        set(OSSL_ANDROID_ARCH ${ANDROID_ABI})
        set(OSSL_EABI "${ANDROID_ABI}-4.9")
    endif()

    set(_ANDROID_ARCH "_ANDROID_ARCH=arch-${OSSL_ANDROID_ARCH}")
    set(ANDROID_NDK_ROOT "ANDROID_NDK_ROOT=${CMAKE_ANDROID_NDK}")
    set(_ANDROID_API "_ANDROID_API=android-${ANDROID_NATIVE_API_LEVEL}")
    set(_ANDROID_EABI "_ANDROID_EABI=${OSSL_EABI}")
    set(_FIPS_SIG_PATH "FIPS=${_FIPS_SIG_PATH}")
    set(ANDROID_ENV ${_ANDROID_EABI} ${_ANDROID_ARCH} ${ANDROID_NDK_ROOT} ${_ANDROID_API} ${_FIPS_SIG_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/android/setenv-android.sh)
endmacro ()

macro(build_fips_module)

    set(FIPS_VERSION "2.0.16")
    set(FIPS_HASH "a3cd13d0521d22dd939063d3b4a0d4ce24494374b91408a05bdaca8b681c63d4")
    set(FIPS_URL "https://www.openssl.org/source/openssl-fips-${FIPS_VERSION}.tar.gz")
    set(FIPS_PATH ${CMAKE_CURRENT_BINARY_DIR}/fips_output)
    set(FIPS_CONFIGURE ./config --prefix=${FIPS_PATH})
    if (FIPS_BUILD_TEST)
        set(FIPS_BUILD make && make build_tests && make build_algvs)
    else ()
        set(FIPS_BUILD make)
    endif ()
    set(FIPS_INSTALL make install)

    if (APPLE)
        if (IOS)
            string(REPLACE ";" " " ARCHS "${IOS_ARCH}")
            set(FIPS_CONFIGURE echo "Building OpenSSL for ${IOS_ARCH}")
            set(FIPS_BUILD SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}/ios TARGETDIR=${FIPS_PATH} IOS_MIN_SDK_VERSION=${IOS_DEPLOYMENT_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/ios/build-fips-loop-archs.sh "${ARCHS}")
            set(FIPS_INSTALL echo "Built FIPS Module for ${IOS_ARCH}")
        else ()
            set(FIPS_CC "/usr/bin/clang -mmacosx-version-min=${OPENSSL_OSX_DEPLOYMENT_TARGET}")
            set(FIPS_CONFIGURE export CC=${FIPS_CC} && chmod +x Configure && ./Configure darwin64-x86_64-cc --prefix=${FIPS_PATH})
        endif ()
    elseif (ANDROID)
        setup_android_env()
        set(FIPS_CONFIGURE ${ANDROID_ENV} ./config --prefix=${FIPS_PATH})
        set(FIPS_BUILD ${ANDROID_ENV} make)
        set(FIPS_INSTALL ${ANDROID_ENV} make install_sw && cp util/incore ${FIPS_PATH}/bin)
        set(_FIPS_SIG_PATH ${FIPS_PATH}/bin/incore)
    elseif (WIN32)
        set(FIPS_CONFIGURE mkdir tmp32dll)
        
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(FIPS_ARCH set PROCESSOR_ARCHITECTURE=AMD64)
        else ()
            set(FIPS_ARCH set PROCESSOR_ARCHITECTURE=x86)
        endif ()

        if (BUILD_FIPS_TESTS)
            set(FIPS_BUILD_TEST cd openssl_fips-prefix\\src\\openssl_fips && nmake -f ms\\ntdll.mak test)
        else ()
            set(FIPS_BUILD_TEST echo "Skipping FIPS test generation")
        endif ()

        set(FIPS_BUILD ${FIPS_ARCH} && ms\\do_fips.bat && ${FIPS_BUILD_TEST})

        set(FIPS_INSTALL echo "no install step")
    endif ()

    ExternalProject_add(
        openssl_fips
        URL ${FIPS_URL}
        URL_HASH SHA256=${FIPS_HASH}
        CONFIGURE_COMMAND ${FIPS_CONFIGURE}
        BUILD_COMMAND ${FIPS_BUILD}
        INSTALL_COMMAND ${FIPS_INSTALL}
        BUILD_IN_SOURCE 1)

endmacro()

macro(build_openssl)

    include(ProcessorCount)
    ProcessorCount(N)

    if (NOT N EQUAL 0)
        set(MAKE_OPS "-j${N}")
    endif ()

    set(OSSL_VERSION "1.0.2v")
    set(OSSL_HASH "17d1d6bf7956d1c263f908d10fe209a22b03fe6ea19367462baaee8923281a4f")
    set(OSSL_URL "https://github.openssl.org/openssl/wickr/archive/OpenSSL_1_0_2v.tar.gz")

    if (FIPS)
        set(FIPS_OPTIONS fips --with-fipsdir=${FIPS_PATH} --with-fipslibdir=${FIPS_PATH}/lib/)
    endif ()

    set(OSSL_OPTIONS ${FIPS_OPTIONS} shared no-ssl2 no-ssl3 no-comp no-dynamic-engine enable-ec_nistp_64_gcc_128 --openssldir=${CMAKE_CURRENT_BINARY_DIR})

    if (APPLE)
        if (IOS)
            string(REPLACE ";" " " ARCHS "${IOS_ARCH}")
            set(OSSL_CONFIGURE echo "Building OpenSSL for ${IOS_ARCH}")
            set(OSSL_IOS_OPTIONS "no-dynamic-engine no-shared no-ssl2 no-ssl3 no-comp")
            set(OSSL_BUILD  export CONFIG_OPTIONS=${OSSL_IOS_OPTIONS} && FIPSDIR=${FIPS_PATH} SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}/ios CONFIG_ENABLE_EC_NISTP_64_GCC_128=true TARGETDIR=${CMAKE_CURRENT_BINARY_DIR} IOS_MIN_SDK_VERSION=${IOS_DEPLOYMENT_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/ios/build-loop-archs.sh "${ARCHS}")
            set(OSSL_INSTALL "")
        else ()
            set(OSSL_SETUP_OSX ${CMAKE_CURRENT_SOURCE_DIR}/osx/setenv-osx.sh)
            set(OSSL_CC "/usr/bin/clang -mmacosx-version-min=${OPENSSL_OSX_DEPLOYMENT_TARGET}")
            set(OSSL_CONFIGURE export CC=${OSSL_CC} && ${OSSL_SETUP_OSX} ./config ${OSSL_OPTIONS})
            set(OSSL_BUILD ${OSSL_SETUP_OSX} make depend ${MAKE_OPS} && ${OSSL_SETUP_OSX} make ${MAKE_OPS})
            set(OSSL_INSTALL make install_sw)
        endif ()
    elseif (ANDROID)
        setup_android_env()
        if (FIPS)
            set(FIPS_OPTIONS fips --with-fipsdir=${FIPS_PATH})
        endif ()

        if (${ANDROID_ABI} STREQUAL "arm64-v8a")
            set(ANDROID_OSSL_OPTIONS ${FIPS_OPTIONS} no-dynamic-engine no-ssl2 enable-ec_nistp_64_gcc_128 no-ssl3 no-comp --openssldir=${CMAKE_CURRENT_BINARY_DIR})
        else ()
            set(ANDROID_OSSL_OPTIONS ${FIPS_OPTIONS} no-dynamic-engine no-ssl2 no-ssl3 no-comp --openssldir=${CMAKE_CURRENT_BINARY_DIR})
        endif ()
        
        set(OSSL_CONFIGURE ${ANDROID_ENV} ./config ${ANDROID_OSSL_OPTIONS})
        set(OSSL_BUILD ${ANDROID_ENV} make depend && ${ANDROID_ENV} make)
        set(OSSL_INSTALL ${ANDROID_ENV} make install_sw)
    elseif (WIN32)
        set(OSSL_FIPS_DIR C:\\usr\\local\\ssl\\fips-2.0)
        if (FIPS)
            set(FIPS_OPTIONS fips --with-fipsdir=${OSSL_FIPS_DIR})
        endif ()

        set(OSSL_OPTIONS ${FIPS_OPTIONS} no-dynamic-engine no-ssl2 no-ssl3 no-comp --prefix=${CMAKE_CURRENT_BINARY_DIR})
        set(OSSL_OPENSSLDIR "C:/Program Files/Common Files/wickr/ssl")

        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(OSSL_CONFIGURE perl Configure VC-WIN64A ${OSSL_OPTIONS} --openssldir=${OSSL_OPENSSLDIR})
            set(OSSL_BUILD ms\\do_win64a.bat)
        else()
            set(OSSL_CONFIGURE perl Configure VC-WIN32 ${OSSL_OPTIONS} --openssldir=${OSSL_OPENSSLDIR})
            set(OSSL_BUILD ms\\do_nasm.bat)
        endif()

        
        set(OSSL_INSTALL nmake -f ms\\ntdll.mak install)
    elseif (UNIX)
        set(OSSL_CONFIGURE ./config ${OSSL_OPTIONS})
        set(OSSL_BUILD make depend ${MAKE_OPS} && make ${MAKE_OPS})
        set(OSSL_INSTALL make install_sw)
    endif ()

    ExternalProject_add(
        openssl
        URL ${OSSL_URL}
        URL_HASH SHA256=${OSSL_HASH}
        CONFIGURE_COMMAND ${OSSL_CONFIGURE}
        BUILD_COMMAND ${OSSL_BUILD}
        INSTALL_COMMAND ${OSSL_INSTALL}
        HTTP_USERNAME ${OSSL_SUPPORT_UNAME}
        HTTP_PASSWORD ${OSSL_SUPPORT_PASS}
        BUILD_IN_SOURCE 1)

    # Add FIPS dependency
    if (FIPS)
        add_dependencies(openssl openssl_fips)
    endif ()

    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_BINARY_DIR}" CACHE INTERNAL "")
    set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include" CACHE INTERNAL "")

    if(APPLE)
        if (IOS)
            set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")
            set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.a" CACHE INTERNAL "")
        else ()
            set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.dylib" CACHE INTERNAL "")
            set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.dylib" CACHE INTERNAL "")
            set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.1.0.0.dylib" CACHE INTERNAL "")
            set(OPENSSL_SSL_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.1.0.0.dylib" CACHE INTERNAL "")
        endif ()
    elseif(WIN32)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libeay32.lib" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/bin/libeay32.dll" CACHE INTERNAL "")
        set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/ssleay32.lib" CACHE INTERNAL "")
        set(OPENSSL_SSL_SHARED "${CMAKE_CURRENT_BINARY_DIR}/bin/ssleay32.dll" CACHE INTERNAL "")
    elseif(ANDROID)

        if (FIPS)
            file(WRITE ${FIPS_PATH}/bin/fipsldwrap "export FIPSLD_CC=${CMAKE_C_COMPILER}; export FIPS_SIG=${FIPS_PATH}/bin/incore; ${FIPS_PATH}/bin/fipsld $*")
            set(OPENSSL_FIPSLD_COMPILER "${FIPS_PATH}/bin/fipsldwrap" CACHE INTERNAL "")
        endif ()

        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")
        set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.a" CACHE INTERNAL "")

        add_custom_command(
            TARGET openssl
            POST_BUILD
            COMMAND chmod +x ${OPENSSL_FIPSLD_COMPILER}
            USES_TERMINAL
        )
    elseif(UNIX)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so.1.0.0" CACHE INTERNAL "")
        set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.so" CACHE INTERNAL "")
        set(OPENSSL_SSL_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libssl.so.1.0.0" CACHE INTERNAL "")
    endif()



endmacro()

if (BUILD_OPENSSL)

    if (ANDROID)
        if (FIPS AND ${ANDROID_ABI} STREQUAL "x86_64")
            message(FATAL_ERROR "OpenSSL does not support FIPS in x86_64 for Android")
            set(FIPS false)
        endif ()
    endif ()

    # FIPS Setup
    if (FIPS)
        build_fips_module()
    endif ()

    # Build OpenSSL
    build_openssl()
endif ()



