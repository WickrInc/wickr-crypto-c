include(ExternalProject)

macro(setup_android_env)
    if(${CMAKE_ANDROID_ARCH} MATCHES "arm")
        set(_ANDROID_EABI "_ANDROID_EABI=arm-linux-androideabi-${CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION}")
    else()
        set(_ANDROID_EABI "_ANDROID_EABI=x86-${CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION}")
    endif()
    set(_ANDROID_ARCH "_ANDROID_ARCH=arch-${CMAKE_ANDROID_ARCH}")
    set(ANDROID_NDK_ROOT "ANDROID_NDK_ROOT=${CMAKE_ANDROID_NDK}")
    set(_ANDROID_API "_ANDROID_API=android-${CMAKE_SYSTEM_VERSION}")
    set(_FIPS_SIG_PATH "FIPS=${_FIPS_SIG_PATH}")
    set(ANDROID_ENV ${_ANDROID_EABI} ${_ANDROID_ARCH} ${ANDROID_NDK_ROOT} ${_ANDROID_API} ${_FIPS_SIG_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/android/setenv-android.sh)
endmacro ()

macro(build_fips_module)

    set(FIPS_VERSION "2.0.16")
    set(FIPS_HASH "a3cd13d0521d22dd939063d3b4a0d4ce24494374b91408a05bdaca8b681c63d4")
    set(FIPS_URL "https://www.openssl.org/source/openssl-fips-${FIPS_VERSION}.tar.gz")
    set(FIPS_PATH ${CMAKE_CURRENT_BINARY_DIR})
    set(FIPS_CONFIGURE ./config --prefix=${FIPS_PATH})
    set(FIPS_BUILD make)
    set(FIPS_INSTALL make install)

    if (APPLE)
        if (IOS)
            string(REPLACE ";" " " ARCHS "${IOS_ARCH}")
            set(FIPS_CONFIGURE echo "Building OpenSSL for ${IOS_ARCH}")
            set(FIPS_BUILD SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}/ios TARGETDIR=${CMAKE_CURRENT_BINARY_DIR} IOS_MIN_SDK_VERSION=${IOS_DEPLOYMENT_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/ios/build-fips-loop-archs.sh "${ARCHS}")
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
        set(FIPS_BUILD ms\\do_fips.bat)
        set(FIPS_INSTALL echo No Install Step)
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

    set(OSSL_VERSION "1.0.2o")
    set(OSSL_HASH "ec3f5c9714ba0fd45cb4e087301eb1336c317e0d20b575a125050470e8089e4d")
    set(OSSL_URL "https://www.openssl.org/source/openssl-${OSSL_VERSION}.tar.gz")

    if (FIPS)
        set(FIPS_OPTIONS fips --with-fipsdir=${FIPS_PATH} --with-fipslibdir=${FIPS_PATH}/lib/)
    endif ()

    set(OSSL_OPTIONS ${FIPS_OPTIONS} shared no-ssl2 no-ssl3 no-comp enable-ec_nistp_64_gcc_128 --openssldir=${CMAKE_CURRENT_BINARY_DIR})

    if (APPLE)
        if (IOS)
            string(REPLACE ";" " " ARCHS "${IOS_ARCH}")
            set(OSSL_CONFIGURE echo "Building OpenSSL for ${IOS_ARCH}")
            set(OSSL_IOS_OPTIONS "no-shared no-ssl2 no-ssl3 no-comp")
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
        set(ANDROID_OSSL_OPTIONS ${FIPS_OPTIONS} no-ssl2 no-ssl3 no-comp --openssldir=${CMAKE_CURRENT_BINARY_DIR})
        set(OSSL_CONFIGURE ${ANDROID_ENV} ./config fips ${ANDROID_OSSL_OPTIONS})
        set(OSSL_BUILD ${ANDROID_ENV} make depend && ${ANDROID_ENV} make)
        set(OSSL_INSTALL ${ANDROID_ENV} make install_sw)
    elseif (WIN32)
        set(OSSL_FIPS_DIR C:\\usr\\local\\ssl\\fips-2.0)
        if (FIPS)
            set(FIPS_OPTIONS fips --with-fipsdir=${OSSL_FIPS_DIR})
        endif ()
        if(CMAKE_GENERATOR MATCHES "(Win64)")
            set(OSSL_OPTIONS ${FIPS_OPTIONS} no-ssl2 no-ssl3 no-comp enable-ec_nistp_64_gcc_128 --openssldir=${CMAKE_CURRENT_BINARY_DIR})
            set(OSSL_CONFIGURE perl Configure VC-WIN64 ${OSSL_OPTIONS})
        else()
            set(OSSL_OPTIONS ${FIPS_OPTIONS} no-ssl2 no-ssl3 no-comp --openssldir=${CMAKE_CURRENT_BINARY_DIR})
            set(OSSL_CONFIGURE perl Configure VC-WIN32 ${OSSL_OPTIONS})
        endif()

        set(OSSL_BUILD ms\\do_nasm.bat)
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
        else ()
            set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.dylib" CACHE INTERNAL "")
            set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.1.0.0.dylib" CACHE INTERNAL "")
        endif ()
    elseif(WIN32)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libeay32.lib" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/bin/libeay32.dll" CACHE INTERNAL "")
    elseif(ANDROID)

        if (FIPS)
            file(WRITE ${FIPS_PATH}/bin/fipsldwrap "export FIPSLD_CC=${CMAKE_C_COMPILER}; export FIPS_SIG=${FIPS_PATH}/bin/incore; ${FIPS_PATH}/bin/fipsld $*")
            set(OPENSSL_FIPSLD_COMPILER "${FIPS_PATH}/bin/fipsldwrap" CACHE INTERNAL "")
        endif ()

        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.a" CACHE INTERNAL "")

        add_custom_command(
            TARGET openssl
            POST_BUILD
            COMMAND chmod +x ${OPENSSL_FIPSLD_COMPILER}
            USES_TERMINAL
        )
    elseif(UNIX)
        set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so" CACHE INTERNAL "")
        set(OPENSSL_CRYPTO_SHARED "${CMAKE_CURRENT_BINARY_DIR}/lib/libcrypto.so.1.0.0" CACHE INTERNAL "")
    endif()



endmacro()

if (BUILD_OPENSSL)
    # FIPS Setup
    if (FIPS)
        build_fips_module()
    endif ()

    # Build OpenSSL
    build_openssl()
endif ()



