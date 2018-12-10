
option(FIPS "Build OpenSSL in fips mode" OFF)
option(OPENSSL_102 "Use OpenSSL 1.0.2 instead of OpenSSL 1.1.1" OFF)

# FIPS is only supported on OPENSSL 1.0.2
if (FIPS)
    set(OPENSSL_102 ON)
endif ()

# When building in FIPS mode, building OpenSSL is required
if (OPENSSL_102 AND NOT BUILD_OPENSSL)
    message(WARNING "When building with -DFIPS=true or -DOPENSSL_102=true building OpenSSL is required, setting BUILD_OPENSSL=true")
    set(BUILD_OPENSSL true)
endif ()

if (NOT BUILD_OPENSSL)
    include(FindOpenSSL)

    if (NOT OPENSSL_FOUND OR OPENSSL_INCLUDE_DIR STREQUAL "OPENSSL_INCLUDE_DIR-NOTFOUND")
        if (OPENSSL_AUTO_BUILD)
            set(BUILD_OPENSSL TRUE)
        else ()
            Message(FATAL_ERROR "OpenSSL was not found")
        endif ()
    endif ()
endif ()

if (OPENSSL_102)
    add_subdirectory(1.0.2-fips)
else ()
    add_subdirectory(1.1.1)
endif ()

Message(STATUS "Using OpenSSL: ${OPENSSL_ROOT_DIR}")
Message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
Message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
Message(STATUS "OpenSSL libcrypto: ${OPENSSL_CRYPTO_LIBRARY}")

if (BUILD_OPENSSL)

    install(DIRECTORY ${OPENSSL_INCLUDE_DIR}/openssl DESTINATION include)
    install(FILES ${OPENSSL_CRYPTO_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})

    if (OPENSSL_CRYPTO_SHARED)
        install(FILES ${OPENSSL_CRYPTO_SHARED} DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif ()

endif ()
