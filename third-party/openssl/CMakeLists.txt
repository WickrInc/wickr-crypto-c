option(FIPS "Build OpenSSL in fips mode" OFF)
option(OPENSSL_102 "Use OpenSSL 1.0.2 instead of OpenSSL 1.1.1" OFF)

if (BUILD_NODE AND (FIPS OR BUILD_OPENSSL))
    message(WARNING "Node exports all of the openssl symbols, we are forced to use their versions")
endif ()

# FIPS is only supported on OPENSSL 1.0.2
if (FIPS)
    if (NOT AWS_LC)
        set(OPENSSL_102 ON)
    endif ()
endif ()

# When building in FIPS mode, building OpenSSL is required
if (OPENSSL_102 AND NOT BUILD_OPENSSL)
    message(WARNING "When building with -DFIPS=true or -DOPENSSL_102=true building OpenSSL is required, setting BUILD_OPENSSL=true")
    set(BUILD_OPENSSL true)
endif ()

if (NOT BUILD_OPENSSL)

    if (BUILD_NODE)
        include(FindNode)
        nodejs_init()
        message(STATUS "Using NodeJS OpenSSL: ${NODEJS_INCLUDE_DIRS}")
        set(OPENSSL_INCLUDE_DIR "${NODEJS_INCLUDE_DIRS}" CACHE INTERNAL "OpenSSL NodeJS Headers")
    else ()
        include(FindOpenSSL)

        if (NOT OPENSSL_FOUND OR OPENSSL_INCLUDE_DIR STREQUAL "OPENSSL_INCLUDE_DIR-NOTFOUND")
            if (OPENSSL_AUTO_BUILD)
                set(BUILD_OPENSSL TRUE)
            else ()
                Message(FATAL_ERROR "OpenSSL was not found")
            endif ()
        endif ()
    endif ()
endif ()

if (OPENSSL_102)
    add_subdirectory(1.0.2-fips)
elseif (AWS_LC)
    add_subdirectory(aws-lc)
else ()
    add_subdirectory(1.1.1)
endif ()

execute_process (
    COMMAND bash -c "cat ${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h | grep \"OPENSSL_VERSION_TEXT\""
    OUTPUT_VARIABLE OPENSSL_VERSION
)

Message(STATUS "Using OpenSSL: ${OPENSSL_ROOT_DIR}")
Message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
Message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
Message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
Message(STATUS "OpenSSL libcrypto: ${OPENSSL_CRYPTO_LIBRARY}")

if (BUILD_OPENSSL)

    install(DIRECTORY ${OPENSSL_INCLUDE_DIR}/openssl DESTINATION include)
    install(FILES ${OPENSSL_CRYPTO_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ${OPENSSL_SSL_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})

    if (OPENSSL_CRYPTO_SHARED)
        install(FILES ${OPENSSL_CRYPTO_SHARED} DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif ()

    if (OPENSSL_SSL_SHARED)
        install(FILES ${OPENSSL_SSL_SHARED} DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif ()

endif ()