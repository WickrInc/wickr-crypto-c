option(FIPS "Build AWS_LC in fips mode" OFF)

if (SYSTEM_OPENSSL)
    include(FindOpenSSL)

    if (NOT OPENSSL_FOUND OR OPENSSL_INCLUDE_DIR STREQUAL "OPENSSL_INCLUDE_DIR-NOTFOUND")
        Message(FATAL_ERROR "OpenSSL was not found")
    endif ()

    message("Using System OpenSSL")

    if (FIPS)
        message(
            WARNING
            "FIPS mode enabled with system openssl. This may cause instability if the system library is not FIPS capable"
        )
    endif ()
else ()
    add_subdirectory(aws-lc)
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

install(DIRECTORY ${OPENSSL_INCLUDE_DIR}/openssl DESTINATION include)
install(FILES ${OPENSSL_CRYPTO_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${OPENSSL_SSL_LIBRARY} DESTINATION ${CMAKE_INSTALL_LIBDIR})

if (OPENSSL_CRYPTO_SHARED)
    install(FILES ${OPENSSL_CRYPTO_SHARED} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if (OPENSSL_SSL_SHARED)
    install(FILES ${OPENSSL_SSL_SHARED} DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()
