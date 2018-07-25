
if (FIPS)
    add_subdirectory(1.0.2-fips)
else ()
    add_subdirectory(1.1.0)
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