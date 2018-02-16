set(THIRD_PARTY "${PROJECT_SOURCE_DIR}/third-party")

file(GLOB ProtobufSources ../protobuf/gen/*.c ../protobuf/gen/*.h)
file(GLOB Sources src/*.c include/wickrcrypto/*.h include/wickrcrypto/private/*.h) 

include_directories("include/wickrcrypto" "../protobuf/gen" "${THIRD_PARTY}/protobuf-c" "${THIRD_PARTY}/crypt_blowfish" "${THIRD_PARTY}/libscrypt" "${OPENSSL_INCLUDE_DIR}")

add_library(wickrcrypto ${Sources} ${ProtobufSources})

add_dependencies(wickrcrypto bcrypt scrypt protobuf-c)

if (BUILD_OPENSSL)
    add_dependencies(wickrcrypto openssl)
endif (BUILD_OPENSSL)

target_link_libraries(wickrcrypto bcrypt scrypt protobuf-c ${OPENSSL_CRYPTO_LIBRARY})

install(TARGETS wickrcrypto EXPORT WickrCryptoConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT WickrCryptoConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

file(GLOB Headers include/wickrcrypto/*.h)

install(FILES ${Headers} DESTINATION include/wickrcrypto)

export(TARGETS wickrcrypto FILE WickrCryptoConfig.cmake)
