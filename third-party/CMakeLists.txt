add_subdirectory(crypt_blowfish)
add_subdirectory(libscrypt)
add_subdirectory(openssl)

set(PC_SOURCES protobuf-c/protobuf-c/protobuf-c.c protobuf-c/protobuf-c/protobuf-c.h)

add_library(protobuf-c ${PC_SOURCES})

install(TARGETS protobuf-c EXPORT ProtobufCConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT ProtobufCConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

install(FILES protobuf-c/protobuf-c/protobuf-c.h DESTINATION include/protobuf-c)

export(TARGETS protobuf-c FILE ProtobufCConfig.cmake)
