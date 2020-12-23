add_subdirectory(crypt_blowfish)
add_subdirectory(libscrypt)
add_subdirectory(openssl)

# Protobuf

set(PC_SOURCES protobuf-c/protobuf-c/protobuf-c.c protobuf-c/protobuf-c/protobuf-c.h)

add_library(protobuf-c ${PC_SOURCES})

install(TARGETS protobuf-c EXPORT ProtobufCConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT ProtobufCConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

install(FILES protobuf-c/protobuf-c/protobuf-c.h DESTINATION include/protobuf-c)

export(TARGETS protobuf-c FILE ProtobufCConfig.cmake)

if (ENABLE_PQ)

    # Kyber 1024 Reference

    set(KYBER_REF kyber/kyber/ref)

    set(KYBER_SRCS 
        ${KYBER_REF}/kex.c 
        ${KYBER_REF}/kem.c
        ${KYBER_REF}/kem.h
        ${KYBER_REF}/params.h
        ${KYBER_REF}/indcpa.c 
        ${KYBER_REF}/polyvec.c 
        ${KYBER_REF}/poly.c 
        ${KYBER_REF}/ntt.c 
        ${KYBER_REF}/cbd.c 
        ${KYBER_REF}/reduce.c 
        ${KYBER_REF}/verify.c
        ${KYBER_REF}/sha256.c
        ${KYBER_REF}/sha512.c
        ${KYBER_REF}/symmetric-aes.c
        ${KYBER_REF}/randombytes.c
        ${KYBER_REF}/aes256ctr.c)

    set(KYBER_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/kyber/ref_header ${CMAKE_CURRENT_SOURCE_DIR}/kyber/ref_header/kyber CACHE INTERNAL "")

    add_library(kyber ${KYBER_SRCS})
    target_compile_definitions(kyber PUBLIC KYBER_K=4 KYBER_90S)

    install(TARGETS kyber EXPORT KyberConfig
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})
        
    install(EXPORT KyberConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

    install(FILES ${KYBER_REF}/kem.h ${KYBER_REF}/params.h DESTINATION include/kyber)

    export(TARGETS kyber FILE KyberConfig.cmake)

endif ()
