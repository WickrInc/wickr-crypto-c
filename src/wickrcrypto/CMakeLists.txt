set(THIRD_PARTY "${PROJECT_SOURCE_DIR}/third-party")

file(GLOB ProtobufSources ../protobuf/gen/*.c ../protobuf/gen/*.h)
file(GLOB Sources src/*.c include/wickrcrypto/*.h include/wickrcrypto/private/*.h) 

include_directories("include/wickrcrypto" "../protobuf/gen" "${THIRD_PARTY}/protobuf-c" "${THIRD_PARTY}/crypt_blowfish" "${THIRD_PARTY}/libscrypt" "${OPENSSL_INCLUDE_DIR}")

# Enable FIPS if needed
if (${FIPS})
    message(STATUS "Enabling FIPS")
    add_definitions(-DFIPS)
endif ()

# Zero all allocations before freeing them (off by default)
option(WICKR_SECURE_MEMORY "Zero wickrcrypto memory before freeing it" OFF)
if (WICKR_SECURE_MEMORY)
    message(STATUS "Enabling secure memory")
    add_definitions(-DWICKR_SECURE_MEMORY)

    # libsodium provides the guarded, page-locked allocator for secrets
    find_package(libsodium CONFIG QUIET)
    find_package(unofficial-sodium CONFIG QUIET)
    if (TARGET libsodium::libsodium)
        set(SODIUM_LIBRARIES libsodium::libsodium)
    elseif (TARGET unofficial-sodium::sodium)
        # vcpkg's package; its target adds SODIUM_STATIC for static builds
        set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    else ()
        find_path(SODIUM_INCLUDE_DIR sodium.h)
        find_library(SODIUM_LIBRARIES NAMES sodium libsodium)
        if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARIES)
            message(FATAL_ERROR "WICKR_SECURE_MEMORY needs libsodium")
        endif ()
        include_directories(${SODIUM_INCLUDE_DIR})
    endif ()
    message(STATUS "libsodium: ${SODIUM_LIBRARIES}")
endif ()

add_library(wickrcrypto ${Sources} ${ProtobufSources})

add_dependencies(wickrcrypto bcrypt scrypt protobuf-c)

if (BUILD_OPENSSL)
    add_dependencies(wickrcrypto openssl)
endif (BUILD_OPENSSL)

target_link_libraries(wickrcrypto bcrypt scrypt protobuf-c ${OPENSSL_CRYPTO_LIBRARY} ${SODIUM_LIBRARIES})

install(TARGETS wickrcrypto EXPORT WickrCryptoConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT WickrCryptoConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake)

file(GLOB Headers include/wickrcrypto/*.h)

install(FILES ${Headers} DESTINATION include/wickrcrypto)

export(TARGETS wickrcrypto FILE WickrCryptoConfig.cmake)

# SWIG OPTIONS

option(BUILD_JAVA "Build Java SWIG module" OFF)

if (BUILD_JAVA)
    add_subdirectory(swig)
endif ()
