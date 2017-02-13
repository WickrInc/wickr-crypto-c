message("In crypto")

use_c99()

file(GLOB_RECURSE CryptoSources *.c)

file(GLOB_RECURSE CryptoHeaders *.h)
file(GLOB_RECURSE ProtoBufs *.proto)

add_library(wickr_crypto_lib STATIC ${CryptoSources} ${CryptoHeaders} ${ProtoBufs})

foreach(FILE ${CryptoSources} ${CryptoHeaders} ${ProtoBufs}) 
    # Get the directory of the source file
    if (CMAKE_VERSION VERSION_LESS "3.0")
        get_filename_component(PARENT_DIR "${FILE}" PATH)
    else()
        get_filename_component(PARENT_DIR "${FILE}" DIRECTORY)
    endif()

    # Remove common directory prefix to make the group
    string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}" "" GROUP "${PARENT_DIR}")

    # Make sure we are using windows slashes
    string(REPLACE "/" "\\" GROUP "${GROUP}")

    set(GROUP "${GROUP}")

    source_group("${GROUP}" FILES "${FILE}")

    if (${FILE} MATCHES "\\.h$")
        INSTALL(FILES ${FILE} DESTINATION "include/${GROUP}")
    endif()
endforeach()

link_directories(${CMAKE_BINARY_DIR}/third-party/lib)


if(WIN32)
    if(PORTS_ARCH MATCHES "x86_64")
        target_link_libraries(wickr_crypto_lib libeay64)
    else()
        target_link_libraries(wickr_crypto_lib libeay32)
    endif()
endif()

# Many Unix platforms have openssl as a default system library, Apple doesnt.

if(APPLE)
    target_link_libraries(wickr_crypto_lib crypto)
elseif (ANDROID)
    target_link_libraries(wickr_crypto_lib crypto)
    target_link_libraries(wickr_crypto_lib protobuf)
    target_link_libraries(wickr_crypto_lib protobuf-c)
    target_link_libraries(wickr_crypto_lib protobuf-lite)
    target_link_libraries(wickr_crypto_lib protoc)
elseif (UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC"  )
endif()

target_link_libraries(wickr_crypto_lib bcrypt)
target_link_libraries(wickr_crypto_lib scrypt)

# include the protobuf libraries

target_link_libraries(wickr_crypto_lib protobuf-c)

INSTALL(TARGETS wickr_crypto_lib DESTINATION "lib/${CMAKE_BUILD_TYPE}" CONFIGURATIONS Release Debug)
if (NOT APPLE AND NOT ANDROID AND UNIX)
else()
    INSTALL(DIRECTORY "${CMAKE_BINARY_DIR}/third-party/include/" DESTINATION "include")
endif()
