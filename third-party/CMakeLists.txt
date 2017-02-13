# Bootstrap support for building required dependencies automatically

cmake_minimum_required(VERSION 2.8.11)

# parallel builds...
set(NPROC 1)
if(APPLE)
    execute_process(COMMAND sysctl -n hw.ncpu OUTPUT_VARIABLE NPROC)
elseif(UNIX)
    execute_process(COMMAND nproc OUTPUT_VARIABLE NPROC)
endif()
string(REGEX REPLACE "\n$" "" NPROC "${NPROC}")

if (NOT APPLE AND NOT ANDROID AND UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_search_module(OPENSSL REQUIRED openssl)
    if( OPENSSL_FOUND )
        include_directories(${OPENSSL_INCLUDE_DIRS})
        message("Using OpenSSL ${OPENSSL_VERSION}")
        message("OpenSSL Root: ${OPENSSL_ROOT_DIR}")
        message("OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
        message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    else()
        message(STATUS "Cannot find OpenSSL package!")
    endif()
else()
    include(wickr-openssl.cmake)
endif()

add_subdirectory(bcrypt)
add_subdirectory(scrypt)
add_subdirectory(protobuf-c)

if (NOT APPLE AND NOT ANDROID AND UNIX)
else()
    add_dependencies(scrypt wickr-openssl)
endif()
