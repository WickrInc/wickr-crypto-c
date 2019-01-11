cmake_minimum_required(VERSION 3.9.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

project(WickrCryptoC)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 11)
set(VERSION_PATCH 0)

set(VERSION_STRING ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH} CACHE INTERNAL "")

if(NOT CMAKE_OSX_DEPLOYMENT_TARGET AND APPLE AND NOT IOS)
    set(CMAKE_OSX_DEPLOYMENT_TARGET 10.10)
endif()

set(OPENSSL_OSX_DEPLOYMENT_TARGET ${CMAKE_OSX_DEPLOYMENT_TARGET} CACHE INTERNAL "")

if(IOS_DEPLOYMENT_TARGET)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}")
endif()

option(BUILD_TESTS "build tests" OFF)
option(BUILD_OPENSSL "Force building OpenSSL" OFF)

if (WIN32 OR APPLE OR ANDROID)
    set(OPENSSL_AUTO_BUILD_DEFAULT TRUE)
else ()
    set(OPENSSL_AUTO_BUILD_DEFAULT FALSE)
endif ()

option(OPENSSL_AUTO_BUILD "Automatically build OpenSSL if not found" ${OPENSSL_AUTO_BUILD_DEFAULT})

add_subdirectory(third-party) 

option(DEPS_ONLY "only build dependencies" OFF)

if(BUILD_TESTS)
    enable_testing()
endif()

if(NOT DEPS_ONLY)
    add_subdirectory(src)
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
