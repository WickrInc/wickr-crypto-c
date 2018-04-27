cmake_minimum_required(VERSION 3.9.0)

set(CMAKE_C_STANDARD 99)

project(WickrCryptoC)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 8)
set(VERSION_PATCH 3)

if(NOT CMAKE_OSX_DEPLOYMENT_TARGET AND APPLE AND NOT IOS)
    set(CMAKE_OSX_DEPLOYMENT_TARGET 10.10)
endif()

set(OPENSSL_OSX_DEPLOYMENT_TARGET ${CMAKE_OSX_DEPLOYMENT_TARGET} CACHE INTERNAL "")

if(IOS_DEPLOYMENT_TARGET)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}")
endif()

add_subdirectory(third-party) 

option(DEPS_ONLY "only build dependencies" false)

if(NOT DEPS_ONLY)
    add_subdirectory(src)
endif()

option(BUILD_TESTS "build tests" false)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
