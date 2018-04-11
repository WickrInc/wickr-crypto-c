cmake_minimum_required(VERSION 3.10.0)

set(OPENSSL_OSX_DEPLOYMENT_TARGET ${CMAKE_OSX_DEPLOYMENT_TARGET} CACHE INTERNAL "")
set(CMAKE_C_STANDARD 99)

project(WickrCryptoC)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 8)
set(VERSION_PATCH 2)

if(IOS)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}")
endif()

add_subdirectory(third-party) 

if(NOT DEPS_ONLY)
    add_subdirectory(src)
endif()

if(NOT IOS AND NOT ANDROID)
    enable_testing()
    add_subdirectory(test)
endif()
