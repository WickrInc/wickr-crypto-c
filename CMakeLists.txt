cmake_minimum_required(VERSION 3.1.0)

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.10")
set(CMAKE_C_STANDARD 99)

project(WickrCryptoC)

if(IOS)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -miphoneos-version-min=9.0")
endif()

add_subdirectory(third-party) 

if(NOT DEPS_ONLY)
    add_subdirectory(src)
endif()

if(NOT IOS AND NOT ANDROID)
    enable_testing()
    add_subdirectory(test)
endif()
