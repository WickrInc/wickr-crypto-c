cmake_minimum_required(VERSION 2.8.11)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

message("CMAKE_BUILD_TYPE is ${CMAKE_BUILD_TYPE}")

if (NOT GIT_FOUND)
    find_package(Git REQUIRED)
endif()

if (NOT PKG_CONFIG_FOUND)
    find_package(PkgConfig REQUIRED)
endif()

macro(use_c99)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_C_FLAGS "--std=gnu99 ${CMAKE_C_FLAGS}")
    endif ()
  else ()
    set (CMAKE_C_STANDARD 99)
  endif ()
endmacro(use_c99)

use_c99()
 
project(Crypto)
 
set (Crypto_VERSION_MAJOR 0)
set (Crypto_VERSION_MINOR 1)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")

if (WIN32)
  set(CMAKE_LIBRARY_PATH_FLAG "LIBPATH:")

  set (CMAKE_C_FLAGS "-DWIN32_LEAN_AND_MEAN ${CMAKE_C_FLAGS}")
  set (CMAKE_CXX_FLAGS "-DWIN32_LEAN_AND_MEAN ${CMAKE_CXX_FLAGS}")
endif()

# install third party support
include_directories("${PROJECT_BINARY_DIR}/third-party/include")
link_directories("${PROJECT_BINARY_DIR}/third-party/lib")
add_subdirectory(third-party)
target_include_directories(scrypt PUBLIC "${PROJECT_BINARY_DIR}/third-party/include")


# add the scrypt include directory
include_directories("${PROJECT_SOURCE_DIR}/third-party/scrypt")
#ExternalProject_Get_Property(wickr-scrypt SOURCE_DIR)
#include_directories("${SOURCE_DIR}")

# add the bcrypt include directory
include_directories("${PROJECT_SOURCE_DIR}/third-party/bcrypt")

# add the protobuf-c include directory
include_directories("${PROJECT_SOURCE_DIR}/third-party/protobuf-c")

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/CryptoConfig.h.in"
  "${PROJECT_BINARY_DIR}/CryptoConfig.h"
  )

# add the binary tree to the search path for include files
# so that we will find CryptoConfig.h
include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
set(LIBRARIES wickr_crypto_lib)

enable_testing()

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" OR
    ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    set(warnings "-Wall -Wextra -Werror")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    set(warnings "/W4 /wd4512 /WX /EHsc")
        # Disabled Warnings:
        #   4512 "assignment operator could not be generated"
        #        This warning provides no useful information and will occur in
        #        well formed programs.
        #        <http://msdn.microsoft.com/en-us/library/hsyx7kbz.aspx>
endif()

add_subdirectory(src)

if (NOT APPLE AND NOT ANDROID AND UNIX)
    add_dependencies(wickr_crypto_lib scrypt)
else()
    add_dependencies(wickr_crypto_lib wickr-openssl)
endif()

if (NOT ANDROID)
    add_dependencies(crypto_test wickr_crypto_lib)
endif()

