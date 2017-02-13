# Bootstrap support for building required dependencies automatically

cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_BUILD_TYPE Release)
set(PORTS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}")
set(PORTS_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}")
set(ENV{MACOSX_DEPLOYMENT_TARGET} "10.10")

include(ExternalProject)

if(WIN32)
    if(PORTS_ARCH MATCHES "x86_64")
        ExternalProject_Add(wickr-cspec
          PREFIX            "${PORTS_PREFIX}"
          GIT_REPOSITORY    git://github.com/arnaudbrejeon/cspec.git
          GIT_TAG           master
          CONFIGURE_COMMAND ""
          BUILD_COMMAND     ""
          INSTALL_COMMAND   ""
          TEST_COMMAND      ""
          BUILD_IN_SOURCE   1
        )
    else()
        ExternalProject_Add(wickr-cspec
          PREFIX            "${PORTS_PREFIX}"
          GIT_REPOSITORY    git://github.com/arnaudbrejeon/cspec.git
          GIT_TAG           master
          CONFIGURE_COMMAND ""
          BUILD_COMMAND     ""
          INSTALL_COMMAND   ""
          TEST_COMMAND      ""
          BUILD_IN_SOURCE   1
        )
    endif()
endif()

# Many Unix platforms have openssl as a default system library, Apple doesnt.

if(APPLE)
    ExternalProject_Add(wickr-cspec
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    git://github.com/arnaudbrejeon/cspec.git
      GIT_TAG           master
      SOURCE_DIR	"${PORTS_PREFIX}/cspec"
      CONFIGURE_COMMAND ""
      BUILD_COMMAND     "autogen.sh"
      INSTALL_COMMAND   ""
      TEST_COMMAND      ""
      BUILD_IN_SOURCE   1
    )
endif()
 
