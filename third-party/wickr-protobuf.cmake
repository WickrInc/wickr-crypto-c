# Bootstrap support for building required dependencies automatically

cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE Debug)
set(PORTS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}")
set(PORTS_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}")
set(ENV{MACOSX_DEPLOYMENT_TARGET} "10.10")

if (NOT PKG_CONFIG_FOUND)
    find_package(PkgConfig REQUIRED)
endif()

message("PKG_CONFIG = ${PKG_CONFIG}")
message("PKG_CONFIG_EXECUTABLE = ${PKG_CONFIG_EXECUTABLE}")
if (CMAKE_VERSION VERSION_LESS "3.0")
    get_filename_component(PKG_CONFIG_PATH "${PKG_CONFIG_EXECUTABLE}" PATH)
else()
    get_filename_component(PKG_CONFIG_PATH "${PKG_CONFIG_EXECUTABLE}" DIRECTORY)
endif()
message("PKG_CONFIG_PATH = ${PKG_CONFIG_PATH}")

include(ExternalProject)

if(ANDROID)
    message("wickr-protobuf.cmake: Building for ANDROID")
    message("wickr-protobuf.cmake: ANDROID_ABI = ${ANDROID_ABI}")
    
    # Protobuf is delivered with an autogen.sh that creates a configure.
    # This means you have to already have automake, autoconf, and libtool
    # installed before use.
    #    ExternalProject_Add(wickr-protobuf
    #      PREFIX            "${PORTS_PREFIX}"
    #  GIT_REPOSITORY    "git://github.com/google/protobuf"
    #  GIT_TAG           "v2.6.1"
    #  CONFIGURE_COMMAND "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-autogen.sh
    #  BUILD_COMMAND     "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-configure-android.sh ${PORTS_PREFIX} ${PORTS_SCRIPTS}/protoc ${ANDROID_ABI}
    #  INSTALL_COMMAND   "${PORTS_SCRIPTS}/setenv-android.sh" make -j ${NPROC} install
    #  BUILD_IN_SOURCE   1
    #)
    #ExternalProject_Add(wickr-protobuf-c
    #  PREFIX            "${PORTS_PREFIX}"
    #  GIT_REPOSITORY    "git://github.com/protobuf-c/protobuf-c"
    #  GIT_TAG           "v1.2.1"
    #  CONFIGURE_COMMAND "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-c-autogen.sh
    #  BUILD_COMMAND     "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-c-configure-android.sh ${PORTS_PREFIX} ${PORTS_SCRIPTS}/protoc ${ANDROID_ABI}
    #  INSTALL_COMMAND   "${PORTS_SCRIPTS}/setenv-android.sh" make -j ${NPROC} install
    #  BUILD_IN_SOURCE   1
    #)

    # Protobuf is delivered with an autogen.sh that creates a configure.
    # This means you have to already have automake, autoconf, and libtool
    # installed before use.
    ExternalProject_Add(wickr-protobuf
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/google/protobuf"
      GIT_TAG           "v2.6.1"
      CONFIGURE_COMMAND "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-autogen.sh
      BUILD_COMMAND     "${PORTS_SCRIPTS}/setenv-android.sh" ./configure --prefix=${PORTS_PREFIX}
      INSTALL_COMMAND   "${PORTS_SCRIPTS}/setenv-android.sh" make -j ${NPROC} install
      BUILD_IN_SOURCE   1
    )
    ExternalProject_Add(wickr-protobuf-c
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/protobuf-c/protobuf-c"
      GIT_TAG           "v1.2.1"
      CONFIGURE_COMMAND "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-c-autogen.sh
      BUILD_COMMAND     "${PORTS_SCRIPTS}/setenv-android.sh" ${PORTS_SCRIPTS}/protobuf-c-configure.sh
      INSTALL_COMMAND   "${PORTS_SCRIPTS}/setenv-android.sh" make -j ${NPROC} install
      BUILD_IN_SOURCE   1
    )

    add_dependencies(wickr-protobuf-c wickr-protobuf)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-c.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-lite.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotoc.a" DESTINATION lib)
elseif(UNIX)
    message("wickr-protobuf.cmake: Building for UNIX")

    # Protobuf is delivered with an autogen.sh that creates a configure.
    # This means you have to already have automake, autoconf, and libtool
    # installed before use.
    ExternalProject_Add(wickr-protobuf
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/google/protobuf"
      GIT_TAG           "v2.6.1"
      CONFIGURE_COMMAND PATH=$ENV{PATH}:${PKG_CONFIG_PATH} && ${PORTS_SCRIPTS}/protobuf-autogen.sh
      BUILD_COMMAND     PATH=$ENV{PATH}:${PKG_CONFIG_PATH} && ${PORTS_SCRIPTS}/protobuf-configure.sh ${PORTS_PREFIX}
      INSTALL_COMMAND   make -j ${NPROC} install
      BUILD_IN_SOURCE   1
    )
    ExternalProject_Add(wickr-protobuf-c
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/protobuf-c/protobuf-c"
      GIT_TAG           "v1.2.1"
      CONFIGURE_COMMAND PATH=$ENV{PATH}:${PKG_CONFIG_PATH} && ${PORTS_SCRIPTS}/protobuf-c-autogen.sh
      BUILD_COMMAND     PATH=$ENV{PATH}:${PKG_CONFIG_PATH} && ${PORTS_SCRIPTS}/protobuf-c-configure.sh
      INSTALL_COMMAND   make -j ${NPROC} install
      BUILD_IN_SOURCE   1
    )
#    if(APPLE)
#        ExternalProject_Add_Step(wickr-protobuf-c e1
#            COMMAND PATH=$ENV{PATH}:${PKG_CONFIG_PATH}
#            DEPENDEES Configure
#            DEPENDERS Build
#        )
#    endif()
    add_dependencies(wickr-protobuf-c wickr-protobuf)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-c.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-lite.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf.a" DESTINATION lib)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotoc.a" DESTINATION lib)
elseif(WIN32)
    message("wickr-protobuf.cmake: Building for WINDOWS")

    # Protobuf is delivered with an autogen.sh that creates a configure.
    # This means you have to already have automake, autoconf, and libtool
    # installed before use.
    ExternalProject_Add(wickr-protobuf
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/google/protobuf"
      GIT_TAG           "v2.6.1"
#      CONFIGURE_COMMAND pwd && ls -l vsprojects && "devenv .\\vsprojects\\protobuf.sln /Upgrade"
#      BUILD_COMMAND     pwd && ls -l && "msbuild .\\vsprojects\\protobuf.sln"
#      CONFIGURE_COMMAND ${PORTS_SCRIPTS}\\protobuf-autogen-win32.sh
      CONFIGURE_COMMAND pwd && rm -rf gtest && curl https://codeload.github.com/google/googletest/tar.gz/release-1.5.0 | tar xz && mv googletest-release-1.5.0 gtest && autogen.sh
      BUILD_COMMAND     ${PORTS_SCRIPTS}\\protobuf-configure-win32.sh ${PORTS_PREFIX}
      INSTALL_COMMAND   nmake INSTALLTOP=..\\.. install
      BUILD_IN_SOURCE   1
    )
    ExternalProject_Add(wickr-protobuf-c
      PREFIX            "${PORTS_PREFIX}"
      GIT_REPOSITORY    "git://github.com/protobuf-c/protobuf-c"
      GIT_TAG           "v1.2.1"
      CONFIGURE_COMMAND ${PORTS_SCRIPTS}/protobuf-c-autogen-win32.sh
      BUILD_COMMAND ${PORTS_SCRIPTS}/protobuf-c-configure-win32.sh
      INSTALL_COMMAND nmake INSTALLTOP=../.. install
      BUILD_IN_SOURCE   1
    )
    add_dependencies(wickr-protobuf-c wickr-protobuf)
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-c.lib" DESTINATION lib/${CMAKE_BUILD_TYPE})
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf-lite.lib" DESTINATION lib/${CMAKE_BUILD_TYPE})
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotobuf.lib" DESTINATION lib/${CMAKE_BUILD_TYPE})
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libprotoc.lib" DESTINATION lib/${CMAKE_BUILD_TYPE})
endif()
