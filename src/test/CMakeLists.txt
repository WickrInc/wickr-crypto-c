message("In crypto test")

use_c99()

file(GLOB_RECURSE CryptoTestSources *.c)
file(GLOB_RECURSE CryptoTestHeaders *.h)

add_executable(crypto_test ${CryptoTestSources} ${CryptoTestHeaders})

foreach(FILE ${CryptoTestSources} ${CryptoTestHeaders})
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

#    # Group into "Source Files" and "Header Files"
#    if ("${FILE}" MATCHES ".*\\.c")
#       set(GROUP "Source Files${GROUP}")
#    elseif("${FILE}" MATCHES ".*\\.h")
#       set(GROUP "Header Files${GROUP}")
#    endif()

    source_group("${GROUP}" FILES "${FILE}")
endforeach()

target_include_directories(crypto_test PUBLIC . cspec cspec/inc)

add_dependencies(crypto_test wickr_crypto_lib)

target_link_libraries(crypto_test wickr_crypto_lib)

if (NOT APPLE AND UNIX)
    message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

    target_link_libraries(crypto_test libcrypto.a)

    find_library(OPENSSL_CRYPTO libcrypto.a REQUIRED)
    message("OpenSSL crypt library: ${OPENSSL_CRYPTO}")
    target_link_libraries(crypto_test ${OPENSSL_CRYPTO})

    target_link_libraries(crypto_test ${CMAKE_DL_LIBS})
endif()

if (WIN32)
  set(CMAKE_LIBRARY_PATH_FLAG "LIBPATH:")
endif()
