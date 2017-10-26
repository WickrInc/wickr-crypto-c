message("In ed448 test")

use_c99()

file(GLOB_RECURSE CryptoEd448TestSources *.c)
file(GLOB_RECURSE CryptoEd448TestHeaders *.h)

add_executable(ed448_test ${CryptoEd448TestSources} ${CryptoEd448TestHeaders})

foreach(FILE ${CryptoEd448TestSources} ${CryptoEd448TestHeaders})
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

add_dependencies(ed448_test wickr_crypto_lib)

target_link_libraries(ed448_test wickr_crypto_lib)

if (NOT APPLE AND UNIX)
    message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

    find_library(OPENSSL_CRYPTO NAMES libcrypto.a libcrypto.so REQUIRED)
    message("OpenSSL crypt library: ${OPENSSL_CRYPTO}")
    target_link_libraries(ed448_test ${OPENSSL_CRYPTO})

    target_link_libraries(ed448_test ${CMAKE_DL_LIBS})
endif()

if (WIN32)
  set(CMAKE_LIBRARY_PATH_FLAG "LIBPATH:")
endif()

target_link_libraries(ed448_test ${DECAF_LIB})
