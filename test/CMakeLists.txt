file(GLOB TestSources *.c)
file(GLOB TestHeaders *.h)
file(GLOB CSpecSources cspec/src/*.c)

add_library(cspec ${CSpecSources})

# Enable FIPS if needed
if (${FIPS})
    message(STATUS "Enabling FIPS")
    add_definitions(-DFIPS)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif ()

target_include_directories(cspec PUBLIC cspec/inc)

add_executable(crypto_test ${TestSources} ${TestHeaders})

# On Windows, the DLL for OpenSSL is needed in order to run tests
if (OPENSSL_CRYPTO_SHARED)

    get_filename_component(OPENSSL_CRYPTO_SHARED_FILENAME ${OPENSSL_CRYPTO_SHARED} NAME)

    add_custom_command(
        TARGET crypto_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${OPENSSL_CRYPTO_SHARED}
                ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/${OPENSSL_CRYPTO_SHARED_FILENAME})

endif()

set(CRYPTO_DIR "${PROJECT_SOURCE_DIR}/src/wickrcrypto/include/wickrcrypto")
set(THIRD_PARTY_DIR "${PROJECT_SOURCE_DIR}/third-party")

include_directories(${CRYPTO_DIR} ${PROJECT_SOURCE_DIR}/src/protobuf/gen ${THIRD_PARTY_DIR}/protobuf-c)

target_link_libraries(crypto_test cspec wickrcrypto)

if (${FIPS})
    target_link_libraries(crypto_test Threads::Threads)
endif ()

if(CMAKE_DL_LIBS)
    target_link_libraries(crypto_test ${CMAKE_DL_LIBS})
endif()

add_test(crypto_test crypto_test)

if (OPENSSL_CRYPTO_SHARED AND UNIX)
    get_filename_component(OPENSSL_CRYPTO_SHARED_DIRECTORY ${OPENSSL_CRYPTO_SHARED} DIRECTORY)
    set_tests_properties(crypto_test PROPERTIES ENVIRONMENT "LD_LIBRARY_PATH=${OPENSSL_CRYPTO_SHARED_DIRECTORY};$ENV{LD_LIBRARY_PATH}" )
endif ()



