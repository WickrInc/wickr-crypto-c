file(GLOB TestSources *.c)
file(GLOB TestHeaders *.h)
file(GLOB CSpecSources cspec/src/*.c)

add_library(cspec ${CSpecSources})

target_include_directories(cspec PUBLIC cspec/inc)

add_executable(crypto_test ${TestSources} ${TestHeaders})

set(CRYPTO_DIR "${CMAKE_SOURCE_DIR}/src/crypto")
set(THIRD_PARTY_DIR "${CMAKE_SOURCE_DIR}/third-party")

include_directories(${CMAKE_SOURCE_DIR}/src/crypto ${THIRD_PARTY_DIR}/protobuf-c/protobuf-c)

target_link_libraries(crypto_test cspec wickrcrypto)

add_test(cypto_test crypto_test)
