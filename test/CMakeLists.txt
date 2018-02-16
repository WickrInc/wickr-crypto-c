file(GLOB TestSources *.c)
file(GLOB TestHeaders *.h)
file(GLOB CSpecSources cspec/src/*.c)

add_library(cspec ${CSpecSources})

target_include_directories(cspec PUBLIC cspec/inc)

add_executable(crypto_test ${TestSources} ${TestHeaders})

set(CRYPTO_DIR "${PROJECT_SOURCE_DIR}/src/wickrcrypto/include/wickrcrypto")
set(THIRD_PARTY_DIR "${PROJECT_SOURCE_DIR}/third-party")

include_directories(${CRYPTO_DIR} ${PROJECT_SOURCE_DIR}/src/protobuf/gen ${THIRD_PARTY_DIR}/protobuf-c)

target_link_libraries(crypto_test cspec wickrcrypto)

add_test(cypto_test crypto_test)
