include(FindPHP)

# Build code with SWIG   
include_directories(${PHP_INCLUDES} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

# Configure the swig target for php7
setup_swig_library("php7" "")
set_target_properties(wickrcryptoswig PROPERTIES OUTPUT_NAME wickrcrypto)
target_link_libraries(wickrcryptoswig ${PHP_LINKER_FLAGS})

if (APPLE)
    target_link_libraries(wickrcryptoswig "-undefined dynamic_lookup")
endif ()

if (BUILD_TESTS)

    find_program(PHPUNIT_EXECUTABLE phpunit)

    add_test(NAME wickrcryptophp 
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND php -d extension_dir=${CMAKE_CURRENT_BINARY_DIR} -d extension=$<TARGET_FILE_NAME:wickrcryptoswig> ${PHPUNIT_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
    
endif ()

install(FILES $<TARGET_FILE:wickrcryptoswig> DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/WickrCrypto.php DESTINATION ${CMAKE_INSTALL_DIR}/php)