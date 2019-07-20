include(FindNode)
nodejs_init()

# Build code with SWIG   
include_directories(${NODEJS_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set(CMAKE_SWIG_FLAGS -v8 ${CMAKE_SWIG_FLAGS})

# Configure the swig target for node
set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/../interface.i PROPERTY CPLUSPLUS ON)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 14)
setup_swig_library("javascript" "${NODEJS_LIBRARIES}")
set_target_properties(wickrcryptoswig PROPERTIES OUTPUT_NAME wickrcrypto)
set_target_properties(wickrcryptoswig PROPERTIES SUFFIX .node)
target_compile_options(wickrcryptoswig PRIVATE -DBUILDING_NODE_EXTENSION)

if (APPLE AND NOT IOS)
    add_custom_command(
        TARGET wickrcryptoswig 
        POST_BUILD 
        COMMAND install_name_tool -id "@rpath/wickrcrypto.node" $<TARGET_FILE:wickrcryptoswig>
        COMMAND install_name_tool -add_rpath "@loader_path" $<TARGET_FILE:wickrcryptoswig>
    )
endif ()

set(CMAKE_SHARED_LINKER_FLAGS ${NODEJS_LINK_FLAGS} ${CMAKE_SHARED_LINKER_FLAGS})

# Make the node module output to it's own folder
set_target_properties(wickrcryptoswig
    PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib"
)

if (BUILD_TESTS)

    add_test(NAME wickrcryptonode 
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMAND npm test
    )
    
endif ()

install(FILES $<TARGET_FILE:wickrcryptoswig> DESTINATION ${CMAKE_INSTALL_LIBDIR})