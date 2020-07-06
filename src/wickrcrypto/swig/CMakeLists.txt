
find_package(SWIG REQUIRED)
include(UseSWIG)

set(CMAKE_SWIG_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR}/../../include)

macro(setup_swig_library SWIG_LANGUAGE OTHER_LIBS)
    swig_add_library(wickrcryptoswig TYPE SHARED LANGUAGE ${SWIG_LANGUAGE} SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../interface.i)
    set_target_properties(wickrcryptoswig PROPERTIES OUTPUT_NAME WickrCrypto)
    swig_link_libraries(wickrcryptoswig wickrcrypto ${OTHER_LIBS})
    add_dependencies(wickrcryptoswig wickrcrypto)
endmacro()

# Add subdirectories for each language if desired

if(BUILD_NODE)
    add_subdirectory(node)
endif()

if(BUILD_JAVA)
    add_subdirectory(java)
endif()

if(BUILD_PHP)
    add_subdirectory(php)
endif()

# Install the SWIG files so dependencies can utilize them
file(GLOB SwigFiles *.i)
install(FILES ${SwigFiles} DESTINATION share/wickrcrypto/swig)