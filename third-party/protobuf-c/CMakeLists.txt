message("In third_party/protobuf-c")

use_c99()

file(GLOB_RECURSE ProtobufCSources *.c)
file(GLOB_RECURSE ProtobufCHeaders *.h)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

add_library(protobuf-c STATIC ${ProtobufCSources} ${ProtobufCHeaders})

foreach(FILE ${ProtobufCSources} ${ProtobufCHeaders} )
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

    source_group("${GROUP}" FILES "${FILE}")

    if (${FILE} MATCHES "\\.h$")
        INSTALL(FILES ${FILE} DESTINATION "include/protobuf-c/${GROUP}")
    endif()
endforeach()

INSTALL(TARGETS protobuf-c DESTINATION "lib")
