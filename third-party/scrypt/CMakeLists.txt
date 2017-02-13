message("In third_party/scrypt")

use_c99()

file(GLOB_RECURSE ScryptSources *.c)
file(GLOB_RECURSE ScryptHeaders *.h)

add_library(scrypt STATIC ${ScryptSources} ${ScryptHeaders})

foreach(FILE ${ScryptSources} ${ScryptHeaders} )
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
        INSTALL(FILES ${FILE} DESTINATION "include/scrypt/${GROUP}")
    endif()
endforeach()

INSTALL(TARGETS scrypt DESTINATION "lib/${CMAKE_BUILD_TYPE}")
