message("In third_party/bcrypt")

use_c99()

file(GLOB_RECURSE BcryptSources *.c)
file(GLOB_RECURSE BcryptHeaders *.h)

if (WIN32)
set(CMAKE_C_FLAGS "-Wall -Oy -O2")
else()
set(CMAKE_C_FLAGS "-fPIC -W -Wall -Wbad-function-cast -Wcast-align -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes -Wshadow -Wundef -Wpointer-arith -fomit-frame-pointer -funroll-loops")
endif()

add_library(bcrypt STATIC ${BcryptSources} ${BcryptHeaders})

foreach(FILE ${BcryptSources} ${BcryptHeaders} )
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
        INSTALL(FILES ${FILE} DESTINATION "include/bcrypt/${GROUP}")
    endif()
endforeach()

INSTALL(TARGETS bcrypt DESTINATION "lib/${CMAKE_BUILD_TYPE}")
