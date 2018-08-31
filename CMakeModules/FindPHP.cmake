# Discover PHP Version

execute_process(COMMAND php-config --version 
    OUTPUT_VARIABLE PHP_CONFIG_VERSION
    RESULT_VARIABLE PHP_CONFIG_VERSION_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT ${PHP_CONFIG_VERSION_RESULT} EQUAL 0)
        message(FATAL_ERROR "Unable to locate PHP")
else()
        set(PHP_VERSION ${PHP_CONFIG_VERSION} CACHE LOCAL "")
        message(STATUS "Using PHP ${PHP_CONFIG_VERSION}")
endif()

# Discover the includes for php
execute_process(COMMAND php-config --includes 
    OUTPUT_VARIABLE PHP_CONFIG_INCLUDES
    RESULT_VARIABLE PHP_CONFIG_INCLUDES_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT ${PHP_CONFIG_INCLUDES_RESULT} EQUAL 0)
        message(FATAL_ERROR "Unable to locate PHP Development Files")
else()
        # Remove the -I part of the response
        string(REPLACE "-I" "" PHP_CONFIG_INCLUDES ${PHP_CONFIG_INCLUDES})
        string(REPLACE " " ";" PHP_CONFIG_INCLUDES ${PHP_CONFIG_INCLUDES})

        set(PHP_INCLUDES ${PHP_CONFIG_INCLUDES} CACHE LOCAL "")
        message(STATUS "PHP Includes: ${PHP_CONFIG_INCLUDES}")
endif()

# Discover linker flags for php

execute_process(COMMAND php-config --ldflags 
    OUTPUT_VARIABLE PHP_CONFIG_LINKER
    RESULT_VARIABLE PHP_CONFIG_LINKER_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT ${PHP_CONFIG_LINKER_RESULT} EQUAL 0)
        message(FATAL_ERROR "Unable to locate PHP Development Files")
else()
        # Remove the -I part of the response
        string(REPLACE " " ";" PHP_CONFIG_LINKER ${PHP_CONFIG_LINKER})

        set(PHP_LINKER_FLAGS ${PHP_CONFIG_LINKER} CACHE LOCAL "")
        message(STATUS "PHP Linker Flags: ${PHP_CONFIG_LINKER}")
endif()