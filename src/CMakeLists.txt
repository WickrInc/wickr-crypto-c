include_directories("crypto")

add_subdirectory(crypto)

if (NOT ANDROID)
    add_subdirectory(test)
endif()

#if (UNIX AND NOT APPLE AND NOT ANDROID)
#    message("Including bindings directory!")
#    add_subdirectory(bindings)
#endif()
