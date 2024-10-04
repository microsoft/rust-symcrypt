cmake_minimum_required(VERSION 3.13.0)

# Windows-specific settings
if(WIN32)
    # Require Windows 10 SDK version 18362
    set(CMAKE_SYSTEM_VERSION 10.0.18362)
endif()

# Default to Release build type if none is specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# Set output directory for libraries to a 'lib' folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib)


# Set the project name and specify it's a C project
project(Win8Env C)

# Include SymCrypt headers
include_directories(../SymCrypt/inc)

# Create a static library (.lib file)
add_library(win_8_env STATIC win_8_env.c)

# Needed for Cargo to find.
install(TARGETS win_8_env DESTINATION .)
