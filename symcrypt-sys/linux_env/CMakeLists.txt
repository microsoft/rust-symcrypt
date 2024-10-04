# Default to Release build type if none is specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# Set output directory for libraries to a 'lib' folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/lib)

# Set the project name and specify it's a C project
project(LinuxEnv C)

# Include SymCrypt headers (modify the path accordingly if necessary)
include_directories(../SymCrypt/inc)

# Set the compiler explicitly to gcc and g++
#set(CMAKE_C_COMPILER gcc)
#set(CMAKE_CXX_COMPILER g++)

# Create a static library (.a file)
add_library(linux_env STATIC linux_env.c)

# Needed for Cargo to find.
install(TARGETS linux_env DESTINATION .)