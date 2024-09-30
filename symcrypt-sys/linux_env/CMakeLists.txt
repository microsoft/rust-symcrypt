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

set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(TARGET_TRIPLE aarch64-linux-gnu)

# Currently only use clang as it makes cross-compilation easier
set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

# Point clang sysroot to cross compilation toolchain when cross compiling
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    # C/C++ toolchain (installed on Ubuntu using apt-get gcc-aarch64-linux-gnu g++-aarch64-linux-gnu)
    set(CMAKE_SYSROOT_COMPILE /usr/${TARGET_TRIPLE})

    # We would expect setting SYSROOT to be sufficient for clang to cross-compile with the gcc-aarch64-linux-gnu
    # toolchain, but it seems that this misses a few key header files for C++...
    # Hacky solution which seems to work for Ubuntu + clang:
    # Get CMake to find the appropriate include directory and explicitly include it
    # Seems like there should be a better way to install cross-compilation tools, or specify search paths to clang
    find_path(CXX_CROSS_INCLUDE_DIR NAMES ${TARGET_TRIPLE} PATHS /usr/${TARGET_TRIPLE}/include/c++/ PATH_SUFFIXES 15 14 13 12 11 10 9 8 7 6 5 NO_DEFAULT_PATH)
    add_compile_options(-I${CXX_CROSS_INCLUDE_DIR}/${TARGET_TRIPLE})
endif()

# Set the project name and specify it's a C project
project(LinuxEnv C)

# Include SymCrypt headers
include_directories(../SymCrypt/inc)

# Create a static library (.lib file)
add_library(linux_env STATIC linux_env.c)

# Needed for Cargo to find.
install(TARGETS linux_env DESTINATION .)
