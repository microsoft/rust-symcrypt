cmake_minimum_required(VERSION 3.13.0)

# Windows-specific settings
if(WIN32)
    # Require Windows 10 SDK version 18362
    set(CMAKE_SYSTEM_VERSION 10.0.18362)
endif()

# Set the project name and specify it's a C project
project(Win8Env C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Create a static library (.lib file)
add_library(win_8_env STATIC win_8_env.c)
