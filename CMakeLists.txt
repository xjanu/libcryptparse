cmake_minimum_required(VERSION 3.10)


### Project Settings ###

# Set the project info
project(cryptparse VERSION 0.1 DESCRIPTION
        "A simple library for parsing Linux' /proc/crypto, written in C.")

# Add an option to build as a static library
option(BUILD_SHARED_LIBS "Build as shared (.so) or static (.a) library" ON)

# default compiler options
add_compile_options(-Wall -Wextra -std=c99 -pedantic)


### LibCryptParse Target ###

# Add the library target
add_library(cryptparse src/libcryptparse.c)

# Set version no. for the target
#set_target_properties(cryptparse PROPERTIES VERSION ${PROJECT_VERSION})

# Declare the public interface
set_target_properties(cryptparse PROPERTIES PUBLIC_HEADER include/libcryptparse.h)

# Include directories
target_include_directories(cryptparse PUBLIC include)


### lscrypto target ###

# Link with the LibCryptParse
link_libraries(cryptparse)

# Add the lscrypto target
add_executable(lscrypto src/main.c)