cmake_minimum_required(VERSION 3.14)
project(staticnet-testing)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON) # error if compiler doesn't support c++11
set(CMAKE_CXX_EXTENSIONS OFF) # use c++11 instead of gnu++11

# Compiler flags
set(WARNINGS "-Wall -Wextra -Wuninitialized ")
set(WARNINGS "${WARNINGS} -Wshadow -Wpedantic -Wcast-align -Wwrite-strings")
set(WARNINGS "${WARNINGS} -Wmissing-declarations -Wvla")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(WARNINGS "${WARNINGS} -Wunsafe-loop-optimizations")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(WARNINGS "${WARNINGS} -Wno-gnu-zero-variadic-macro-arguments")
endif()

set(CMAKE_CXX_FLAGS "-g ${WARNINGS}")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -fsanitize=address")

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release")
endif(NOT CMAKE_BUILD_TYPE)

# Main project code
add_subdirectory("${PROJECT_SOURCE_DIR}/bridge")
