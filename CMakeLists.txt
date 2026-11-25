cmake_minimum_required(VERSION 3.24)
project(twolink VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TWOLINK_BUILD_TESTS "Build unit tests" ON)
option(TWOLINK_SANITIZE "Enable ASan + UBSan" OFF)
option(TWOLINK_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

include(cmake/CompilerOptions.cmake)
include(cmake/Dependencies.cmake)

add_subdirectory(src/core)
add_subdirectory(src/framing)
add_subdirectory(apps/cli)

if(TWOLINK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
