cmake_minimum_required(VERSION 3.25)

option(TWOLINK_BUILD_TESTS "Build unit tests" ON)

# Dependencies come from vcpkg (manifest mode, vcpkg.json). The feature list must
# be set before project(), where the vcpkg toolchain installs packages.
if(TWOLINK_BUILD_TESTS)
  list(APPEND VCPKG_MANIFEST_FEATURES tests)
endif()

project(twolink VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TWOLINK_SANITIZE "Enable ASan + UBSan" OFF)
option(TWOLINK_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(TWOLINK_FUZZ "Build libFuzzer targets (Clang only)" OFF)

if(TWOLINK_FUZZ AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "TWOLINK_FUZZ requires Clang")
endif()

include(cmake/CompilerOptions.cmake)
include(cmake/Dependencies.cmake)

add_subdirectory(third_party/noise-c)

add_subdirectory(src/core)
add_subdirectory(src/framing)
add_subdirectory(src/crypto)
add_subdirectory(src/identity)
add_subdirectory(apps/cli)

if(TWOLINK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
  add_subdirectory(tests/fuzz)
endif()
