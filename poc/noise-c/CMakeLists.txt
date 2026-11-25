# Noise library proof-of-concept (task 0.7). Standalone; not part of the main build.
#
#   cmake -S poc/noise-c -B build/poc-noise && cmake --build build/poc-noise -j
#   ctest --test-dir build/poc-noise --output-on-failure
cmake_minimum_required(VERSION 3.25)
project(noise_poc LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

option(POC_SANITIZE "ASan + UBSan (GCC/Clang)" OFF)
if(POC_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

include(FetchContent)

# libsodium, built from source by a CMake wrapper (official sources as a submodule).
FetchContent_Declare(libsodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG 9b2848dfc1b917a9410f0de9d81059b26cbfaa8d
  GIT_SUBMODULES_RECURSE TRUE)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)

# noise-c: pinned commit, sources only (its autotools build is not used).
FetchContent_Declare(noisec
  GIT_REPOSITORY https://github.com/rweather/noise-c.git
  GIT_TAG cfe25410979a87391bb9ac8d4d4bef64e9f268c6)

FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
  GIT_SHALLOW TRUE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(libsodium googletest)
FetchContent_GetProperties(noisec)
if(NOT noisec_POPULATED)
  FetchContent_Populate(noisec)
endif()

# Mirrors noise-c's src/protocol/Makefile.am for the libsodium build, minus
# Curve448 and NewHope (unused by 2Link; their Goldilocks code is GCC-only).
set(N ${noisec_SOURCE_DIR}/src)
add_library(noiseprotocol STATIC
  ${N}/protocol/cipherstate.c
  ${N}/protocol/dhstate.c
  ${N}/protocol/errors.c
  ${N}/protocol/handshakestate.c
  ${N}/protocol/hashstate.c
  ${N}/protocol/internal.c
  ${N}/protocol/names.c
  ${N}/protocol/patterns.c
  ${N}/protocol/randstate.c
  ${N}/protocol/signstate.c
  ${N}/protocol/symmetricstate.c
  ${N}/protocol/util.c
  ${N}/protocol/rand_sodium.c
  ${N}/backend/ref/hash-blake2s.c
  ${N}/crypto/blake2/blake2s.c
  ${N}/backend/ref/cipher-aesgcm.c
  ${N}/backend/sodium/cipher-aesgcm.c
  ${N}/backend/sodium/cipher-chachapoly.c
  ${N}/backend/sodium/dh-curve25519.c
  ${N}/backend/sodium/hash-blake2b.c
  ${N}/backend/sodium/hash-sha256.c
  ${N}/backend/sodium/hash-sha512.c
  ${N}/backend/sodium/sign-ed25519.c
  ${N}/crypto/aes/rijndael-alg-fst.c
  ${N}/crypto/ghash/ghash.c
  noise_stubs.c
  noise_rekey.c)
target_include_directories(noiseprotocol PUBLIC ${noisec_SOURCE_DIR}/include PRIVATE ${N} ${N}/protocol .)
target_compile_definitions(noiseprotocol PRIVATE USE_LIBSODIUM=1)
target_link_libraries(noiseprotocol PUBLIC sodium)
if(MSVC)
  target_compile_definitions(noiseprotocol PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

enable_testing()
include(GoogleTest)
add_executable(noise_poc_test noise_poc_test.cpp)
target_include_directories(noise_poc_test PRIVATE .)
target_link_libraries(noise_poc_test PRIVATE noiseprotocol GTest::gtest_main)
gtest_discover_tests(noise_poc_test)
