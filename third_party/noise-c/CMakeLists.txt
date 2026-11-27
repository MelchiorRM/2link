# noise-c, pinned and hash-checked (threat model X1). Only the sources 2Link
# needs are built, with the libsodium backend; noise-c's autotools build is not
# used. No noise-c source file is modified: 2Link's additions live next to this
# file (twolink_noise_ext.c, noise_stubs.c).
#
# To move the pin: change URL and URL_HASH together, review the upstream diff,
# and rerun the conformance tests (tests/crypto) on Linux and MSVC.

include(FetchContent)
FetchContent_Declare(noisec
  URL https://github.com/rweather/noise-c/archive/cfe25410979a87391bb9ac8d4d4bef64e9f268c6.tar.gz
  URL_HASH SHA256=d95cdd666124e9d1175c0c24024d7cabcd71149a9dbfe0de3aca43c562f7ac12
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
# noise-c has no CMakeLists.txt, so this only downloads and extracts it.
FetchContent_MakeAvailable(noisec)

# Mirrors noise-c's src/protocol/Makefile.am for the libsodium build, minus
# Curve448 and NewHope (unused; their Goldilocks code is GCC-only). The reference
# BLAKE2s and AES-GCM files are still needed because noise-c's name tables
# reference them; 2Link's protocol names never select them.
set(N ${noisec_SOURCE_DIR}/src)
add_library(twolink_noisec STATIC
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
  twolink_noise_ext.c)
add_library(twolink::noisec ALIAS twolink_noisec)
set_target_properties(twolink_noisec PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
target_include_directories(twolink_noisec
  PUBLIC ${noisec_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${N} ${N}/protocol)
target_compile_definitions(twolink_noisec PRIVATE USE_LIBSODIUM=1)
target_link_libraries(twolink_noisec PUBLIC unofficial-sodium::sodium)

# Third-party code: not held to 2Link's warning flags, but sanitized like the
# rest so memory bugs inside noise-c show up in CI.
if(MSVC)
  target_compile_definitions(twolink_noisec PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(twolink_noisec PRIVATE /w)
else()
  target_compile_options(twolink_noisec PRIVATE -w)
  if(TWOLINK_SANITIZE)
    target_compile_options(twolink_noisec PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  endif()
endif()
