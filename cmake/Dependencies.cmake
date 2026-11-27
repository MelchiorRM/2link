# All third-party packages come from vcpkg (vcpkg.json, manifest mode).

find_package(unofficial-sodium CONFIG REQUIRED)

if(TWOLINK_BUILD_TESTS)
  find_package(GTest CONFIG REQUIRED)
endif()

# Later phases: Asio (Phase 1), Noise (Phase 1, noise-c built by us),
# BLAKE3 (Phase 2), SQLite (Phase 7).
