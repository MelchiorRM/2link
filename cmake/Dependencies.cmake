# All third-party packages come from vcpkg (vcpkg.json, manifest mode).

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)  # standalone Asio, header-only (target asio::asio)

if(TWOLINK_BUILD_TESTS)
  find_package(GTest CONFIG REQUIRED)
endif()

# Later phases: BLAKE3 (Phase 2), SQLite (Phase 7). noise-c is built by
# third_party/noise-c.
