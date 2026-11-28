include(GoogleTest)

add_executable(twolink_tests
  smoke_test.cpp
  core/byte_io_test.cpp
  core/error_code_test.cpp
  crypto/crypto_env.cpp
  crypto/noise_ext_test.cpp
  crypto/noise_test.cpp
  deps/sodium_test.cpp
  framing/frame_test.cpp
  identity/device_id_test.cpp
  identity/identity_test.cpp
  identity/keystore_test.cpp
  identity/trust_store_test.cpp
  session/session_test.cpp
  handshake/payload_test.cpp
  handshake/engine_test.cpp
  core/utf8_test.cpp
  core/tlv_test.cpp
  connection/pairing_gate_test.cpp
  connection/payloads_test.cpp
  connection/connection_test.cpp
  transport/node_test.cpp
  discovery/announcement_test.cpp
  discovery/device_table_test.cpp
  discovery/service_test.cpp
  cli/cli_test.cpp
  integration/integration_test.cpp
  framing/frame_parser_test.cpp)
target_include_directories(twolink_tests PRIVATE support integration)
target_link_libraries(twolink_tests PRIVATE
  twolink::core twolink::framing twolink::crypto twolink::identity twolink::session twolink::handshake twolink::connection twolink::transport twolink::discovery twolink::cli_lib twolink::noisec twolink::options
  unofficial-sodium::sodium GTest::gtest_main)
gtest_discover_tests(twolink_tests)

# The 2link binary itself: exit codes and output of non-interactive commands.
add_test(NAME Cli.Version COMMAND twolink_cli version)
set_tests_properties(Cli.Version PROPERTIES PASS_REGULAR_EXPRESSION "protocol v1")
add_test(NAME Cli.IdCreatesIdentity
  COMMAND twolink_cli id --name ctest --data-dir ${CMAKE_CURRENT_BINARY_DIR}/cli-data)
set_tests_properties(Cli.IdCreatesIdentity PROPERTIES
  PASS_REGULAR_EXPRESSION "Device ID:   [0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]")  # CMake regex: no {n}
add_test(NAME Cli.UnknownCommandFails COMMAND twolink_cli bogus)
set_tests_properties(Cli.UnknownCommandFails PROPERTIES WILL_FAIL TRUE)
