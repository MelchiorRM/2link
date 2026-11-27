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
  connection/pairing_gate_test.cpp
  connection/payloads_test.cpp
  connection/connection_test.cpp
  framing/frame_parser_test.cpp)
target_link_libraries(twolink_tests PRIVATE
  twolink::core twolink::framing twolink::crypto twolink::identity twolink::session twolink::handshake twolink::connection twolink::noisec twolink::options
  unofficial-sodium::sodium GTest::gtest_main)
gtest_discover_tests(twolink_tests)
