include(GoogleTest)

add_executable(twolink_tests
  smoke_test.cpp
  core/byte_io_test.cpp
  core/error_code_test.cpp
  framing/frame_test.cpp
  framing/frame_parser_test.cpp)
target_link_libraries(twolink_tests PRIVATE
  twolink::core twolink::framing twolink::options GTest::gtest_main)
gtest_discover_tests(twolink_tests)
