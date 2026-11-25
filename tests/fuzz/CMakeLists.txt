# TWOLINK_FUZZ=ON (Clang only): real libFuzzer binary.
# Otherwise: replay driver that runs the target over input files, so the
# harness always compiles.
if(TWOLINK_FUZZ)
  add_executable(fuzz_frame_parser frame_parser_fuzz.cpp)
  target_compile_options(fuzz_frame_parser PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_frame_parser PRIVATE -fsanitize=fuzzer)
else()
  add_executable(fuzz_frame_parser frame_parser_fuzz.cpp replay_main.cpp)
endif()
target_link_libraries(fuzz_frame_parser PRIVATE twolink::framing twolink::options)

if(NOT TWOLINK_FUZZ)
  file(GLOB _corpus CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/*)
  add_test(NAME FuzzCorpus.FrameParser COMMAND fuzz_frame_parser ${_corpus})
endif()
