# TWOLINK_FUZZ=ON (Clang only): real libFuzzer binary.
# Otherwise: replay driver that runs the target over input files, so the
# harness always compiles.
function(twolink_fuzz_target name source corpus_dir test_name)
  if(TWOLINK_FUZZ)
    add_executable(${name} ${source})
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  else()
    add_executable(${name} ${source} replay_main.cpp)
    file(GLOB _corpus CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${corpus_dir}/*)
    add_test(NAME ${test_name} COMMAND ${name} ${_corpus})
  endif()
  target_link_libraries(${name} PRIVATE ${ARGN} twolink::options)
endfunction()

twolink_fuzz_target(fuzz_frame_parser frame_parser_fuzz.cpp corpus
  FuzzCorpus.FrameParser twolink::framing)
twolink_fuzz_target(fuzz_handshake_payload handshake_payload_fuzz.cpp corpus_payload
  FuzzCorpus.HandshakePayload twolink::handshake)
twolink_fuzz_target(fuzz_announcement announcement_fuzz.cpp corpus_announce
  FuzzCorpus.Announcement twolink::discovery twolink::crypto)
