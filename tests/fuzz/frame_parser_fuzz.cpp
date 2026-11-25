// Fuzz target for the frame parser (threat model S6, S7).
//
// Invariants checked:
//  1. No crash, leak or UB (run under ASan/UBSan).
//  2. The parser never holds more than kMaxFrameSize bytes.
//  3. Chunking does not matter: feeding the input in pieces gives the same
//     frames and the same error as feeding it in one call.
//  4. Every delivered frame re-encodes to a valid frame with the same header.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "twolink/framing/frame_parser.hpp"

namespace {

using namespace twolink::framing;

struct Frame {
  FrameHeader header;
  std::vector<std::uint8_t> payload;
  bool operator==(const Frame&) const = default;
};

void check(bool condition) {
  if (!condition) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  // First byte picks the chunk size for the split feed.
  const std::size_t chunk = std::size_t{data[0]} + 1;
  const std::span<const std::uint8_t> input{data + 1, size - 1};

  auto collect = [](std::vector<Frame>& out) {
    return [&out](const FrameView& f) {
      check(f.payload.size() == f.header.length);
      std::vector<std::uint8_t> encoded;
      check(encode_frame(f.header, f.payload, encoded) == FrameError::kOk);
      FrameHeader back;
      check(decode_header(encoded, back) == FrameError::kOk && back == f.header);
      out.push_back({f.header, {f.payload.begin(), f.payload.end()}});
    };
  };

  std::vector<Frame> whole_frames;
  FrameParser whole;
  const FrameError whole_err = whole.feed(input, collect(whole_frames));
  check(whole.buffered() <= kMaxFrameSize);

  std::vector<Frame> split_frames;
  FrameParser split;
  FrameError split_err = FrameError::kOk;
  for (std::size_t pos = 0; pos < input.size(); pos += chunk) {
    const auto n = chunk < input.size() - pos ? chunk : input.size() - pos;
    split_err = split.feed(input.subspan(pos, n), collect(split_frames));
    check(split.buffered() <= kMaxFrameSize);
    if (split_err != FrameError::kOk) break;
  }

  check(whole_err == split_err);
  check(whole_frames == split_frames);
  return 0;
}
