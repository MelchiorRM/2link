#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "twolink/core/byte_io.hpp"
#include "twolink/framing/frame.hpp"

namespace twolink::framing::test {

// Writes a header with arbitrary field values, bypassing validation, so tests
// can build malformed frames.
inline std::array<std::uint8_t, kHeaderSize> raw_header(std::uint8_t version, std::uint8_t type,
                                                         std::uint8_t flags, std::uint8_t reserved,
                                                         std::uint32_t stream_id,
                                                         std::uint64_t conn_id, std::uint64_t seq,
                                                         std::uint32_t length) {
  std::array<std::uint8_t, kHeaderSize> out{};
  ByteWriter w{out};
  [[maybe_unused]] const bool ok = w.write(version) && w.write(type) && w.write(flags) &&
                                   w.write(reserved) && w.write(stream_id) && w.write(conn_id) &&
                                   w.write(seq) && w.write(length);
  return out;
}

// A valid encrypted MSG frame with a recognizable payload pattern.
inline FrameHeader msg_header(std::uint64_t seq, std::uint32_t length) {
  FrameHeader h;
  h.type = FrameType::kMsg;
  h.stream_id = kMessagingStream;
  h.conn_id = 0x1122334455667788ull;
  h.seq = seq;
  h.length = length;
  return h;
}

inline std::vector<std::uint8_t> pattern(std::size_t n, std::uint8_t start = 0) {
  std::vector<std::uint8_t> v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>(start + i);
  return v;
}

inline std::vector<std::uint8_t> make_frame(const FrameHeader& h,
                                            const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> out;
  if (encode_frame(h, payload, out) != FrameError::kOk) out.clear();
  return out;
}

}  // namespace twolink::framing::test
