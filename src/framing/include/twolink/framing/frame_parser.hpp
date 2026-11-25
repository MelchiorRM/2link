#pragma once

// Incremental frame parser for a TCP byte stream, spec v0.1 §2.4.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "twolink/framing/frame.hpp"

namespace twolink::framing {

struct FrameView {
  FrameHeader header;
  // Valid only during the handler call; copy it to keep it.
  std::span<const std::uint8_t> payload;
};

// Splits a byte stream into validated frames.
//
// - Handles partial reads, several frames per read and frames spanning reads.
// - The header is validated before any payload byte is buffered, and payload
//   memory is sized only from a validated length (at most kMaxPayload).
// - Holds at most one incomplete frame (kHeaderSize + kMaxPayload bytes).
// - The first error is sticky: the parser stops and every later feed() returns it.
//   The caller must close the connection (spec §1).
//
// Frames fully contained in the input are delivered without copying.
class FrameParser {
 public:
  using Handler = std::function<void(const FrameView&)>;

  // Calls on_frame once per complete frame, in stream order. The handler must not
  // call back into this parser.
  [[nodiscard]] FrameError feed(std::span<const std::uint8_t> data, const Handler& on_frame);

  [[nodiscard]] bool failed() const noexcept { return state_ == State::kFailed; }
  [[nodiscard]] FrameError error() const noexcept { return error_; }

  // Bytes of an incomplete frame currently held.
  [[nodiscard]] std::size_t buffered() const noexcept {
    return state_ == State::kPayload ? kHeaderSize + payload_fill_ : header_fill_;
  }

  // Drops any partial frame and clears a failure.
  void reset() noexcept;

 private:
  enum class State : std::uint8_t { kHeader, kPayload, kFailed };

  FrameError fail(FrameError error) noexcept;
  void begin_payload(const Handler& on_frame);

  State state_ = State::kHeader;
  FrameError error_ = FrameError::kOk;

  std::array<std::uint8_t, kHeaderSize> header_buf_{};
  std::size_t header_fill_ = 0;

  FrameHeader header_{};
  std::vector<std::uint8_t> payload_;
  std::size_t payload_fill_ = 0;
};

}  // namespace twolink::framing
