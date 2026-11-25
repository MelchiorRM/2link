#include "twolink/framing/frame_parser.hpp"

#include <algorithm>

namespace twolink::framing {

FrameError FrameParser::feed(std::span<const std::uint8_t> data, const Handler& on_frame) {
  if (state_ == State::kFailed) return error_;

  while (!data.empty()) {
    if (state_ == State::kHeader) {
      // Fast path: a whole header, and maybe the whole frame, is in the input.
      if (header_fill_ == 0 && data.size() >= kHeaderSize) {
        FrameHeader h;
        if (const auto err = decode_header(data, h); err != FrameError::kOk) return fail(err);
        data = data.subspan(kHeaderSize);
        if (data.size() >= h.length) {
          on_frame(FrameView{h, data.first(h.length)});
          data = data.subspan(h.length);
          continue;
        }
        header_ = h;
        begin_payload(on_frame);
        continue;
      }

      const std::size_t n = std::min(kHeaderSize - header_fill_, data.size());
      std::copy_n(data.data(), n, header_buf_.data() + header_fill_);
      header_fill_ += n;
      data = data.subspan(n);
      if (header_fill_ < kHeaderSize) break;

      if (const auto err = decode_header(header_buf_, header_); err != FrameError::kOk) {
        return fail(err);
      }
      header_fill_ = 0;
      begin_payload(on_frame);
    } else {  // State::kPayload
      const std::size_t n = std::min(std::size_t{header_.length} - payload_fill_, data.size());
      std::copy_n(data.data(), n, payload_.data() + payload_fill_);
      payload_fill_ += n;
      data = data.subspan(n);
      if (payload_fill_ == header_.length) {
        state_ = State::kHeader;
        payload_fill_ = 0;
        on_frame(FrameView{header_, payload_});
      }
    }
  }
  return FrameError::kOk;
}

void FrameParser::begin_payload(const Handler& on_frame) {
  if (header_.length == 0) {  // not reachable with spec v0.1 limits; kept for safety
    state_ = State::kHeader;
    on_frame(FrameView{header_, {}});
    return;
  }
  payload_.resize(header_.length);  // length already validated <= kMaxPayload
  payload_fill_ = 0;
  state_ = State::kPayload;
}

FrameError FrameParser::fail(FrameError error) noexcept {
  state_ = State::kFailed;
  error_ = error;
  header_fill_ = 0;
  payload_fill_ = 0;
  payload_.clear();
  return error;
}

void FrameParser::reset() noexcept {
  state_ = State::kHeader;
  error_ = FrameError::kOk;
  header_fill_ = 0;
  payload_fill_ = 0;
  payload_.clear();
}

}  // namespace twolink::framing
