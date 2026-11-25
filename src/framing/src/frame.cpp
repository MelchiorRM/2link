#include "twolink/framing/frame.hpp"

#include <algorithm>
#include <array>

#include "twolink/core/byte_io.hpp"

namespace twolink::framing {

std::string_view to_string(FrameError error) noexcept {
  switch (error) {
    case FrameError::kOk: return "ok";
    case FrameError::kTruncated: return "truncated header";
    case FrameError::kUnsupportedVersion: return "unsupported version";
    case FrameError::kInvalidFlags: return "invalid flags";
    case FrameError::kInvalidReserved: return "invalid reserved byte";
    case FrameError::kUnknownType: return "unknown frame type";
    case FrameError::kWrongStream: return "frame type not valid on stream";
    case FrameError::kPayloadTooLarge: return "payload too large";
    case FrameError::kPayloadTooShort: return "payload too short";
    case FrameError::kLengthMismatch: return "length does not match payload";
  }
  return "unknown";
}

ErrorCode to_error_code(FrameError error) noexcept {
  switch (error) {
    case FrameError::kOk: return ErrorCode::kNoError;
    case FrameError::kUnsupportedVersion: return ErrorCode::kUnsupportedVersion;
    case FrameError::kPayloadTooLarge: return ErrorCode::kFrameTooLarge;
    case FrameError::kWrongStream: return ErrorCode::kInvalidStream;
    case FrameError::kLengthMismatch: return ErrorCode::kInternalError;
    case FrameError::kTruncated:
    case FrameError::kInvalidFlags:
    case FrameError::kInvalidReserved:
    case FrameError::kUnknownType:
    case FrameError::kPayloadTooShort: return ErrorCode::kProtocolError;
  }
  return ErrorCode::kProtocolError;
}

namespace {

// Validation shared by encoder and decoder. Takes the raw type byte so the
// decoder never casts an unchecked value to FrameType.
FrameError validate_fields(std::uint8_t version, std::uint8_t raw_type, std::uint8_t flags,
                           std::uint8_t reserved, std::uint32_t stream_id,
                           std::uint32_t length) noexcept {
  if (version != kProtocolVersion) return FrameError::kUnsupportedVersion;
  if (flags != 0) return FrameError::kInvalidFlags;
  if (reserved != 0) return FrameError::kInvalidReserved;
  if (!is_known_frame_type(raw_type)) return FrameError::kUnknownType;
  const auto type = static_cast<FrameType>(raw_type);
  if (stream_class_for(type) != stream_class_of(stream_id)) return FrameError::kWrongStream;
  if (length > max_payload(type)) return FrameError::kPayloadTooLarge;
  if (length < min_payload(type)) return FrameError::kPayloadTooShort;
  return FrameError::kOk;
}

}  // namespace

FrameError validate_header(const FrameHeader& h) noexcept {
  return validate_fields(h.version, static_cast<std::uint8_t>(h.type), h.flags, h.reserved,
                         h.stream_id, h.length);
}

FrameError encode_header(const FrameHeader& h, std::span<std::uint8_t, kHeaderSize> out) noexcept {
  if (const auto err = validate_header(h); err != FrameError::kOk) return err;
  ByteWriter w{out};
  // Cannot fail: the buffer is exactly kHeaderSize bytes.
  [[maybe_unused]] const bool ok = w.write(h.version) && w.write(static_cast<std::uint8_t>(h.type)) &&
                                   w.write(h.flags) && w.write(h.reserved) &&
                                   w.write(h.stream_id) && w.write(h.conn_id) && w.write(h.seq) &&
                                   w.write(h.length);
  return FrameError::kOk;
}

FrameError decode_header(std::span<const std::uint8_t> input, FrameHeader& out) noexcept {
  if (input.size() < kHeaderSize) return FrameError::kTruncated;
  ByteReader r{input.first<kHeaderSize>()};
  std::uint8_t version = 0, raw_type = 0, flags = 0, reserved = 0;
  std::uint32_t stream_id = 0, length = 0;
  std::uint64_t conn_id = 0, seq = 0;
  [[maybe_unused]] const bool ok = r.read(version) && r.read(raw_type) && r.read(flags) &&
                                   r.read(reserved) && r.read(stream_id) && r.read(conn_id) &&
                                   r.read(seq) && r.read(length);

  if (const auto err = validate_fields(version, raw_type, flags, reserved, stream_id, length);
      err != FrameError::kOk) {
    return err;
  }
  out = FrameHeader{version, static_cast<FrameType>(raw_type), flags, reserved,
                    stream_id, conn_id, seq, length};
  return FrameError::kOk;
}

FrameError encode_frame(const FrameHeader& header, std::span<const std::uint8_t> payload,
                        std::vector<std::uint8_t>& out) {
  if (payload.size() != header.length) return FrameError::kLengthMismatch;
  std::array<std::uint8_t, kHeaderSize> head{};
  if (const auto err = encode_header(header, head); err != FrameError::kOk) return err;
  std::vector<std::uint8_t> frame(kHeaderSize + payload.size());
  std::copy(head.begin(), head.end(), frame.begin());
  std::copy(payload.begin(), payload.end(), frame.begin() + static_cast<std::ptrdiff_t>(kHeaderSize));
  out = std::move(frame);
  return FrameError::kOk;
}

}  // namespace twolink::framing
