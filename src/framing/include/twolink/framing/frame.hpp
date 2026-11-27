#pragma once

// Frame format, spec v0.1 §2 and §3.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "twolink/core/error_code.hpp"
#include "twolink/core/version.hpp"

namespace twolink::framing {

// §2.1 size limits.
inline constexpr std::size_t kHeaderSize = 28;
inline constexpr std::size_t kMaxPayload = 65535;  // Noise message limit, every frame type
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kMaxFrameSize = kHeaderSize + kMaxPayload;

// §2.2 streams.
inline constexpr std::uint32_t kControlStream = 0;
inline constexpr std::uint32_t kMessagingStream = 1;
inline constexpr std::uint32_t kFirstTransferStream = 2;

enum class StreamClass : std::uint8_t { kControl, kMessaging, kTransfer };

// §3 frame types.
enum class FrameType : std::uint8_t {
  kHandshake = 0x01,
  kPairConfirm = 0x02,
  kPairReject = 0x03,
  kPing = 0x04,
  kPong = 0x05,
  kRekey = 0x06,
  kClose = 0x07,

  kMsg = 0x10,
  kMsgAck = 0x11,
  kSyncRequest = 0x12,
  kSyncResponse = 0x13,

  kTransferOffer = 0x20,
  kTransferAccept = 0x21,
  kTransferReject = 0x22,
  kChunkRequest = 0x23,
  kChunkData = 0x24,
  kChunkAck = 0x25,
  kTransferCancel = 0x26,
  kTransferComplete = 0x27,
  kTransferResume = 0x28,
};

[[nodiscard]] constexpr bool is_known_frame_type(std::uint8_t raw) noexcept {
  return (raw >= 0x01 && raw <= 0x07) || (raw >= 0x10 && raw <= 0x13) ||
         (raw >= 0x20 && raw <= 0x28);
}

[[nodiscard]] constexpr StreamClass stream_class_of(std::uint32_t stream_id) noexcept {
  if (stream_id == kControlStream) return StreamClass::kControl;
  if (stream_id == kMessagingStream) return StreamClass::kMessaging;
  return StreamClass::kTransfer;
}

// Precondition: type is a known frame type.
[[nodiscard]] constexpr StreamClass stream_class_for(FrameType type) noexcept {
  const auto raw = static_cast<std::uint8_t>(type);
  if (raw < 0x10) return StreamClass::kControl;
  if (raw < 0x20) return StreamClass::kMessaging;
  return StreamClass::kTransfer;
}

// Only HANDSHAKE frames are plaintext (§3).
[[nodiscard]] constexpr bool is_encrypted(FrameType type) noexcept {
  return type != FrameType::kHandshake;
}

struct FrameHeader {
  std::uint8_t version = kProtocolVersion;
  FrameType type = FrameType::kHandshake;
  std::uint8_t flags = 0;
  std::uint8_t reserved = 0;
  std::uint32_t stream_id = kControlStream;
  std::uint64_t conn_id = 0;
  std::uint64_t seq = 0;
  std::uint32_t length = 0;  // payload bytes, including the AEAD tag if encrypted

  friend bool operator==(const FrameHeader&, const FrameHeader&) = default;
};

enum class FrameError : std::uint8_t {
  kOk,
  kTruncated,           // fewer than kHeaderSize bytes
  kUnsupportedVersion,  // version != 1
  kInvalidFlags,        // flags != 0
  kInvalidReserved,     // reserved != 0
  kUnknownType,         // type not in §3
  kWrongStream,         // type not valid on stream_id
  kPayloadTooLarge,     // length above the per-type limit
  kPayloadTooShort,     // length below the per-type minimum
  kLengthMismatch,      // header length != payload size (encoder)
};

[[nodiscard]] std::string_view to_string(FrameError error) noexcept;

// Close code to report for a framing error (§7.2).
[[nodiscard]] ErrorCode to_error_code(FrameError error) noexcept;

// Minimum and maximum payload length for a frame type (§2.1).
[[nodiscard]] constexpr std::size_t min_payload(FrameType type) noexcept {
  return is_encrypted(type) ? kAeadTagSize : 1;  // HANDSHAKE carries at least the kind byte
}
[[nodiscard]] constexpr std::size_t max_payload(FrameType type) noexcept {
  static_cast<void>(type);  // same limit for every type in v0.1.1
  return kMaxPayload;
}

// Checks every header rule that does not need connection state.
// conn_id and seq are checked by the session layer.
[[nodiscard]] FrameError validate_header(const FrameHeader& header) noexcept;

// Validates, then serializes the header. Nothing is written on error.
[[nodiscard]] FrameError encode_header(const FrameHeader& header,
                                       std::span<std::uint8_t, kHeaderSize> out) noexcept;

// Parses and validates the first kHeaderSize bytes of input.
// out is only written on success.
[[nodiscard]] FrameError decode_header(std::span<const std::uint8_t> input,
                                       FrameHeader& out) noexcept;

// Serializes a whole frame. header.length must equal payload.size().
// out is replaced on success and left untouched on error.
[[nodiscard]] FrameError encode_frame(const FrameHeader& header,
                                      std::span<const std::uint8_t> payload,
                                      std::vector<std::uint8_t>& out);

}  // namespace twolink::framing
