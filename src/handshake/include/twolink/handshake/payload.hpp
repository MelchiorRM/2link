#pragma once

// Handshake payload TLV list, spec v0.1.2 §4.3 (threat model H7).
//
//   tag: u8 | len: u16 | value: [len] u8     (repeated)
//
// Tags 0x00-0x7F are optional (unknown ones ignored), 0x80-0xFF critical
// (unknown ones reject the whole list). Duplicates, missing required tags and
// malformed values are fatal.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace twolink::handshake {

enum class Tag : std::uint8_t {
  kDeviceName = 0x01,
  kRole = 0x02,
  kFeatures = 0x03,
};

inline constexpr std::uint8_t kCriticalTagBit = 0x80;
inline constexpr std::size_t kMaxDeviceNameSize = 64;

// §6.4: which connection of a peer pair this is.
enum class ConnectionRole : std::uint8_t { kPrimary = 0, kBulk = 1 };

struct HandshakePayload {
  std::string device_name;  // UTF-8, 1..64 bytes
  ConnectionRole role = ConnectionRole::kPrimary;
  std::optional<std::uint32_t> features;  // v0.1 senders send 0 or omit it

  friend bool operator==(const HandshakePayload&, const HandshakePayload&) = default;
};

enum class PayloadError : std::uint8_t {
  kOk,
  kTruncated,         // tag/len header or value cut short
  kDuplicateTag,      // a tag appears twice (known or unknown)
  kUnknownCritical,   // unknown tag in 0x80-0xFF
  kMissingRequired,   // DEVICE_NAME or ROLE absent
  kBadDeviceName,     // empty, longer than 64 bytes, or not UTF-8
  kBadRole,           // len != 1 or value not 0/1
  kBadFeatures,       // len != 4
};

[[nodiscard]] std::string_view to_string(PayloadError error) noexcept;

// True if name is a valid DEVICE_NAME value.
[[nodiscard]] bool is_valid_device_name(std::string_view name) noexcept;

// Appends the TLV encoding to out. Fails (appending nothing) if a field is
// invalid. Tags are written in ascending order.
[[nodiscard]] PayloadError encode_payload(const HandshakePayload& payload,
                                          std::vector<std::uint8_t>& out);

// Parses a received TLV list. out is only written on success.
[[nodiscard]] PayloadError decode_payload(std::span<const std::uint8_t> input,
                                          HandshakePayload& out);

}  // namespace twolink::handshake
