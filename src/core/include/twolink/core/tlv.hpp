#pragma once

// TLV lists, spec v0.1.3 §4.3 (used by handshake payloads and discovery
// announcements, §8.1):
//
//   tag: u8 | len: u16 | value: [len] u8     (repeated)
//
// Rules enforced here for every list:
// - a truncated tag, length or value rejects the list;
// - a tag seen twice (known or unknown) rejects the list;
// - an unknown tag with the high bit set (0x80-0xFF, critical) rejects the
//   list; an unknown tag below 0x80 is ignored.
// The caller's visitor decides which tags are known and validates values.

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "twolink/core/byte_io.hpp"

namespace twolink {

inline constexpr std::uint8_t kTlvCriticalBit = 0x80;

enum class TlvError : std::uint8_t {
  kOk,
  kTruncated,
  kDuplicateTag,
  kUnknownCritical,
  kBadValue,  // the visitor rejected a known tag's value
};

enum class TlvVisit : std::uint8_t {
  kAccepted,  // known tag, valid value
  kUnknown,   // not a tag the caller knows
  kBadValue,  // known tag, malformed value
};

// Calls visit(tag, value) once per entry, in order, and stops at the first
// error. visit: TlvVisit(std::uint8_t tag, std::span<const std::uint8_t> value).
template <typename Visitor>
[[nodiscard]] TlvError parse_tlv(std::span<const std::uint8_t> input, Visitor&& visit) {
  ByteReader r{input};
  std::bitset<256> seen;
  while (r.remaining() > 0) {
    std::uint8_t tag = 0;
    std::uint16_t len = 0;
    std::span<const std::uint8_t> value;
    if (!r.read(tag) || !r.read(len) || !r.view_bytes(len, value)) return TlvError::kTruncated;
    if (seen.test(tag)) return TlvError::kDuplicateTag;
    seen.set(tag);
    switch (visit(tag, value)) {
      case TlvVisit::kAccepted: break;
      case TlvVisit::kBadValue: return TlvError::kBadValue;
      case TlvVisit::kUnknown:
        if ((tag & kTlvCriticalBit) != 0) return TlvError::kUnknownCritical;
        break;
    }
  }
  return TlvError::kOk;
}

// Appends one entry. Precondition: value.size() <= 65535.
inline void append_tlv(std::vector<std::uint8_t>& out, std::uint8_t tag,
                       std::span<const std::uint8_t> value) {
  out.push_back(tag);
  out.push_back(static_cast<std::uint8_t>(value.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(value.size() & 0xFF));
  out.insert(out.end(), value.begin(), value.end());
}

}  // namespace twolink
