#pragma once

// Finding paired devices by what a user types, and choosing a device name.

#include <string>
#include <string_view>
#include <vector>

#include "twolink/identity/trust_store.hpp"

namespace twolink::cli {

struct PeerMatch {
  enum class Result : std::uint8_t { kFound, kNotFound, kAmbiguous };
  Result result = Result::kNotFound;
  std::vector<const identity::PeerRecord*> matches;
};

// Matches an exact device name, or a prefix (at least 4 hex digits, dashes
// optional) of the device ID's hex form. The device must be unique.
[[nodiscard]] PeerMatch resolve_peer(const identity::TrustStore& trust, std::string_view query);

// A valid DEVICE_NAME (UTF-8, 1..64 bytes) from a host name: invalid bytes are
// replaced, long names are cut at a character boundary, empty becomes a default.
[[nodiscard]] std::string sanitize_device_name(std::string_view raw);

// "2026-11-27 12:34 UTC".
[[nodiscard]] std::string format_utc(std::int64_t unix_seconds);

}  // namespace twolink::cli
