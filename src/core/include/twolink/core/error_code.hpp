#pragma once

// Connection error codes, spec v0.1 §7.2.

#include <cstdint>
#include <string_view>

namespace twolink {

enum class ErrorCode : std::uint16_t {
  kNoError = 0x0000,
  kProtocolError = 0x0001,
  kUnsupportedVersion = 0x0002,
  kFrameTooLarge = 0x0003,
  kDecryptFailed = 0x0004,
  kReplayDetected = 0x0005,
  kHandshakeFailed = 0x0006,
  kUnknownPeer = 0x0007,
  kIdentityChanged = 0x0008,
  kPairingRejected = 0x0009,
  kPairingTimeout = 0x000A,
  kRateLimited = 0x000B,
  kTimeout = 0x000C,
  kDuplicateConnection = 0x000D,
  kInvalidStream = 0x000E,
  kInternalError = 0x000F,
};

// Local-only codes are logged or shown to the user, never sent in CLOSE (§7.1).
[[nodiscard]] constexpr bool is_local_only(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kUnsupportedVersion:
    case ErrorCode::kHandshakeFailed:
    case ErrorCode::kUnknownPeer:
    case ErrorCode::kIdentityChanged:
    case ErrorCode::kRateLimited:
      return true;
    default:
      return false;
  }
}

// Maps a code received in CLOSE; unknown values become kProtocolError (§7.1).
[[nodiscard]] constexpr ErrorCode error_code_from_wire(std::uint16_t raw) noexcept {
  return raw <= static_cast<std::uint16_t>(ErrorCode::kInternalError) ? static_cast<ErrorCode>(raw)
                                                                       : ErrorCode::kProtocolError;
}

[[nodiscard]] std::string_view to_string(ErrorCode code) noexcept;

}  // namespace twolink
