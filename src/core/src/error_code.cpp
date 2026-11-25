#include "twolink/core/error_code.hpp"

namespace twolink {

std::string_view to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kNoError: return "NO_ERROR";
    case ErrorCode::kProtocolError: return "PROTOCOL_ERROR";
    case ErrorCode::kUnsupportedVersion: return "UNSUPPORTED_VERSION";
    case ErrorCode::kFrameTooLarge: return "FRAME_TOO_LARGE";
    case ErrorCode::kDecryptFailed: return "DECRYPT_FAILED";
    case ErrorCode::kReplayDetected: return "REPLAY_DETECTED";
    case ErrorCode::kHandshakeFailed: return "HANDSHAKE_FAILED";
    case ErrorCode::kUnknownPeer: return "UNKNOWN_PEER";
    case ErrorCode::kIdentityChanged: return "IDENTITY_CHANGED";
    case ErrorCode::kPairingRejected: return "PAIRING_REJECTED";
    case ErrorCode::kPairingTimeout: return "PAIRING_TIMEOUT";
    case ErrorCode::kRateLimited: return "RATE_LIMITED";
    case ErrorCode::kTimeout: return "TIMEOUT";
    case ErrorCode::kDuplicateConnection: return "DUPLICATE_CONNECTION";
    case ErrorCode::kInvalidStream: return "INVALID_STREAM";
    case ErrorCode::kInternalError: return "INTERNAL_ERROR";
  }
  return "UNKNOWN";
}

}  // namespace twolink
