#pragma once

// Payloads of the control frames (spec v0.1.2 §3.1) and the Phase 1 MSG
// (§3.2). Decoders require the exact length: trailing bytes are malformed.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "twolink/core/error_code.hpp"

namespace twolink::connection {

inline constexpr std::size_t kMaxCloseReason = 256;
// §6.6: message text limit, so a message fits one frame with room for metadata.
inline constexpr std::size_t kMaxMessageText = 61440;

using Bytes = std::vector<std::uint8_t>;

// PING / PONG: nonce: u64.
[[nodiscard]] Bytes encode_ping(std::uint64_t nonce);
[[nodiscard]] std::optional<std::uint64_t> decode_ping(std::span<const std::uint8_t> p) noexcept;

// PAIR_REJECT: reason: u16. Unknown codes become PROTOCOL_ERROR (§7.1).
[[nodiscard]] Bytes encode_pair_reject(ErrorCode reason);
[[nodiscard]] std::optional<ErrorCode> decode_pair_reject(std::span<const std::uint8_t> p) noexcept;

// CLOSE: code: u16, reason_len: u16, reason: UTF-8, reason_len <= 256.
struct ClosePayload {
  ErrorCode code = ErrorCode::kNoError;
  std::string reason;
};
// The reason is cut to kMaxCloseReason bytes at a UTF-8 boundary.
[[nodiscard]] Bytes encode_close(ErrorCode code, std::string_view reason = {});
[[nodiscard]] std::optional<ClosePayload> decode_close(std::span<const std::uint8_t> p);

// MSG (Phase 1): text_len: u32, text: UTF-8, at most kMaxMessageText bytes.
[[nodiscard]] bool is_valid_message_text(std::string_view text) noexcept;
// Precondition: is_valid_message_text(text).
[[nodiscard]] Bytes encode_msg(std::string_view text);
[[nodiscard]] std::optional<std::string> decode_msg(std::span<const std::uint8_t> p);

}  // namespace twolink::connection
