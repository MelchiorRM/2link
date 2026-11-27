#include "twolink/connection/payloads.hpp"

#include <array>

#include "twolink/core/byte_io.hpp"
#include "twolink/core/utf8.hpp"

namespace twolink::connection {

namespace {

std::string_view as_text(std::span<const std::uint8_t> b) noexcept {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}

std::span<const std::uint8_t> as_bytes(std::string_view s) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

template <typename T>
void put(Bytes& out, T value) {
  std::array<std::uint8_t, sizeof(T)> b{};
  store_be<T>(b, value);
  out.insert(out.end(), b.begin(), b.end());
}

}  // namespace

Bytes encode_ping(std::uint64_t nonce) {
  Bytes out;
  put(out, nonce);
  return out;
}

std::optional<std::uint64_t> decode_ping(std::span<const std::uint8_t> p) noexcept {
  ByteReader r{p};
  std::uint64_t nonce = 0;
  if (!r.read(nonce) || r.remaining() != 0) return std::nullopt;
  return nonce;
}

Bytes encode_pair_reject(ErrorCode reason) {
  Bytes out;
  put(out, static_cast<std::uint16_t>(reason));
  return out;
}

std::optional<ErrorCode> decode_pair_reject(std::span<const std::uint8_t> p) noexcept {
  ByteReader r{p};
  std::uint16_t code = 0;
  if (!r.read(code) || r.remaining() != 0) return std::nullopt;
  return error_code_from_wire(code);
}

Bytes encode_close(ErrorCode code, std::string_view reason) {
  if (reason.size() > kMaxCloseReason) {
    std::size_t n = kMaxCloseReason;
    while (n > 0 && (static_cast<std::uint8_t>(reason[n]) & 0xC0) == 0x80) --n;  // char boundary
    reason = reason.substr(0, n);
  }
  if (!is_valid_utf8(reason)) reason = {};
  Bytes out;
  put(out, static_cast<std::uint16_t>(code));
  put(out, static_cast<std::uint16_t>(reason.size()));
  const auto r = as_bytes(reason);
  out.insert(out.end(), r.begin(), r.end());
  return out;
}

std::optional<ClosePayload> decode_close(std::span<const std::uint8_t> p) {
  ByteReader r{p};
  std::uint16_t code = 0;
  std::uint16_t len = 0;
  std::span<const std::uint8_t> reason;
  if (!r.read(code) || !r.read(len) || len > kMaxCloseReason || !r.view_bytes(len, reason) ||
      r.remaining() != 0 || !is_valid_utf8(reason)) {
    return std::nullopt;
  }
  return ClosePayload{error_code_from_wire(code), std::string(as_text(reason))};
}

bool is_valid_message_text(std::string_view text) noexcept {
  return text.size() <= kMaxMessageText && is_valid_utf8(text);
}

Bytes encode_msg(std::string_view text) {
  Bytes out;
  put(out, static_cast<std::uint32_t>(text.size()));
  const auto t = as_bytes(text);
  out.insert(out.end(), t.begin(), t.end());
  return out;
}

std::optional<std::string> decode_msg(std::span<const std::uint8_t> p) {
  ByteReader r{p};
  std::uint32_t len = 0;
  std::span<const std::uint8_t> text;
  if (!r.read(len) || len > kMaxMessageText || !r.view_bytes(len, text) || r.remaining() != 0 ||
      !is_valid_utf8(text)) {
    return std::nullopt;
  }
  return std::string(as_text(text));
}

}  // namespace twolink::connection
