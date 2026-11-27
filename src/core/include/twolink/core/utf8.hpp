#pragma once

// Strict UTF-8 validation for strings received from the network (spec §1:
// strings are UTF-8). Rejects overlong encodings, surrogates (U+D800..U+DFFF),
// code points above U+10FFFF and truncated sequences, as RFC 3629 requires.

#include <cstdint>
#include <span>
#include <string_view>

namespace twolink {

[[nodiscard]] constexpr bool is_valid_utf8(std::span<const std::uint8_t> s) noexcept {
  std::size_t i = 0;
  while (i < s.size()) {
    const std::uint8_t b = s[i];
    if (b < 0x80) {
      ++i;
      continue;
    }
    std::size_t n = 0;          // continuation bytes
    std::uint8_t lo = 0x80;     // allowed range of the second byte
    std::uint8_t hi = 0xBF;
    if (b >= 0xC2 && b <= 0xDF) {
      n = 1;
    } else if (b >= 0xE0 && b <= 0xEF) {
      n = 2;
      if (b == 0xE0) lo = 0xA0;  // overlong
      if (b == 0xED) hi = 0x9F;  // surrogates
    } else if (b >= 0xF0 && b <= 0xF4) {
      n = 3;
      if (b == 0xF0) lo = 0x90;  // overlong
      if (b == 0xF4) hi = 0x8F;  // above U+10FFFF
    } else {
      return false;  // continuation byte, C0/C1 overlong, or F5..FF
    }
    if (s.size() - i <= n) return false;  // truncated
    if (s[i + 1] < lo || s[i + 1] > hi) return false;
    for (std::size_t k = 2; k <= n; ++k) {
      if ((s[i + k] & 0xC0) != 0x80) return false;
    }
    i += n + 1;
  }
  return true;
}

[[nodiscard]] inline bool is_valid_utf8(std::string_view s) noexcept {
  return is_valid_utf8(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
}

}  // namespace twolink
