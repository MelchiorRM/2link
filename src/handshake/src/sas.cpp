#include "twolink/handshake/sas.hpp"

#include <array>
#include <string_view>

#include <sodium.h>

namespace twolink::handshake {

std::uint32_t sas_number(const crypto::HandshakeHash& h) noexcept {
  static constexpr std::string_view kLabel = "2link sas v1";
  std::array<std::uint8_t, 32> d{};
  crypto_generichash_state st;
  crypto_generichash_init(&st, nullptr, 0, d.size());
  crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(kLabel.data()),
                            kLabel.size());
  crypto_generichash_update(&st, h.data(), h.size());
  crypto_generichash_final(&st, d.data(), d.size());

  std::uint64_t v = 0;
  for (std::size_t i = 0; i < 5; ++i) v = (v << 8) | d[i];
  return static_cast<std::uint32_t>(v % 1'000'000);
}

std::string format_sas(std::uint32_t n) {
  std::string s = "000 000";
  for (int pos : {6, 5, 4, 2, 1, 0}) {
    s[static_cast<std::size_t>(pos)] = static_cast<char>('0' + n % 10);
    n /= 10;
  }
  return s;
}

}  // namespace twolink::handshake
