#include "twolink/identity/device_id.hpp"

#include <cstddef>

#include <sodium.h>

namespace twolink::identity {

namespace {
constexpr char kHexDigits[] = "0123456789abcdef";

void append_hex(std::string& out, std::uint8_t byte) {
  out += kHexDigits[byte >> 4];
  out += kHexDigits[byte & 0x0F];
}
}  // namespace

DeviceId device_id_from_key(const crypto::PublicKey& static_public_key) noexcept {
  DeviceId id{};
  crypto_generichash(id.data(), id.size(), static_public_key.data(), static_public_key.size(),
                     nullptr, 0);
  return id;
}

std::string display_form(const DeviceId& id) {
  std::string out;
  out.reserve(19);
  for (std::size_t i = 0; i < 8; ++i) {
    if (i > 0 && i % 2 == 0) out += '-';
    append_hex(out, id[i]);
  }
  return out;
}

std::string to_hex(const DeviceId& id) {
  std::string out;
  out.reserve(id.size() * 2);
  for (const std::uint8_t b : id) append_hex(out, b);
  return out;
}

}  // namespace twolink::identity
