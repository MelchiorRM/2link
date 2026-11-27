#pragma once

// Short authentication string, spec v0.1.2 §4.5 (threat model H1):
//
//   d   = BLAKE2b-256("2link sas v1" || h)
//   n   = (first 5 bytes of d as big-endian u40) mod 1 000 000
//   SAS = n as 6 decimal digits, zero-padded, shown as "123 456"

#include <cstdint>
#include <string>

#include "twolink/crypto/keys.hpp"

namespace twolink::handshake {

// The SAS as a number in [0, 999 999].
[[nodiscard]] std::uint32_t sas_number(const crypto::HandshakeHash& h) noexcept;

// "ddd ddd", zero-padded. Precondition: n < 1 000 000.
[[nodiscard]] std::string format_sas(std::uint32_t n);

[[nodiscard]] inline std::string sas_string(const crypto::HandshakeHash& h) {
  return format_sas(sas_number(h));
}

}  // namespace twolink::handshake
