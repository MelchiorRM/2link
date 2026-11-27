#pragma once

// Device identity derived from the static public key (spec v0.1.1 §4.1).

#include <array>
#include <cstdint>
#include <string>

#include "twolink/crypto/keys.hpp"

namespace twolink::identity {

// The full 32-byte device_id is the identity: storage, lookups, comparisons and
// tie-breaks use all of it (spec §4.1). Ordered lexicographically (spec §6.4).
using DeviceId = std::array<std::uint8_t, 32>;

// device_id = BLAKE2b-256(static_public_key). Requires crypto::initialize().
[[nodiscard]] DeviceId device_id_from_key(const crypto::PublicKey& static_public_key) noexcept;

// First 8 bytes as lowercase hex in four groups of four, e.g. "3fa1-09bc-77de-0142".
// A label for people and logs only; never used to identify or trust a device.
[[nodiscard]] std::string display_form(const DeviceId& id);

// All 32 bytes as lowercase hex (64 characters).
[[nodiscard]] std::string to_hex(const DeviceId& id);

}  // namespace twolink::identity
