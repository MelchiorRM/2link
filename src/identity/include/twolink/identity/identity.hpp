#pragma once

// The device's persistent identity: static key pair + device_id (spec §4.1).

#include <optional>
#include <string_view>

#include "twolink/crypto/keys.hpp"
#include "twolink/identity/device_id.hpp"
#include "twolink/identity/keystore.hpp"

namespace twolink::identity {

inline constexpr std::string_view kIdentitySecretName = "identity";

struct Identity {
  crypto::StaticKeyPair key;
  DeviceId device_id;
};

// Loads the identity key, generating and storing one on first run. Requires
// crypto::initialize().
//
// Any keystore error other than "not found" is returned unchanged and nothing
// is written: a damaged or exposed key is never replaced automatically, since
// a new key is a new device to every peer (spec §4.8). If created is not null,
// it is set to whether a new key was generated.
[[nodiscard]] KeystoreStatus load_or_create_identity(Keystore& keystore, std::optional<Identity>& out,
                                                     bool* created = nullptr);

}  // namespace twolink::identity
