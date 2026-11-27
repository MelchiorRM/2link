#include "twolink/identity/identity.hpp"

namespace twolink::identity {

namespace {

Identity from_secret(const SecretKey& secret) {
  crypto::StaticKeyPair key = crypto::StaticKeyPair::from_private_key(secret.bytes());
  const DeviceId id = device_id_from_key(key.public_key());
  return Identity{std::move(key), id};
}

}  // namespace

KeystoreStatus load_or_create_identity(Keystore& keystore, std::optional<Identity>& out,
                                       bool* created) {
  if (created != nullptr) *created = false;
  std::optional<SecretKey> secret;
  KeystoreStatus status = keystore.load(kIdentitySecretName, secret);
  if (status == KeystoreStatus::kNotFound) {
    const crypto::StaticKeyPair fresh = crypto::StaticKeyPair::generate();
    status = keystore.store(kIdentitySecretName, SecretKey::from_bytes(fresh.private_key()));
    if (status == KeystoreStatus::kOk) {
      if (created != nullptr) *created = true;
      out = from_secret(SecretKey::from_bytes(fresh.private_key()));
      return KeystoreStatus::kOk;
    }
    if (status != KeystoreStatus::kAlreadyExists) return status;
    // Another process created it first: use theirs.
    status = keystore.load(kIdentitySecretName, secret);
  }
  if (status != KeystoreStatus::kOk) return status;
  out = from_secret(*secret);
  return KeystoreStatus::kOk;
}

}  // namespace twolink::identity
