#include "twolink/crypto/keys.hpp"

#include <algorithm>

#include <noise/protocol.h>
#include <sodium.h>

namespace twolink::crypto {

bool initialize() noexcept {
  // Function-local static: initialised exactly once, thread-safe (C++11).
  static const bool ok = sodium_init() >= 0 && noise_init() == NOISE_ERROR_NONE;
  return ok;
}

StaticKeyPair StaticKeyPair::generate() noexcept {
  StaticKeyPair pair;
  randombytes_buf(pair.private_.data(), pair.private_.size());
  // Clamping is applied inside the scalar multiplication, as X25519 requires.
  crypto_scalarmult_curve25519_base(pair.public_.data(), pair.private_.data());
  return pair;
}

StaticKeyPair StaticKeyPair::from_private_key(
    std::span<const std::uint8_t, kKeySize> private_key) noexcept {
  StaticKeyPair pair;
  std::copy(private_key.begin(), private_key.end(), pair.private_.begin());
  crypto_scalarmult_curve25519_base(pair.public_.data(), pair.private_.data());
  return pair;
}

StaticKeyPair::StaticKeyPair(StaticKeyPair&& other) noexcept
    : private_(other.private_), public_(other.public_) {
  other.wipe();
}

StaticKeyPair& StaticKeyPair::operator=(StaticKeyPair&& other) noexcept {
  if (this != &other) {
    private_ = other.private_;
    public_ = other.public_;
    other.wipe();
  }
  return *this;
}

StaticKeyPair::~StaticKeyPair() { wipe(); }

void StaticKeyPair::wipe() noexcept {
  sodium_memzero(private_.data(), private_.size());
  sodium_memzero(public_.data(), public_.size());
}

}  // namespace twolink::crypto
