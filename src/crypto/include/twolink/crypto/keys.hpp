#pragma once

// Curve25519 static key pair (spec v0.1 §4.1) and library initialisation.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace twolink::crypto {

inline constexpr std::size_t kKeySize = 32;   // Curve25519 public and private keys
inline constexpr std::size_t kTagSize = 16;   // ChaCha20-Poly1305 tag
inline constexpr std::size_t kHashSize = 64;  // BLAKE2b handshake hash

using PublicKey = std::array<std::uint8_t, kKeySize>;
using HandshakeHash = std::array<std::uint8_t, kHashSize>;

// Initialises libsodium and noise-c. Call before anything else in this module.
// Safe to call repeatedly and from several threads; returns false if either
// library fails to initialise.
[[nodiscard]] bool initialize() noexcept;

// A device's long-term key pair. Move-only; the private key is wiped when the
// object is destroyed or moved from (threat model L4).
class StaticKeyPair {
 public:
  // Fresh key pair from the libsodium CSPRNG.
  [[nodiscard]] static StaticKeyPair generate() noexcept;
  // Rebuilds the pair from a stored private key (e.g. from the keystore).
  [[nodiscard]] static StaticKeyPair from_private_key(
      std::span<const std::uint8_t, kKeySize> private_key) noexcept;

  StaticKeyPair(const StaticKeyPair&) = delete;
  StaticKeyPair& operator=(const StaticKeyPair&) = delete;
  StaticKeyPair(StaticKeyPair&& other) noexcept;
  StaticKeyPair& operator=(StaticKeyPair&& other) noexcept;
  ~StaticKeyPair();

  [[nodiscard]] const PublicKey& public_key() const noexcept { return public_; }
  [[nodiscard]] std::span<const std::uint8_t, kKeySize> private_key() const noexcept {
    return private_;
  }

 private:
  StaticKeyPair() = default;
  void wipe() noexcept;

  std::array<std::uint8_t, kKeySize> private_{};
  PublicKey public_{};
};

}  // namespace twolink::crypto
