#pragma once

// RAII wrapper over noise-c for spec v0.1.1 §4–5.
//
// Only the two protocols 2Link uses can be built:
//   Noise_XX_25519_ChaChaPoly_BLAKE2b (pairing) and
//   Noise_IK_25519_ChaChaPoly_BLAKE2b (reconnection).
//
// Error rule (threat model X3): noise-c frees an object on some errors but
// leaves the caller's pointer set. This wrapper never keeps or exposes a raw
// noise-c pointer after an error: the first failure destroys the underlying
// state, and every later call on that object fails without touching noise-c.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "twolink/crypto/keys.hpp"

struct NoiseCipherState_s;
struct NoiseHandshakeState_s;

namespace twolink::crypto {

namespace detail {
struct CipherStateDeleter {
  void operator()(NoiseCipherState_s* state) const noexcept;
};
struct HandshakeStateDeleter {
  void operator()(NoiseHandshakeState_s* state) const noexcept;
};
}  // namespace detail

// One direction of an established session (spec §5.1). The nonce is the
// CipherState's internal counter; 2Link never chooses nonces (spec §5.2).
class CipherState {
 public:
  CipherState(CipherState&&) noexcept = default;
  CipherState& operator=(CipherState&&) noexcept = default;
  ~CipherState() = default;

  // In-place EncryptWithAd. On entry buffer[0, plaintext_len) is the plaintext;
  // on success buffer[0, plaintext_len + kTagSize) is ciphertext || tag and the
  // counter has advanced by one. Fails if buffer is too small, the result would
  // exceed the Noise message limit (65 535 bytes), or the counter is exhausted.
  [[nodiscard]] bool encrypt_in_place(std::span<const std::uint8_t> ad,
                                      std::span<std::uint8_t> buffer,
                                      std::size_t plaintext_len) noexcept;

  // In-place DecryptWithAd. buffer holds ciphertext || tag; on success the
  // plaintext is buffer[0, buffer.size() - kTagSize) and the counter has advanced
  // by one. The plaintext MUST NOT be used on failure (spec §5.2).
  [[nodiscard]] bool decrypt_in_place(std::span<const std::uint8_t> ad,
                                      std::span<std::uint8_t> buffer) noexcept;

  // Noise Rekey(): replaces the key, leaves the counter unchanged (spec §5.4).
  [[nodiscard]] bool rekey() noexcept;

  // Number of messages processed so far, i.e. the nonce of the next message.
  // This is the value of seq for the next frame (spec §5.2). 0 once failed.
  [[nodiscard]] std::uint64_t nonce() const noexcept;

  // False after any failed operation; a failed CipherState refuses all work.
  [[nodiscard]] bool usable() const noexcept { return state_ != nullptr; }

 private:
  friend class Handshake;
  explicit CipherState(NoiseCipherState_s* state) noexcept : state_(state) {}

  std::unique_ptr<NoiseCipherState_s, detail::CipherStateDeleter> state_;
};

enum class Pattern : std::uint8_t { kXX, kIK };
enum class Role : std::uint8_t { kInitiator, kResponder };

enum class HandshakeAction : std::uint8_t {
  kWriteMessage,  // call write_message()
  kReadMessage,   // call read_message()
  kSplit,         // handshake complete: read hash/remote key, then split()
  kFinished,      // split() has been called
  kFailed,        // an operation failed; the handshake is dead
};

struct HandshakeConfig {
  Pattern pattern = Pattern::kXX;
  Role role = Role::kInitiator;
  // Spec §4.2: "2LINK/1". Kept as a parameter so tests can use other values.
  std::span<const std::uint8_t> prologue;
  // IK initiator only, and required there: the pinned responder key (spec §4.8).
  std::optional<PublicKey> remote_static;
  // Tests only (Cacophony reference vectors). Never set outside tests: a fixed
  // ephemeral key destroys forward secrecy.
  std::optional<std::array<std::uint8_t, kKeySize>> fixed_ephemeral_for_testing;
};

class Handshake {
 public:
  // Fails on invalid parameters (e.g. IK initiator without a pinned key) or if
  // noise-c cannot create the state.
  [[nodiscard]] static std::optional<Handshake> create(const HandshakeConfig& config,
                                                       const StaticKeyPair& local) noexcept;

  Handshake(Handshake&&) noexcept = default;
  Handshake& operator=(Handshake&&) noexcept = default;
  ~Handshake() = default;

  [[nodiscard]] HandshakeAction action() const noexcept;

  // Writes the next handshake message carrying payload into out. Returns the
  // message length. Requires action() == kWriteMessage.
  [[nodiscard]] std::optional<std::size_t> write_message(std::span<const std::uint8_t> payload,
                                                         std::span<std::uint8_t> out) noexcept;

  // Processes a received handshake message and writes its payload into
  // payload_out. Returns the payload length. Requires action() == kReadMessage.
  [[nodiscard]] std::optional<std::size_t> read_message(std::span<const std::uint8_t> message,
                                                        std::span<std::uint8_t> payload_out) noexcept;

  // The peer's static key once the handshake has authenticated it: after IK
  // message 1 for the responder (trust-store lookup, spec §4.8), after XX
  // message 2 or 3, and always in kSplit.
  [[nodiscard]] std::optional<PublicKey> remote_static() const noexcept;

  // Handshake hash h, available in kSplit (SAS input, spec §4.5).
  [[nodiscard]] std::optional<HandshakeHash> handshake_hash() const noexcept;

  struct Keys {
    CipherState send;
    CipherState recv;
  };
  // Noise Split(). Requires action() == kSplit; afterwards action() == kFinished
  // and the handshake state is destroyed.
  [[nodiscard]] std::optional<Keys> split() noexcept;

 private:
  explicit Handshake(NoiseHandshakeState_s* state) noexcept : state_(state) {}
  void fail() noexcept;

  std::unique_ptr<NoiseHandshakeState_s, detail::HandshakeStateDeleter> state_;
  bool finished_ = false;
};

}  // namespace twolink::crypto
