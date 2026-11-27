#include "twolink/crypto/noise.hpp"

#include <noise/protocol.h>

#include "twolink/noise_ext.h"

namespace twolink::crypto {

namespace detail {
void CipherStateDeleter::operator()(NoiseCipherState_s* state) const noexcept {
  noise_cipherstate_free(state);  // wipes the key before freeing
}
void HandshakeStateDeleter::operator()(NoiseHandshakeState_s* state) const noexcept {
  noise_handshakestate_free(state);  // wipes keys and chaining state
}
}  // namespace detail

namespace {

// noise-c's NoiseBuffer has non-const data; input buffers are only read.
std::uint8_t* input_ptr(std::span<const std::uint8_t> s) noexcept {
  return const_cast<std::uint8_t*>(s.data());  // NOLINT(cppcoreguidelines-pro-type-const-cast)
}

const std::uint8_t* ad_ptr(std::span<const std::uint8_t> ad) noexcept {
  return ad.empty() ? nullptr : ad.data();
}

}  // namespace

// --- CipherState ---------------------------------------------------------------

bool CipherState::encrypt_in_place(std::span<const std::uint8_t> ad,
                                   std::span<std::uint8_t> buffer,
                                   std::size_t plaintext_len) noexcept {
  if (!state_) return false;
  if (buffer.size() < kTagSize || plaintext_len > buffer.size() - kTagSize) {
    state_.reset();
    return false;
  }
  NoiseBuffer b;
  noise_buffer_set_inout(b, buffer.data(), plaintext_len, buffer.size());
  if (noise_cipherstate_encrypt_with_ad(state_.get(), ad_ptr(ad), ad.size(), &b) !=
      NOISE_ERROR_NONE) {
    state_.reset();
    return false;
  }
  return true;
}

bool CipherState::decrypt_in_place(std::span<const std::uint8_t> ad,
                                   std::span<std::uint8_t> buffer) noexcept {
  if (!state_) return false;
  NoiseBuffer b;
  noise_buffer_set_inout(b, buffer.data(), buffer.size(), buffer.size());
  if (noise_cipherstate_decrypt_with_ad(state_.get(), ad_ptr(ad), ad.size(), &b) !=
      NOISE_ERROR_NONE) {
    state_.reset();
    return false;
  }
  return true;
}

bool CipherState::rekey() noexcept {
  if (!state_) return false;
  if (twolink_noise_cipherstate_rekey(state_.get()) != NOISE_ERROR_NONE) {
    state_.reset();
    return false;
  }
  return true;
}

std::uint64_t CipherState::nonce() const noexcept {
  return twolink_noise_cipherstate_nonce(state_.get());
}

// --- Handshake -----------------------------------------------------------------

std::optional<Handshake> Handshake::create(const HandshakeConfig& config,
                                           const StaticKeyPair& local) noexcept {
  const bool initiator = config.role == Role::kInitiator;
  const bool needs_pin = config.pattern == Pattern::kIK && initiator;
  if (needs_pin != config.remote_static.has_value()) return std::nullopt;

  NoiseProtocolId id{};
  id.prefix_id = NOISE_PREFIX_STANDARD;
  id.pattern_id = config.pattern == Pattern::kXX ? NOISE_PATTERN_XX : NOISE_PATTERN_IK;
  id.dh_id = NOISE_DH_CURVE25519;
  id.cipher_id = NOISE_CIPHER_CHACHAPOLY;
  id.hash_id = NOISE_HASH_BLAKE2b;

  NoiseHandshakeState* raw = nullptr;
  if (noise_handshakestate_new_by_id(&raw, &id,
                                     initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER) !=
      NOISE_ERROR_NONE) {
    return std::nullopt;  // raw may dangle (X3): never touched
  }
  Handshake hs(raw);
  NoiseHandshakeState* s = hs.state_.get();

  const auto priv = local.private_key();
  if (noise_dhstate_set_keypair_private(noise_handshakestate_get_local_keypair_dh(s), priv.data(),
                                        priv.size()) != NOISE_ERROR_NONE) {
    return std::nullopt;
  }
  if (noise_handshakestate_set_prologue(s, config.prologue.data(), config.prologue.size()) !=
      NOISE_ERROR_NONE) {
    return std::nullopt;
  }
  if (config.remote_static) {
    if (noise_dhstate_set_public_key(noise_handshakestate_get_remote_public_key_dh(s),
                                     config.remote_static->data(),
                                     config.remote_static->size()) != NOISE_ERROR_NONE) {
      return std::nullopt;
    }
  }
  if (config.fixed_ephemeral_for_testing) {
    NoiseDHState* e = noise_handshakestate_get_fixed_ephemeral_dh(s);
    if (e == nullptr ||
        noise_dhstate_set_keypair_private(e, config.fixed_ephemeral_for_testing->data(),
                                          config.fixed_ephemeral_for_testing->size()) !=
            NOISE_ERROR_NONE) {
      return std::nullopt;
    }
  }
  if (noise_handshakestate_start(s) != NOISE_ERROR_NONE) return std::nullopt;
  return hs;
}

HandshakeAction Handshake::action() const noexcept {
  if (!state_) return finished_ ? HandshakeAction::kFinished : HandshakeAction::kFailed;
  switch (noise_handshakestate_get_action(state_.get())) {
    case NOISE_ACTION_WRITE_MESSAGE:
      return HandshakeAction::kWriteMessage;
    case NOISE_ACTION_READ_MESSAGE:
      return HandshakeAction::kReadMessage;
    case NOISE_ACTION_SPLIT:
      return HandshakeAction::kSplit;
    default:
      return HandshakeAction::kFailed;
  }
}

void Handshake::fail() noexcept { state_.reset(); }

std::optional<std::size_t> Handshake::write_message(std::span<const std::uint8_t> payload,
                                                    std::span<std::uint8_t> out) noexcept {
  if (action() != HandshakeAction::kWriteMessage) {
    fail();
    return std::nullopt;
  }
  NoiseBuffer msg;
  NoiseBuffer pl;
  noise_buffer_set_output(msg, out.data(), out.size());
  noise_buffer_set_input(pl, input_ptr(payload), payload.size());
  if (noise_handshakestate_write_message(state_.get(), &msg, payload.empty() ? nullptr : &pl) !=
      NOISE_ERROR_NONE) {
    fail();
    return std::nullopt;
  }
  return msg.size;
}

std::optional<std::size_t> Handshake::read_message(std::span<const std::uint8_t> message,
                                                   std::span<std::uint8_t> payload_out) noexcept {
  if (action() != HandshakeAction::kReadMessage) {
    fail();
    return std::nullopt;
  }
  NoiseBuffer msg;
  NoiseBuffer pl;
  noise_buffer_set_input(msg, input_ptr(message), message.size());
  noise_buffer_set_output(pl, payload_out.data(), payload_out.size());
  if (noise_handshakestate_read_message(state_.get(), &msg, &pl) != NOISE_ERROR_NONE) {
    fail();
    return std::nullopt;
  }
  return pl.size;
}

std::optional<PublicKey> Handshake::remote_static() const noexcept {
  if (!state_ || !noise_handshakestate_has_remote_public_key(state_.get())) return std::nullopt;
  PublicKey key{};
  if (noise_dhstate_get_public_key(noise_handshakestate_get_remote_public_key_dh(state_.get()),
                                   key.data(), key.size()) != NOISE_ERROR_NONE) {
    return std::nullopt;
  }
  return key;
}

std::optional<HandshakeHash> Handshake::handshake_hash() const noexcept {
  if (action() != HandshakeAction::kSplit) return std::nullopt;
  HandshakeHash h{};
  if (noise_handshakestate_get_handshake_hash(state_.get(), h.data(), h.size()) !=
      NOISE_ERROR_NONE) {
    return std::nullopt;
  }
  return h;
}

std::optional<Handshake::Keys> Handshake::split() noexcept {
  if (action() != HandshakeAction::kSplit) {
    fail();
    return std::nullopt;
  }
  NoiseCipherState* send = nullptr;
  NoiseCipherState* recv = nullptr;
  const int err = noise_handshakestate_split(state_.get(), &send, &recv);
  if (err != NOISE_ERROR_NONE) {
    fail();  // send/recv may dangle (X3): never touched
    return std::nullopt;
  }
  Keys keys{CipherState(send), CipherState(recv)};
  state_.reset();
  finished_ = true;
  return keys;
}

}  // namespace twolink::crypto
