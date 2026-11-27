#pragma once

// Handshake framing and driver, spec v0.1.2 §4.2-4.4 and §4.8.
//
// HANDSHAKE frames carry `kind: u8 | noise_message`, one Noise message per
// frame, with seq 0, 1, 2 counted across both directions. The engine runs one
// side of an XX (PAIR) or IK (RECONNECT) handshake over such frames, encodes
// and checks the TLV payloads, and hands back the session keys.
//
// Errors before session keys exist are never sent (§7.1, threat model H6): on
// any failure the engine appends nothing to `out`, and the caller just closes
// the TCP connection. Every error is sticky.
//
// Not handled here (task 1.5): the pairing window, rate limits, timeouts and
// the states after the handshake.

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "twolink/core/error_code.hpp"
#include "twolink/crypto/keys.hpp"
#include "twolink/crypto/noise.hpp"
#include "twolink/framing/frame.hpp"
#include "twolink/handshake/payload.hpp"

namespace twolink::handshake {

enum class HandshakeKind : std::uint8_t {
  kPair = 0x01,       // Noise XX
  kReconnect = 0x02,  // Noise IK
};

// Spec §4.2.
inline constexpr std::string_view kPrologue = "2LINK/1";

// Largest Noise message in a HANDSHAKE frame (§2.1).
inline constexpr std::size_t kMaxNoiseMessage = framing::kMaxPayload - 1;

struct HandshakeFrame {
  HandshakeKind kind;
  std::span<const std::uint8_t> noise_message;
};

// Splits a HANDSHAKE frame payload. Fails on an unknown kind or an empty
// payload. A responder uses this on the first frame to learn the kind before
// creating its engine (the pairing window applies to PAIR only, §4.6).
[[nodiscard]] std::optional<HandshakeFrame> parse_handshake_payload(
    std::span<const std::uint8_t> payload) noexcept;

// Decides whether a newly authenticated remote static key may continue the
// handshake. An IK responder checks its trust store here (§4.8); returning
// false fails the handshake with UNKNOWN_PEER.
using RemoteKeyCheck = std::function<bool(const crypto::PublicKey&)>;

struct EngineConfig {
  HandshakeKind kind = HandshakeKind::kPair;
  crypto::Role role = crypto::Role::kInitiator;
  // Initiator: the conn_id it picked (§2.3). Responder: ignored; adopted from
  // the first frame.
  std::uint64_t conn_id = 0;
  // RECONNECT initiator only, and required there: the pinned peer key (§4.8).
  std::optional<crypto::PublicKey> remote_static;
  // What this side announces (§4.3).
  HandshakePayload local_payload;
  // Called once, as soon as the peer's static key is authenticated. Optional:
  // when empty every key is accepted (PAIR: the SAS decides, §4.5).
  RemoteKeyCheck check_remote;
};

struct HandshakeResult {
  std::uint64_t conn_id = 0;
  crypto::PublicKey remote_static{};
  HandshakePayload remote_payload;
  crypto::HandshakeHash hash{};  // SAS input (§4.5)
  crypto::Handshake::Keys keys;
};

class HandshakeEngine {
 public:
  // Fails on invalid configuration: invalid local payload, ROLE bulk with
  // PAIR (§4.3), RECONNECT initiator without a pinned key.
  [[nodiscard]] static std::optional<HandshakeEngine> create(EngineConfig config,
                                                             const crypto::StaticKeyPair& local);

  HandshakeEngine(HandshakeEngine&&) noexcept = default;
  HandshakeEngine& operator=(HandshakeEngine&&) noexcept = default;
  ~HandshakeEngine() = default;

  // Initiator only: appends the first HANDSHAKE frame to out.
  [[nodiscard]] ErrorCode start(std::vector<std::uint8_t>& out);

  // Processes a received frame (header validated by the parser). If a reply is
  // due it is appended to out. Errors (all local, never sent):
  //   kProtocolError    not HANDSHAKE, wrong conn_id or seq, kind changed,
  //                     bad TLV payload, ROLE bulk with PAIR, non-empty XX
  //                     message 1, frame after completion
  //   kHandshakeFailed  Noise rejected the message
  //   kUnknownPeer      check_remote refused the peer key
  [[nodiscard]] ErrorCode on_frame(const framing::FrameHeader& header,
                                   std::span<const std::uint8_t> payload,
                                   std::vector<std::uint8_t>& out);

  // The handshake has completed: take_result() is available.
  [[nodiscard]] bool complete() const noexcept { return result_.has_value() || result_taken_; }
  [[nodiscard]] bool failed() const noexcept { return error_ != ErrorCode::kNoError; }
  [[nodiscard]] ErrorCode error() const noexcept { return error_; }
  [[nodiscard]] HandshakeKind kind() const noexcept { return config_.kind; }

  // Moves the result out once complete; nullopt otherwise or if already taken.
  [[nodiscard]] std::optional<HandshakeResult> take_result() noexcept;

 private:
  HandshakeEngine(EngineConfig config, crypto::Handshake noise) noexcept;

  ErrorCode fail(ErrorCode code) noexcept;
  ErrorCode write_next(std::vector<std::uint8_t>& out);
  ErrorCode check_remote_once();
  ErrorCode finish_if_ready();
  // True if handshake message `index` carries a TLV payload (§4.3).
  [[nodiscard]] bool carries_payload(std::uint64_t index) const noexcept;

  EngineConfig config_;
  crypto::Handshake noise_;
  std::uint64_t next_seq_ = 0;  // handshake frames so far, both directions
  bool have_conn_id_ = false;
  bool remote_checked_ = false;
  std::optional<HandshakePayload> remote_payload_;
  std::optional<HandshakeResult> result_;
  bool result_taken_ = false;
  ErrorCode error_ = ErrorCode::kNoError;
};

}  // namespace twolink::handshake
