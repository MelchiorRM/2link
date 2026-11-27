#pragma once

// Session layer, spec v0.1.2 §5: encrypted frames on an established connection.
//
// A Session owns both CipherStates from Noise Split() and turns plaintext into
// wire frames and back:
//
// - every encrypted frame's header is its associated data (§5.2, S2);
// - seq is always the sending CipherState counter, and a received frame must
//   carry exactly the receiving counter (§5.3, S3, S4);
// - frames must carry this connection's conn_id (§2.3, S5);
// - the sending direction is rekeyed after kRekeyFrames frames or
//   kRekeyInterval under one key, whichever comes first (§5.4).
//
// The session is pure: no I/O, and time is passed in, so tests can use a fake
// clock. Every receive error and every crypto failure is sticky: the session
// refuses all later work and the caller must close the connection (§7.1).
// Invalid arguments to seal() (a caller bug, not a peer action) are only
// reported.
//
// Not handled here: which frame types are allowed in which state (§6.3) and
// payload formats other than REKEY's.

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "twolink/core/error_code.hpp"
#include "twolink/crypto/noise.hpp"
#include "twolink/framing/frame.hpp"

namespace twolink::session {

using Clock = std::chrono::steady_clock;

// §5.4 / §9.
inline constexpr std::uint64_t kRekeyFrames = std::uint64_t{1} << 24;
inline constexpr std::chrono::seconds kRekeyInterval{3600};

// Largest plaintext an encrypted frame can carry (§2.1): 65 519 bytes.
inline constexpr std::size_t kMaxPlaintext = framing::kMaxPayload - framing::kAeadTagSize;

// Counter 2^64-1 is reserved by Noise (§5.3). The last usable value is kept for
// CLOSE, so a session can always say why it ends.
inline constexpr std::uint64_t kLastSeq = UINT64_MAX - 1;

// True if a frame of this type may be sent with this seq.
[[nodiscard]] constexpr bool seq_allows(std::uint64_t seq, framing::FrameType type) noexcept {
  return seq < kLastSeq || (seq == kLastSeq && type == framing::FrameType::kClose);
}

// No sending key encrypts more than max_frames frames (the REKEY that retires
// it included) or is used for longer than max_age. max_frames must be >= 2.
struct RekeyPolicy {
  std::uint64_t max_frames = kRekeyFrames;
  Clock::duration max_age = kRekeyInterval;
};

class Session {
 public:
  // keys comes from Handshake::split(); both CipherStates must be usable.
  // conn_id is the connection's id (§2.3), now the time the keys were made.
  [[nodiscard]] static std::optional<Session> create(crypto::Handshake::Keys keys,
                                                     std::uint64_t conn_id, Clock::time_point now,
                                                     RekeyPolicy policy = {});

  Session(Session&&) noexcept = default;
  Session& operator=(Session&&) noexcept = default;
  ~Session() = default;

  // Encrypts one frame and appends it, header included, to out.
  //
  // If the sending key is due for rekeying (§5.4) a REKEY frame is appended
  // first and the key replaced, so a caller cannot forget it. Sealing REKEY
  // itself is the same as send_rekey(). On error nothing is appended.
  // plaintext must not point into out.
  //
  // Errors, not sticky: kProtocolError for HANDSHAKE, a stream that does not
  // fit the type, plaintext above kMaxPlaintext, or REKEY with a payload.
  // Sticky: kInternalError if encryption fails or the counter is exhausted.
  // After a sticky error every call returns that error.
  [[nodiscard]] ErrorCode seal(Clock::time_point now, framing::FrameType type,
                               std::uint32_t stream_id, std::span<const std::uint8_t> plaintext,
                               std::vector<std::uint8_t>& out);

  // Rekeys the sending direction now (§5.4 allows rekeying early): appends a
  // REKEY frame to out, then replaces the sending key.
  [[nodiscard]] ErrorCode send_rekey(Clock::time_point now, std::vector<std::uint8_t>& out);

  // Checks and decrypts one received frame. header must come from the frame
  // parser (already validated) and payload is its ciphertext || tag.
  //
  // Checks, in order, before any decryption:
  //   kProtocolError   HANDSHAKE frame, length != payload size, wrong conn_id
  //   kReplayDetected  seq != receiving counter (duplicate, gap, reorder)
  // then
  //   kDecryptFailed   AEAD failure; plaintext is left empty
  //   kProtocolError   REKEY with a non-empty payload
  //
  // On success plaintext holds the payload. A REKEY frame is consumed here: the
  // receiving key is replaced and the caller just sees an empty REKEY.
  [[nodiscard]] ErrorCode open(const framing::FrameHeader& header,
                               std::span<const std::uint8_t> payload,
                               std::vector<std::uint8_t>& plaintext);

  // True if the next seal() will rekey first.
  [[nodiscard]] bool rekey_due(Clock::time_point now) const noexcept;

  // seq of the next frame sent / expected (the CipherState counters).
  [[nodiscard]] std::uint64_t next_send_seq() const noexcept { return send_.nonce(); }
  [[nodiscard]] std::uint64_t next_recv_seq() const noexcept { return recv_.nonce(); }

  [[nodiscard]] std::uint64_t conn_id() const noexcept { return conn_id_; }

  // The first error, or kNoError while the session works.
  [[nodiscard]] bool failed() const noexcept { return error_ != ErrorCode::kNoError; }
  [[nodiscard]] ErrorCode error() const noexcept { return error_; }

 private:
  Session(crypto::Handshake::Keys keys, std::uint64_t conn_id, Clock::time_point now,
          RekeyPolicy policy) noexcept;

  ErrorCode fail(ErrorCode code) noexcept;
  ErrorCode seal_one(framing::FrameType type, std::uint32_t stream_id,
                     std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& out);
  ErrorCode rekey_send(Clock::time_point now, std::vector<std::uint8_t>& out);

  crypto::CipherState send_;
  crypto::CipherState recv_;
  std::uint64_t conn_id_;
  RekeyPolicy policy_;
  // Where the current sending key started.
  std::uint64_t send_key_first_seq_ = 0;
  Clock::time_point send_key_since_;
  ErrorCode error_ = ErrorCode::kNoError;
};

}  // namespace twolink::session
