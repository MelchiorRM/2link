#pragma once

// Connection state machine, spec v0.1.2 §6 (threat model H6, H9, S8).
//
// One Connection is one TCP connection after it is connected: CONNECTING is
// the transport's business (task 1.7). The Connection is pure: the caller
// feeds it parsed frames, timer ticks and user actions, writes whatever bytes
// it appends to `out`, and drains its events.
//
//   HANDSHAKING --XX--> AWAIT_CONFIRM --both confirmed--> ESTABLISHED
//        |  \--IK----------------------------------------^     |
//        v                     v                                v
//      CLOSED <------------ CLOSING <----------------------------
//
// - Before keys exist nothing is ever sent on failure (§7.1, H6).
// - With keys, the side detecting an error sends CLOSE with the code, then
//   drains in CLOSING for at most CLOSE_LINGER.
// - Received frames are checked against the per-state table (§6.3) and the
//   connection role (§6.4) after decryption, so only authenticated frames
//   decide what happens.

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "twolink/core/error_code.hpp"
#include "twolink/crypto/keys.hpp"
#include "twolink/framing/frame.hpp"
#include "twolink/handshake/engine.hpp"
#include "twolink/identity/device_id.hpp"
#include "twolink/session/session.hpp"

namespace twolink::connection {

using Clock = session::Clock;
using Bytes = std::vector<std::uint8_t>;
using namespace std::chrono_literals;

// §6.5.
inline constexpr Clock::duration kHandshakeTimeout = 10s;
inline constexpr Clock::duration kPairTimeout = 120s;
inline constexpr Clock::duration kKeepaliveInterval = 15s;
inline constexpr Clock::duration kIdleTimeout = 45s;
inline constexpr Clock::duration kCloseLinger = 1s;

enum class State : std::uint8_t {
  kHandshaking,
  kAwaitConfirm,
  kEstablished,
  kClosing,
  kClosed,
};

[[nodiscard]] std::string_view to_string(State state) noexcept;

// Frame types a state accepts from the peer (§6.3), before role rules.
[[nodiscard]] bool allowed_in_state(State state, framing::FrameType type) noexcept;

// Frame types a connection role carries (§6.4). Primary: streams 0 and 1.
// Bulk: PING, PONG, REKEY, CLOSE on stream 0, and transfer streams.
[[nodiscard]] bool allowed_on_role(handshake::ConnectionRole role,
                                   framing::FrameType type) noexcept;

// §6.4 simultaneous connect: of two connections between the same two peers,
// the one whose initiator has the lexicographically lower device_id is kept.
// Returns true if the connection initiated by `a` wins over the one by `b`.
[[nodiscard]] inline bool initiator_wins(const identity::DeviceId& a,
                                         const identity::DeviceId& b) noexcept {
  return a < b;
}

// 64 random bits from the CSPRNG (§2.3).
[[nodiscard]] std::uint64_t random_conn_id() noexcept;

struct Event {
  enum class Kind : std::uint8_t {
    kSasReady,     // XX done: show `sas`, then confirm_sas() or reject_sas()
    kEstablished,  // `paired` true after pairing, false after IK
    kMessage,      // MSG received: `text`
    kFrame,        // another application frame: `type`, `stream_id`, `payload`
    kClosed,       // terminal: `code`, `by_peer`, `reason`, `transport_lost`
  };
  explicit Event(Kind k) noexcept : kind(k) {}

  Kind kind;

  // kSasReady, kEstablished
  std::string sas;
  crypto::PublicKey peer_key{};
  handshake::HandshakePayload peer;
  bool paired = false;

  // kMessage
  std::string text;

  // kFrame
  framing::FrameType type = framing::FrameType::kMsg;
  std::uint32_t stream_id = 0;
  Bytes payload;

  // kClosed
  ErrorCode code = ErrorCode::kNoError;
  bool by_peer = false;
  bool transport_lost = false;
  std::string reason;
};

// Decisions the Connection asks its owner for. All optional; an empty hook
// refuses.
struct Hooks {
  // Responder, first PAIR frame: kNoError to continue, otherwise the (local)
  // reason the connection is closed without a reply: pairing window closed,
  // rate limited, too many handshakes (§4.6).
  std::function<ErrorCode()> admit_pair;
  // RECONNECT responder: is this key in the trust store? (§4.8)
  std::function<bool(const crypto::PublicKey&)> is_trusted;
  // XX completed: may this pairing take the single AWAIT_CONFIRM slot?
  std::function<bool()> begin_confirm;
};

struct InitiatorParams {
  handshake::HandshakeKind kind = handshake::HandshakeKind::kPair;
  handshake::ConnectionRole role = handshake::ConnectionRole::kPrimary;
  std::optional<crypto::PublicKey> remote_static;  // RECONNECT: the pinned key
  std::uint64_t conn_id = 0;                       // use random_conn_id()
};

class Connection {
 public:
  // Outgoing connection, TCP just connected: appends the first HANDSHAKE frame
  // to out. Fails on invalid parameters.
  [[nodiscard]] static std::optional<Connection> initiate(const crypto::StaticKeyPair& local,
                                                          handshake::HandshakePayload local_payload,
                                                          const InitiatorParams& params,
                                                          Hooks hooks, Clock::time_point now,
                                                          Bytes& out);

  // Incoming connection, TCP just accepted. `local` must outlive the
  // Connection's handshake (it is read when the first frame arrives).
  [[nodiscard]] static std::optional<Connection> accept(const crypto::StaticKeyPair& local,
                                                        handshake::HandshakePayload local_payload,
                                                        Hooks hooks, Clock::time_point now);

  Connection(Connection&&) noexcept = default;
  Connection& operator=(Connection&&) noexcept = default;
  ~Connection() = default;

  // A frame from the parser (header validated).
  void on_frame(const framing::FrameHeader& header, std::span<const std::uint8_t> payload,
                Clock::time_point now, Bytes& out);

  // Runs due timers. Call at next_deadline() (or any time).
  void on_tick(Clock::time_point now, Bytes& out);
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  // AWAIT_CONFIRM: the local user's SAS decision.
  void confirm_sas(Clock::time_point now, Bytes& out);
  void reject_sas(Clock::time_point now, Bytes& out);

  // ESTABLISHED, primary only. kProtocolError for invalid text, kInvalidStream
  // on a bulk connection, kInternalError if not established.
  [[nodiscard]] ErrorCode send_message(std::string_view text, Clock::time_point now, Bytes& out);

  // Local close. Sends CLOSE when keys exist; no-op once closing.
  void close(ErrorCode code, Clock::time_point now, Bytes& out);

  // Transport: everything appended so far has been written. Ends CLOSING once
  // our CLOSE is out.
  void on_flushed(Clock::time_point now);
  // Transport: TCP connection lost.
  void on_transport_lost();

  [[nodiscard]] std::vector<Event> take_events() { return std::exchange(events_, {}); }

  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] handshake::HandshakeKind kind() const noexcept { return kind_; }
  [[nodiscard]] handshake::ConnectionRole role() const noexcept { return role_; }
  [[nodiscard]] crypto::Role noise_role() const noexcept { return noise_role_; }
  // The authenticated peer key, once the handshake has completed.
  [[nodiscard]] const std::optional<crypto::PublicKey>& peer_key() const noexcept {
    return peer_key_;
  }

 private:
  Connection(const crypto::StaticKeyPair& local, handshake::HandshakePayload local_payload,
             Hooks hooks, crypto::Role noise_role, Clock::time_point now);

  void on_handshake_frame(const framing::FrameHeader& header,
                          std::span<const std::uint8_t> payload, Clock::time_point now,
                          Bytes& out);
  void on_handshake_complete(Clock::time_point now, Bytes& out);
  void on_keyed_frame(framing::FrameType type, std::uint32_t stream_id, const Bytes& plaintext,
                      Clock::time_point now, Bytes& out);

  // Sends a frame through the session; on failure the connection is closed.
  bool send(framing::FrameType type, std::uint32_t stream_id, std::span<const std::uint8_t> payload,
            Clock::time_point now, Bytes& out);
  void establish(bool paired);
  // Keyed states: send CLOSE(code) and enter CLOSING.
  void fail_keyed(ErrorCode code, Clock::time_point now, Bytes& out);
  // Enter CLOSING with the given outcome (CLOSE already sent or not needed).
  void enter_closing(ErrorCode code, bool by_peer, std::string reason, Clock::time_point now);
  // Terminal; emits kClosed once.
  void finish(ErrorCode code, bool by_peer, std::string reason, bool transport_lost = false);

  const crypto::StaticKeyPair* local_;
  handshake::HandshakePayload local_payload_;
  Hooks hooks_;
  crypto::Role noise_role_;
  handshake::HandshakeKind kind_ = handshake::HandshakeKind::kPair;
  handshake::ConnectionRole role_ = handshake::ConnectionRole::kPrimary;

  State state_ = State::kHandshaking;
  std::optional<handshake::HandshakeEngine> engine_;
  std::optional<session::Session> session_;
  std::optional<crypto::PublicKey> peer_key_;
  handshake::HandshakePayload peer_payload_;

  bool local_confirmed_ = false;
  bool peer_confirmed_ = false;
  std::uint64_t next_ping_nonce_ = 0;

  Clock::time_point state_since_;
  Clock::time_point last_send_;
  Clock::time_point last_recv_;

  // Outcome reported when CLOSING ends.
  bool close_sent_ = false;
  ErrorCode close_code_ = ErrorCode::kNoError;
  bool close_by_peer_ = false;
  std::string close_reason_;

  std::vector<Event> events_;
};

}  // namespace twolink::connection
