#include "twolink/connection/connection.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include <sodium.h>

#include "twolink/connection/payloads.hpp"
#include "twolink/handshake/sas.hpp"

namespace twolink::connection {

using framing::FrameHeader;
using framing::FrameType;
using framing::kControlStream;
using framing::kMessagingStream;
using handshake::ConnectionRole;
using handshake::HandshakeKind;

std::string_view to_string(State state) noexcept {
  switch (state) {
    case State::kHandshaking: return "HANDSHAKING";
    case State::kAwaitConfirm: return "AWAIT_CONFIRM";
    case State::kEstablished: return "ESTABLISHED";
    case State::kClosing: return "CLOSING";
    case State::kClosed: return "CLOSED";
  }
  return "?";
}

bool allowed_in_state(State state, FrameType type) noexcept {
  switch (state) {
    case State::kHandshaking: return type == FrameType::kHandshake;
    case State::kAwaitConfirm:
      return type == FrameType::kPairConfirm || type == FrameType::kPairReject ||
             type == FrameType::kPing || type == FrameType::kPong || type == FrameType::kClose;
    case State::kEstablished:
      return type != FrameType::kHandshake && type != FrameType::kPairConfirm &&
             type != FrameType::kPairReject;
    case State::kClosing: return type == FrameType::kClose;
    case State::kClosed: return false;
  }
  return false;
}

bool allowed_on_role(ConnectionRole role, FrameType type) noexcept {
  const framing::StreamClass cls = framing::stream_class_for(type);
  if (role == ConnectionRole::kPrimary) return cls != framing::StreamClass::kTransfer;
  if (cls == framing::StreamClass::kTransfer) return true;
  return type == FrameType::kPing || type == FrameType::kPong || type == FrameType::kRekey ||
         type == FrameType::kClose;
}

std::uint64_t random_conn_id() noexcept {
  std::uint64_t id = 0;
  randombytes_buf(&id, sizeof id);
  return id;
}

Connection::Connection(const crypto::StaticKeyPair& local,
                       handshake::HandshakePayload local_payload, Hooks hooks,
                       crypto::Role noise_role, Clock::time_point now)
    : local_(&local),
      local_payload_(std::move(local_payload)),
      hooks_(std::move(hooks)),
      noise_role_(noise_role),
      state_since_(now),
      last_send_(now),
      last_recv_(now) {}

std::optional<Connection> Connection::initiate(const crypto::StaticKeyPair& local,
                                               handshake::HandshakePayload local_payload,
                                               const InitiatorParams& params, Hooks hooks,
                                               Clock::time_point now, Bytes& out) {
  local_payload.role = params.role;
  Connection c(local, local_payload, std::move(hooks), crypto::Role::kInitiator, now);
  c.kind_ = params.kind;
  c.role_ = params.role;

  handshake::EngineConfig ec;
  ec.kind = params.kind;
  ec.role = crypto::Role::kInitiator;
  ec.conn_id = params.conn_id;
  ec.remote_static = params.remote_static;
  ec.local_payload = std::move(local_payload);
  c.engine_ = handshake::HandshakeEngine::create(std::move(ec), local);
  if (!c.engine_) return std::nullopt;

  Bytes first;
  if (c.engine_->start(first) != ErrorCode::kNoError) return std::nullopt;
  out.insert(out.end(), first.begin(), first.end());
  return c;
}

std::optional<Connection> Connection::accept(const crypto::StaticKeyPair& local,
                                             handshake::HandshakePayload local_payload,
                                             Hooks hooks, Clock::time_point now) {
  if (!handshake::is_valid_device_name(local_payload.device_name)) return std::nullopt;
  return Connection(local, std::move(local_payload), std::move(hooks), crypto::Role::kResponder,
                    now);
}

// --- frames -------------------------------------------------------------------

void Connection::on_frame(const FrameHeader& header, std::span<const std::uint8_t> payload,
                          Clock::time_point now, Bytes& out) {
  if (state_ == State::kClosed) return;
  if (state_ == State::kHandshaking) {
    on_handshake_frame(header, payload, now, out);
    return;
  }

  Bytes plaintext;
  const ErrorCode err = session_->open(header, payload, plaintext);
  if (err != ErrorCode::kNoError) {
    if (state_ == State::kClosing) {
      finish(close_code_, close_by_peer_, close_reason_);
    } else {
      fail_keyed(err, now, out);
    }
    return;
  }
  last_recv_ = now;
  on_keyed_frame(header.type, header.stream_id, plaintext, now, out);
}

void Connection::on_handshake_frame(const FrameHeader& header,
                                    std::span<const std::uint8_t> payload, Clock::time_point now,
                                    Bytes& out) {
  if (header.type != FrameType::kHandshake) {
    finish(ErrorCode::kProtocolError, false, {});  // no frame before keys (§7.1)
    return;
  }

  if (!engine_) {  // responder, first frame: the kind picks the pattern
    const auto frame = handshake::parse_handshake_payload(payload);
    if (!frame) {
      finish(ErrorCode::kProtocolError, false, {});
      return;
    }
    kind_ = frame->kind;
    handshake::EngineConfig ec;
    ec.kind = kind_;
    ec.role = crypto::Role::kResponder;
    ec.local_payload = local_payload_;
    if (kind_ == HandshakeKind::kPair) {
      const ErrorCode admit = hooks_.admit_pair ? hooks_.admit_pair() : ErrorCode::kPairingRejected;
      if (admit != ErrorCode::kNoError) {
        finish(admit, false, {});  // refused without a reply (§4.6)
        return;
      }
    } else {
      // A copy of the hook, not `this`: the Connection may move.
      ec.check_remote = hooks_.is_trusted
                            ? hooks_.is_trusted
                            : handshake::RemoteKeyCheck([](const crypto::PublicKey&) { return false; });
    }
    engine_ = handshake::HandshakeEngine::create(std::move(ec), *local_);
    if (!engine_) {
      finish(ErrorCode::kInternalError, false, {});
      return;
    }
  }

  Bytes reply;
  const ErrorCode err = engine_->on_frame(header, payload, reply);
  if (err != ErrorCode::kNoError) {
    finish(err, false, {});  // reply is empty on failure (H6)
    return;
  }
  last_recv_ = now;
  if (!reply.empty()) {
    out.insert(out.end(), reply.begin(), reply.end());
    last_send_ = now;
  }
  if (engine_->complete()) on_handshake_complete(now, out);
}

void Connection::on_handshake_complete(Clock::time_point now, Bytes& out) {
  auto result = engine_->take_result();
  engine_.reset();
  local_ = nullptr;
  if (!result) {
    finish(ErrorCode::kHandshakeFailed, false, {});
    return;
  }
  if (noise_role_ == crypto::Role::kResponder) {
    role_ = result->remote_payload.role;  // the initiator decides (§6.4)
  } else if (result->remote_payload.role != role_) {
    finish(ErrorCode::kProtocolError, false, {});
    return;
  }
  peer_key_ = result->remote_static;
  peer_payload_ = result->remote_payload;
  const std::string sas = handshake::sas_string(result->hash);

  session_ = session::Session::create(std::move(result->keys), result->conn_id, now);
  if (!session_) {
    finish(ErrorCode::kInternalError, false, {});
    return;
  }
  state_since_ = now;

  if (kind_ == HandshakeKind::kReconnect) {
    establish(false);
    return;
  }
  state_ = State::kAwaitConfirm;
  if (!hooks_.begin_confirm || !hooks_.begin_confirm()) {
    fail_keyed(ErrorCode::kPairingRejected, now, out);  // another pairing awaits (§4.6)
    return;
  }
  Event e{Event::Kind::kSasReady};
  e.sas = sas;
  e.peer_key = *peer_key_;
  e.peer = peer_payload_;
  events_.push_back(std::move(e));
}

void Connection::on_keyed_frame(FrameType type, std::uint32_t stream_id, const Bytes& plaintext,
                                Clock::time_point now, Bytes& out) {
  if (state_ == State::kClosing) {
    // The outcome was decided on entering CLOSING; the peer's CLOSE ends it.
    if (type == FrameType::kClose) finish(close_code_, close_by_peer_, close_reason_);
    return;  // anything else is discarded (§6.3)
  }

  if (!allowed_in_state(state_, type)) {
    fail_keyed(ErrorCode::kProtocolError, now, out);
    return;
  }
  if (state_ == State::kEstablished && !allowed_on_role(role_, type)) {
    fail_keyed(ErrorCode::kInvalidStream, now, out);
    return;
  }

  switch (type) {
    case FrameType::kClose: {
      const auto close = decode_close(plaintext);
      if (!close) {
        finish(ErrorCode::kProtocolError, false, {});  // no reply to CLOSE (§7.1)
        return;
      }
      finish(close->code, true, close->reason);
      return;
    }
    case FrameType::kPing: {
      const auto nonce = decode_ping(plaintext);
      if (!nonce) {
        fail_keyed(ErrorCode::kProtocolError, now, out);
        return;
      }
      static_cast<void>(send(FrameType::kPong, kControlStream, encode_ping(*nonce), now, out));
      return;
    }
    case FrameType::kPong:
      if (!decode_ping(plaintext)) fail_keyed(ErrorCode::kProtocolError, now, out);
      return;
    case FrameType::kRekey:
      return;  // consumed by the session
    case FrameType::kPairConfirm:
      if (!plaintext.empty() || peer_confirmed_) {
        fail_keyed(ErrorCode::kProtocolError, now, out);
        return;
      }
      peer_confirmed_ = true;
      if (local_confirmed_) establish(true);
      return;
    case FrameType::kPairReject: {
      if (!decode_pair_reject(plaintext)) {
        fail_keyed(ErrorCode::kProtocolError, now, out);
        return;
      }
      enter_closing(ErrorCode::kPairingRejected, true, {}, now);  // their CLOSE follows
      return;
    }
    case FrameType::kMsg: {
      auto text = decode_msg(plaintext);
      if (!text) {
        fail_keyed(ErrorCode::kProtocolError, now, out);
        return;
      }
      Event e{Event::Kind::kMessage};
      e.text = std::move(*text);
      events_.push_back(std::move(e));
      return;
    }
    default: {
      Event e{Event::Kind::kFrame};
      e.type = type;
      e.stream_id = stream_id;
      e.payload = plaintext;
      events_.push_back(std::move(e));
      return;
    }
  }
}

// --- user actions ---------------------------------------------------------------

void Connection::confirm_sas(Clock::time_point now, Bytes& out) {
  if (state_ != State::kAwaitConfirm || local_confirmed_) return;
  if (!send(FrameType::kPairConfirm, kControlStream, {}, now, out)) return;
  local_confirmed_ = true;
  if (peer_confirmed_) establish(true);
}

void Connection::reject_sas(Clock::time_point now, Bytes& out) {
  if (state_ != State::kAwaitConfirm) return;
  if (!send(FrameType::kPairReject, kControlStream, encode_pair_reject(ErrorCode::kPairingRejected),
            now, out)) {
    return;
  }
  fail_keyed(ErrorCode::kPairingRejected, now, out);
}

ErrorCode Connection::send_message(std::string_view text, Clock::time_point now, Bytes& out) {
  if (state_ != State::kEstablished) return ErrorCode::kInternalError;
  if (role_ != ConnectionRole::kPrimary) return ErrorCode::kInvalidStream;
  if (!is_valid_message_text(text)) return ErrorCode::kProtocolError;
  return send(FrameType::kMsg, kMessagingStream, encode_msg(text), now, out)
             ? ErrorCode::kNoError
             : ErrorCode::kInternalError;
}

void Connection::close(ErrorCode code, Clock::time_point now, Bytes& out) {
  switch (state_) {
    case State::kHandshaking: finish(code, false, {}); return;
    case State::kAwaitConfirm:
    case State::kEstablished: fail_keyed(code, now, out); return;
    case State::kClosing:
    case State::kClosed: return;
  }
}

void Connection::on_flushed(Clock::time_point now) {
  static_cast<void>(now);
  if (state_ == State::kClosing && close_sent_) finish(close_code_, close_by_peer_, close_reason_);
}

void Connection::on_transport_lost() {
  if (state_ == State::kClosed) return;
  if (state_ == State::kClosing) {
    finish(close_code_, close_by_peer_, close_reason_);
  } else {
    finish(ErrorCode::kNoError, false, {}, true);
  }
}

// --- timers -------------------------------------------------------------------

std::optional<Clock::time_point> Connection::next_deadline() const noexcept {
  switch (state_) {
    case State::kHandshaking: return state_since_ + kHandshakeTimeout;
    case State::kAwaitConfirm:
      return std::min({state_since_ + kPairTimeout, last_send_ + kKeepaliveInterval,
                       last_recv_ + kIdleTimeout});
    case State::kEstablished:
      return std::min(last_send_ + kKeepaliveInterval, last_recv_ + kIdleTimeout);
    case State::kClosing: return state_since_ + kCloseLinger;
    case State::kClosed: return std::nullopt;
  }
  return std::nullopt;
}

void Connection::on_tick(Clock::time_point now, Bytes& out) {
  switch (state_) {
    case State::kHandshaking:
      if (now >= state_since_ + kHandshakeTimeout) finish(ErrorCode::kTimeout, false, {});
      return;
    case State::kAwaitConfirm:
      if (now >= state_since_ + kPairTimeout) {
        fail_keyed(ErrorCode::kPairingTimeout, now, out);
        return;
      }
      [[fallthrough]];
    case State::kEstablished:
      if (now >= last_recv_ + kIdleTimeout) {
        fail_keyed(ErrorCode::kTimeout, now, out);
        return;
      }
      if (now >= last_send_ + kKeepaliveInterval) {
        static_cast<void>(
            send(FrameType::kPing, kControlStream, encode_ping(next_ping_nonce_++), now, out));
      }
      return;
    case State::kClosing:
      if (now >= state_since_ + kCloseLinger) finish(close_code_, close_by_peer_, close_reason_);
      return;
    case State::kClosed: return;
  }
}

// --- helpers --------------------------------------------------------------------

bool Connection::send(FrameType type, std::uint32_t stream_id,
                      std::span<const std::uint8_t> payload, Clock::time_point now, Bytes& out) {
  if (session_->seal(now, type, stream_id, payload, out) != ErrorCode::kNoError) {
    finish(ErrorCode::kInternalError, false, {});
    return false;
  }
  last_send_ = now;
  return true;
}

void Connection::establish(bool paired) {
  state_ = State::kEstablished;
  Event e{Event::Kind::kEstablished};
  e.peer_key = *peer_key_;
  e.peer = peer_payload_;
  e.paired = paired;
  events_.push_back(std::move(e));
}

void Connection::fail_keyed(ErrorCode code, Clock::time_point now, Bytes& out) {
  // Local-only codes are never sent (§7.1); the peer sees a generic error.
  const ErrorCode wire = is_local_only(code) ? ErrorCode::kProtocolError : code;
  if (session_->seal(now, FrameType::kClose, kControlStream, encode_close(wire), out) !=
      ErrorCode::kNoError) {
    finish(code, false, {});
    return;
  }
  last_send_ = now;
  close_sent_ = true;
  enter_closing(code, false, {}, now);
}

void Connection::enter_closing(ErrorCode code, bool by_peer, std::string reason,
                               Clock::time_point now) {
  state_ = State::kClosing;
  state_since_ = now;
  close_code_ = code;
  close_by_peer_ = by_peer;
  close_reason_ = std::move(reason);
}

void Connection::finish(ErrorCode code, bool by_peer, std::string reason, bool transport_lost) {
  if (state_ == State::kClosed) return;
  state_ = State::kClosed;
  engine_.reset();
  session_.reset();
  local_ = nullptr;
  Event e{Event::Kind::kClosed};
  e.code = code;
  e.by_peer = by_peer;
  e.reason = std::move(reason);
  e.transport_lost = transport_lost;
  events_.push_back(std::move(e));
}

}  // namespace twolink::connection
