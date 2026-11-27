#include "twolink/handshake/engine.hpp"

#include <utility>

namespace twolink::handshake {

using crypto::HandshakeAction;
using framing::FrameError;
using framing::FrameHeader;
using framing::FrameType;
using framing::kHeaderSize;

std::optional<HandshakeFrame> parse_handshake_payload(
    std::span<const std::uint8_t> payload) noexcept {
  if (payload.empty()) return std::nullopt;
  const std::uint8_t kind = payload[0];
  if (kind != static_cast<std::uint8_t>(HandshakeKind::kPair) &&
      kind != static_cast<std::uint8_t>(HandshakeKind::kReconnect)) {
    return std::nullopt;
  }
  return HandshakeFrame{static_cast<HandshakeKind>(kind), payload.subspan(1)};
}

std::optional<HandshakeEngine> HandshakeEngine::create(EngineConfig config,
                                                       const crypto::StaticKeyPair& local) {
  std::vector<std::uint8_t> probe;
  if (encode_payload(config.local_payload, probe) != PayloadError::kOk) return std::nullopt;
  if (config.kind == HandshakeKind::kPair && config.local_payload.role == ConnectionRole::kBulk) {
    return std::nullopt;  // §4.3: bulk connections only reconnect
  }
  const bool ik = config.kind == HandshakeKind::kReconnect;
  if (ik && config.role == crypto::Role::kInitiator && !config.remote_static) return std::nullopt;

  const auto* prologue = reinterpret_cast<const std::uint8_t*>(kPrologue.data());
  crypto::HandshakeConfig nc;
  nc.pattern = ik ? crypto::Pattern::kIK : crypto::Pattern::kXX;
  nc.role = config.role;
  nc.prologue = std::span(prologue, kPrologue.size());
  if (ik && config.role == crypto::Role::kInitiator) nc.remote_static = config.remote_static;

  auto noise = crypto::Handshake::create(nc, local);
  if (!noise) return std::nullopt;
  return HandshakeEngine(std::move(config), std::move(*noise));
}

HandshakeEngine::HandshakeEngine(EngineConfig config, crypto::Handshake noise) noexcept
    : config_(std::move(config)),
      noise_(std::move(noise)),
      have_conn_id_(config_.role == crypto::Role::kInitiator) {}

ErrorCode HandshakeEngine::fail(ErrorCode code) noexcept {
  if (error_ == ErrorCode::kNoError) error_ = code;
  return error_;
}

bool HandshakeEngine::carries_payload(std::uint64_t index) const noexcept {
  // §4.3: XX message 1 is empty; every other message carries the TLV list.
  return config_.kind == HandshakeKind::kReconnect || index != 0;
}

ErrorCode HandshakeEngine::start(std::vector<std::uint8_t>& out) {
  if (failed()) return error_;
  if (config_.role != crypto::Role::kInitiator || next_seq_ != 0) {
    return fail(ErrorCode::kInternalError);
  }
  return write_next(out);
}

ErrorCode HandshakeEngine::write_next(std::vector<std::uint8_t>& out) {
  if (noise_.action() != HandshakeAction::kWriteMessage) return fail(ErrorCode::kInternalError);

  std::vector<std::uint8_t> payload;
  if (carries_payload(next_seq_) &&
      encode_payload(config_.local_payload, payload) != PayloadError::kOk) {
    return fail(ErrorCode::kInternalError);
  }

  std::vector<std::uint8_t> message(kMaxNoiseMessage);
  const auto n = noise_.write_message(payload, message);
  if (!n) return fail(ErrorCode::kHandshakeFailed);

  FrameHeader header;
  header.type = FrameType::kHandshake;
  header.stream_id = framing::kControlStream;
  header.conn_id = config_.conn_id;
  header.seq = next_seq_;
  header.length = static_cast<std::uint32_t>(1 + *n);

  const std::size_t start = out.size();
  out.resize(start + kHeaderSize);
  if (framing::encode_header(header, std::span(out).subspan(start).first<kHeaderSize>()) !=
      FrameError::kOk) {
    out.resize(start);
    return fail(ErrorCode::kInternalError);
  }
  out.push_back(static_cast<std::uint8_t>(config_.kind));
  out.insert(out.end(), message.begin(), message.begin() + static_cast<std::ptrdiff_t>(*n));
  ++next_seq_;

  if (const ErrorCode e = finish_if_ready(); e != ErrorCode::kNoError) {
    out.resize(start);
    return e;
  }
  return ErrorCode::kNoError;
}

ErrorCode HandshakeEngine::check_remote_once() {
  if (remote_checked_) return ErrorCode::kNoError;
  const auto remote = noise_.remote_static();
  if (!remote) return ErrorCode::kNoError;  // not authenticated yet
  remote_checked_ = true;
  if (config_.check_remote && !config_.check_remote(*remote)) {
    return fail(ErrorCode::kUnknownPeer);
  }
  return ErrorCode::kNoError;
}

ErrorCode HandshakeEngine::finish_if_ready() {
  if (noise_.action() != HandshakeAction::kSplit) return ErrorCode::kNoError;
  if (const ErrorCode e = check_remote_once(); e != ErrorCode::kNoError) return e;
  const auto remote = noise_.remote_static();
  const auto hash = noise_.handshake_hash();
  if (!remote || !hash) return fail(ErrorCode::kHandshakeFailed);
  if (!remote_payload_) return fail(ErrorCode::kProtocolError);
  auto keys = noise_.split();
  if (!keys) return fail(ErrorCode::kHandshakeFailed);
  result_ = HandshakeResult{config_.conn_id, *remote, std::move(*remote_payload_), *hash,
                            std::move(*keys)};
  return ErrorCode::kNoError;
}

ErrorCode HandshakeEngine::on_frame(const FrameHeader& header,
                                    std::span<const std::uint8_t> payload,
                                    std::vector<std::uint8_t>& out) {
  if (failed()) return error_;
  if (result_ || result_taken_) return fail(ErrorCode::kProtocolError);  // after completion

  if (header.type != FrameType::kHandshake || header.stream_id != framing::kControlStream ||
      header.length != payload.size()) {
    return fail(ErrorCode::kProtocolError);
  }
  if (!have_conn_id_) {
    config_.conn_id = header.conn_id;  // responder: the initiator picks it (§2.3)
    have_conn_id_ = true;
  } else if (header.conn_id != config_.conn_id) {
    return fail(ErrorCode::kProtocolError);
  }
  if (header.seq != next_seq_) return fail(ErrorCode::kProtocolError);

  const auto frame = parse_handshake_payload(payload);
  if (!frame || frame->kind != config_.kind) return fail(ErrorCode::kProtocolError);  // H7
  if (noise_.action() != HandshakeAction::kReadMessage) return fail(ErrorCode::kProtocolError);

  const std::uint64_t index = next_seq_;
  std::vector<std::uint8_t> plain(kMaxNoiseMessage);
  const auto n = noise_.read_message(frame->noise_message, plain);
  if (!n) return fail(ErrorCode::kHandshakeFailed);
  ++next_seq_;

  if (const ErrorCode e = check_remote_once(); e != ErrorCode::kNoError) return e;

  const std::span<const std::uint8_t> body = std::span(plain).first(*n);
  if (carries_payload(index)) {
    HandshakePayload remote;
    if (decode_payload(body, remote) != PayloadError::kOk) return fail(ErrorCode::kProtocolError);
    if (config_.kind == HandshakeKind::kPair && remote.role == ConnectionRole::kBulk) {
      return fail(ErrorCode::kProtocolError);
    }
    remote_payload_ = std::move(remote);
  } else if (!body.empty()) {
    return fail(ErrorCode::kProtocolError);  // XX message 1 carries nothing
  }

  if (noise_.action() == HandshakeAction::kWriteMessage) return write_next(out);
  return finish_if_ready();
}

std::optional<HandshakeResult> HandshakeEngine::take_result() noexcept {
  if (!result_) return std::nullopt;
  std::optional<HandshakeResult> r = std::move(result_);
  result_.reset();
  result_taken_ = true;
  return r;
}

}  // namespace twolink::handshake
