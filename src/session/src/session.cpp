#include "twolink/session/session.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include <sodium.h>

namespace twolink::session {

using framing::FrameError;
using framing::FrameHeader;
using framing::FrameType;
using framing::kAeadTagSize;
using framing::kHeaderSize;

std::optional<Session> Session::create(crypto::Handshake::Keys keys, std::uint64_t conn_id,
                                       Clock::time_point now, RekeyPolicy policy) {
  if (!keys.send.usable() || !keys.recv.usable()) return std::nullopt;
  if (policy.max_frames < 2) return std::nullopt;  // room for one frame and REKEY
  return Session(std::move(keys), conn_id, now, policy);
}

Session::Session(crypto::Handshake::Keys keys, std::uint64_t conn_id, Clock::time_point now,
                 RekeyPolicy policy) noexcept
    : send_(std::move(keys.send)),
      recv_(std::move(keys.recv)),
      conn_id_(conn_id),
      policy_(policy),
      send_key_first_seq_(send_.nonce()),
      send_key_since_(now) {}

ErrorCode Session::fail_send(ErrorCode code) noexcept {
  if (send_error_ == ErrorCode::kNoError) send_error_ = code;
  if (error_ == ErrorCode::kNoError) error_ = code;
  return send_error_;
}

ErrorCode Session::fail_recv(ErrorCode code) noexcept {
  if (recv_error_ == ErrorCode::kNoError) recv_error_ = code;
  if (error_ == ErrorCode::kNoError) error_ = code;
  return recv_error_;
}

bool Session::rekey_due(Clock::time_point now) const noexcept {
  // The REKEY frame itself goes out under the old key, so it is due when the
  // next frame would be the last one that key may encrypt.
  return send_.nonce() - send_key_first_seq_ + 1 >= policy_.max_frames ||
         now - send_key_since_ >= policy_.max_age;
}

ErrorCode Session::seal(Clock::time_point now, FrameType type, std::uint32_t stream_id,
                        std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& out) {
  if (send_error_ != ErrorCode::kNoError) return send_error_;
  if (recv_error_ != ErrorCode::kNoError && type != FrameType::kClose) return recv_error_;

  // Argument checks first, so a rejected call changes nothing.
  if (!framing::is_encrypted(type) || plaintext.size() > kMaxPlaintext) {
    return ErrorCode::kProtocolError;
  }
  FrameHeader probe;
  probe.type = type;
  probe.stream_id = stream_id;
  probe.conn_id = conn_id_;
  probe.length = static_cast<std::uint32_t>(plaintext.size() + kAeadTagSize);
  if (framing::validate_header(probe) != FrameError::kOk) return ErrorCode::kProtocolError;

  if (type == FrameType::kRekey) {
    if (!plaintext.empty()) return ErrorCode::kProtocolError;
    return rekey_send(now, out);
  }

  const std::size_t start = out.size();
  if (rekey_due(now)) {
    if (const ErrorCode e = rekey_send(now, out); e != ErrorCode::kNoError) return e;
  }
  if (const ErrorCode e = seal_one(type, stream_id, plaintext, out); e != ErrorCode::kNoError) {
    out.resize(start);
    return e;
  }
  return ErrorCode::kNoError;
}

ErrorCode Session::send_rekey(Clock::time_point now, std::vector<std::uint8_t>& out) {
  if (send_error_ != ErrorCode::kNoError) return send_error_;
  if (recv_error_ != ErrorCode::kNoError) return recv_error_;
  return rekey_send(now, out);
}

ErrorCode Session::rekey_send(Clock::time_point now, std::vector<std::uint8_t>& out) {
  // §5.4: REKEY goes out under the old key, then the key is replaced.
  const std::size_t start = out.size();
  if (const ErrorCode e = seal_one(FrameType::kRekey, framing::kControlStream, {}, out);
      e != ErrorCode::kNoError) {
    return e;
  }
  if (!send_.rekey()) {
    out.resize(start);
    return fail_send(ErrorCode::kInternalError);
  }
  send_key_first_seq_ = send_.nonce();
  send_key_since_ = now;
  return ErrorCode::kNoError;
}

ErrorCode Session::seal_one(FrameType type, std::uint32_t stream_id,
                            std::span<const std::uint8_t> plaintext,
                            std::vector<std::uint8_t>& out) {
  const std::uint64_t seq = send_.nonce();
  if (!seq_allows(seq, type)) return fail_send(ErrorCode::kInternalError);

  FrameHeader header;
  header.type = type;
  header.stream_id = stream_id;
  header.conn_id = conn_id_;
  header.seq = seq;  // §5.2: seq is the sending counter, never chosen separately
  header.length = static_cast<std::uint32_t>(plaintext.size() + kAeadTagSize);

  const std::size_t start = out.size();
  out.resize(start + kHeaderSize + header.length);
  const std::span<std::uint8_t> frame = std::span(out).subspan(start);
  const auto head = frame.first<kHeaderSize>();
  const auto body = frame.subspan(kHeaderSize);

  if (framing::encode_header(header, head) != FrameError::kOk) {
    out.resize(start);
    return ErrorCode::kProtocolError;
  }
  std::copy(plaintext.begin(), plaintext.end(), body.begin());
  if (!send_.encrypt_in_place(head, body, plaintext.size())) {
    out.resize(start);
    return fail_send(ErrorCode::kInternalError);
  }
  return ErrorCode::kNoError;
}

ErrorCode Session::open(const FrameHeader& header, std::span<const std::uint8_t> payload,
                        std::vector<std::uint8_t>& plaintext) {
  plaintext.clear();
  if (recv_error_ != ErrorCode::kNoError) return recv_error_;

  if (!framing::is_encrypted(header.type) || header.length != payload.size()) {
    return fail_recv(ErrorCode::kProtocolError);
  }
  // The parser has validated the header; checking again keeps open() safe on
  // its own and gives the exact bytes that were authenticated.
  std::array<std::uint8_t, kHeaderSize> ad{};
  if (const FrameError e = framing::encode_header(header, ad); e != FrameError::kOk) {
    return fail_recv(framing::to_error_code(e));
  }
  if (header.conn_id != conn_id_) return fail_recv(ErrorCode::kProtocolError);  // §2.3, S5
  if (header.seq != recv_.nonce()) return fail_recv(ErrorCode::kReplayDetected);  // §5.3, S3

  plaintext.assign(payload.begin(), payload.end());
  if (!recv_.decrypt_in_place(ad, plaintext)) {
    sodium_memzero(plaintext.data(), plaintext.size());
    plaintext.clear();
    return fail_recv(ErrorCode::kDecryptFailed);
  }
  plaintext.resize(plaintext.size() - kAeadTagSize);

  if (header.type == FrameType::kRekey) {
    if (!plaintext.empty()) return fail_recv(ErrorCode::kProtocolError);
    if (!recv_.rekey()) return fail_recv(ErrorCode::kInternalError);
  }
  return ErrorCode::kNoError;
}

}  // namespace twolink::session
