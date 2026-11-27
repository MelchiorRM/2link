// Handshake framing and engine, spec v0.1.2 §4.2-4.4, §4.8 (threat model
// H1, H5, H6, H7).

#include "twolink/handshake/engine.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "twolink/crypto/keys.hpp"
#include "twolink/crypto/noise.hpp"
#include "twolink/framing/frame_parser.hpp"
#include "twolink/handshake/sas.hpp"

namespace {

using twolink::ErrorCode;
using twolink::crypto::PublicKey;
using twolink::crypto::Role;
using twolink::crypto::StaticKeyPair;
using twolink::framing::FrameHeader;
using twolink::framing::FrameParser;
using twolink::framing::FrameType;
using twolink::framing::FrameView;
using twolink::framing::kHeaderSize;
using twolink::handshake::ConnectionRole;
using twolink::handshake::EngineConfig;
using twolink::handshake::HandshakeEngine;
using twolink::handshake::HandshakeKind;
using twolink::handshake::HandshakePayload;
using twolink::handshake::HandshakeResult;
using twolink::handshake::parse_handshake_payload;
using twolink::handshake::sas_string;

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint64_t kConnId = 0xC0FFEE0011223344ull;

struct Frame {
  FrameHeader header;
  Bytes payload;
};

std::vector<Frame> parse(const Bytes& wire) {
  std::vector<Frame> frames;
  FrameParser parser;
  EXPECT_EQ(parser.feed(wire,
                        [&](const FrameView& v) {
                          frames.push_back(
                              Frame{v.header, Bytes(v.payload.begin(), v.payload.end())});
                        }),
            twolink::framing::FrameError::kOk);
  return frames;
}

Bytes wire_of(const Frame& f) {
  Bytes out;
  EXPECT_EQ(twolink::framing::encode_frame(f.header, f.payload, out),
            twolink::framing::FrameError::kOk);
  return out;
}

EngineConfig config(HandshakeKind kind, Role role, std::string name,
                    ConnectionRole crole = ConnectionRole::kPrimary) {
  EngineConfig c;
  c.kind = kind;
  c.role = role;
  c.conn_id = role == Role::kInitiator ? kConnId : 0;
  c.local_payload = HandshakePayload{std::move(name), crole, 0u};
  return c;
}

struct Peers {
  StaticKeyPair init_key = StaticKeyPair::generate();
  StaticKeyPair resp_key = StaticKeyPair::generate();
};

// Delivers every frame in wire to e; returns the first error and collects replies.
ErrorCode deliver(HandshakeEngine& e, const Bytes& wire, Bytes& reply) {
  for (const Frame& f : parse(wire)) {
    if (const ErrorCode err = e.on_frame(f.header, f.payload, reply); err != ErrorCode::kNoError) {
      return err;
    }
  }
  return ErrorCode::kNoError;
}

// Runs the exchange to completion; returns the first error from either side.
ErrorCode run(HandshakeEngine& init, HandshakeEngine& resp, std::vector<Frame>* transcript = nullptr) {
  Bytes to_resp;
  if (const ErrorCode e = init.start(to_resp); e != ErrorCode::kNoError) return e;
  HandshakeEngine* reader = &resp;
  HandshakeEngine* writer = &init;
  Bytes pending = to_resp;
  while (!pending.empty()) {
    if (transcript) {
      for (Frame& f : parse(pending)) transcript->push_back(std::move(f));
    }
    Bytes reply;
    if (const ErrorCode e = deliver(*reader, pending, reply); e != ErrorCode::kNoError) return e;
    pending = std::move(reply);
    std::swap(reader, writer);
  }
  return ErrorCode::kNoError;
}

void expect_keys_work(HandshakeResult& a, HandshakeResult& b) {
  std::array<std::uint8_t, 4> ad{1, 2, 3, 4};
  Bytes buf{'h', 'i'};
  buf.resize(2 + twolink::crypto::kTagSize);
  ASSERT_TRUE(a.keys.send.encrypt_in_place(ad, buf, 2));
  ASSERT_TRUE(b.keys.recv.decrypt_in_place(ad, buf));
  EXPECT_EQ(buf[0], 'h');
}

// --- framing (§4.2) -----------------------------------------------------------

TEST(HandshakeFraming, ParsePayload) {
  EXPECT_FALSE(parse_handshake_payload({}));
  for (int bad : {0x00, 0x03, 0xFF}) {
    const Bytes b{static_cast<std::uint8_t>(bad), 1, 2};
    EXPECT_FALSE(parse_handshake_payload(b)) << bad;
  }
  const Bytes ok{0x02, 9, 8};
  const auto f = parse_handshake_payload(ok);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->kind, HandshakeKind::kReconnect);
  EXPECT_EQ(Bytes(f->noise_message.begin(), f->noise_message.end()), (Bytes{9, 8}));
}

// --- PAIR / XX (§4.4) ---------------------------------------------------------

TEST(HandshakeXX, CompletesAndBothSidesAgree) {
  Peers p;
  auto init = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, "alpha"),
                                      p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "beta"),
                                      p.resp_key);
  ASSERT_TRUE(init && resp);
  std::vector<Frame> transcript;
  ASSERT_EQ(run(*init, *resp, &transcript), ErrorCode::kNoError);
  ASSERT_TRUE(init->complete() && resp->complete());

  // Three frames, seq 0..2 across both directions, same conn_id and kind.
  ASSERT_EQ(transcript.size(), 3u);
  for (std::size_t i = 0; i < transcript.size(); ++i) {
    const FrameHeader& h = transcript[i].header;
    EXPECT_EQ(h.type, FrameType::kHandshake);
    EXPECT_EQ(h.stream_id, 0u);
    EXPECT_EQ(h.conn_id, kConnId);
    EXPECT_EQ(h.seq, i);
    EXPECT_EQ(transcript[i].payload[0], 0x01);
  }

  auto a = init->take_result();
  auto b = resp->take_result();
  ASSERT_TRUE(a && b);
  EXPECT_FALSE(init->take_result());
  EXPECT_TRUE(init->complete());
  EXPECT_EQ(a->conn_id, kConnId);
  EXPECT_EQ(b->conn_id, kConnId);  // adopted from the first frame
  EXPECT_EQ(a->remote_static, p.resp_key.public_key());
  EXPECT_EQ(b->remote_static, p.init_key.public_key());
  EXPECT_EQ(a->remote_payload.device_name, "beta");
  EXPECT_EQ(b->remote_payload.device_name, "alpha");
  EXPECT_EQ(a->hash, b->hash);
  EXPECT_EQ(sas_string(a->hash), sas_string(b->hash));
  expect_keys_work(*a, *b);
  expect_keys_work(*b, *a);
}

TEST(HandshakeXX, RelayAttackerSeesDifferentCodes) {  // H1 (unit level)
  // A <-> M and M <-> B are two separate handshakes: the SAS values differ.
  Peers ab;
  const StaticKeyPair m_key = StaticKeyPair::generate();
  auto a = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, "a"), ab.init_key);
  auto m_resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"), m_key);
  auto m_init = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, "a"), m_key);
  auto b = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"), ab.resp_key);
  ASSERT_TRUE(a && m_resp && m_init && b);
  ASSERT_EQ(run(*a, *m_resp), ErrorCode::kNoError);
  ASSERT_EQ(run(*m_init, *b), ErrorCode::kNoError);
  const auto ra = a->take_result();
  const auto rb = b->take_result();
  ASSERT_TRUE(ra && rb);
  EXPECT_NE(ra->hash, rb->hash);
  EXPECT_NE(ra->remote_static, ab.resp_key.public_key());  // A sees M's key, not B's
}

TEST(HandshakeXX, BulkRoleIsNotAllowedForPairing) {  // §4.3
  Peers p;
  EXPECT_FALSE(HandshakeEngine::create(
      config(HandshakeKind::kPair, Role::kInitiator, "a", ConnectionRole::kBulk), p.init_key));
}

TEST(HandshakeXX, InvalidLocalPayloadIsRejected) {
  Peers p;
  EXPECT_FALSE(HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, ""),
                                       p.init_key));
}

// Drives an XX initiator by hand with the raw Noise wrapper, so tests can send
// payloads the engine would never produce.
struct RawInitiator {
  std::optional<twolink::crypto::Handshake> hs;
  std::uint64_t seq = 0;

  explicit RawInitiator(const StaticKeyPair& key) {
    static const std::string prologue(twolink::handshake::kPrologue);
    twolink::crypto::HandshakeConfig c;
    c.pattern = twolink::crypto::Pattern::kXX;
    c.role = Role::kInitiator;
    c.prologue = std::span(reinterpret_cast<const std::uint8_t*>(prologue.data()), prologue.size());
    hs = twolink::crypto::Handshake::create(c, key);
  }

  Bytes write(const Bytes& payload) {
    std::array<std::uint8_t, 1024> msg{};
    const auto n = hs->write_message(payload, msg);
    EXPECT_TRUE(n);
    Frame f;
    f.header.type = FrameType::kHandshake;
    f.header.conn_id = kConnId;
    f.header.seq = seq++;
    f.payload.push_back(0x01);
    f.payload.insert(f.payload.end(), msg.begin(), msg.begin() + static_cast<std::ptrdiff_t>(*n));
    f.header.length = static_cast<std::uint32_t>(f.payload.size());
    return wire_of(f);
  }

  void read(const Bytes& wire) {
    const auto frames = parse(wire);
    ASSERT_EQ(frames.size(), 1u);
    std::array<std::uint8_t, 1024> out{};
    ASSERT_TRUE(hs->read_message(std::span(frames[0].payload).subspan(1), out));
    ++seq;
  }
};

TEST(HandshakeXX, NonEmptyFirstMessageIsRejected) {  // §4.3
  Peers p;
  RawInitiator raw(p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"),
                                      p.resp_key);
  ASSERT_TRUE(resp);
  Bytes reply;
  EXPECT_EQ(deliver(*resp, raw.write({'x'}), reply), ErrorCode::kProtocolError);
  EXPECT_TRUE(reply.empty());
}

TEST(HandshakeXX, PeerAnnouncingBulkInPairingIsRejected) {  // §4.3
  Peers p;
  RawInitiator raw(p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"),
                                      p.resp_key);
  ASSERT_TRUE(resp);
  Bytes msg2;
  ASSERT_EQ(deliver(*resp, raw.write({}), msg2), ErrorCode::kNoError);
  raw.read(msg2);
  Bytes tlv;
  ASSERT_EQ(encode_payload(HandshakePayload{"a", ConnectionRole::kBulk, {}}, tlv),
            twolink::handshake::PayloadError::kOk);
  Bytes reply;
  EXPECT_EQ(deliver(*resp, raw.write(tlv), reply), ErrorCode::kProtocolError);
  EXPECT_FALSE(resp->complete());
}

TEST(HandshakeXX, GarbageTlvIsRejected) {  // H7
  Peers p;
  RawInitiator raw(p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"),
                                      p.resp_key);
  ASSERT_TRUE(resp);
  Bytes msg2;
  ASSERT_EQ(deliver(*resp, raw.write({}), msg2), ErrorCode::kNoError);
  raw.read(msg2);
  Bytes reply;
  EXPECT_EQ(deliver(*resp, raw.write({0x80, 0, 0}), reply), ErrorCode::kProtocolError);
}

// --- RECONNECT / IK (§4.8) ----------------------------------------------------

TEST(HandshakeIK, CompletesWithTrustedPeer) {
  Peers p;
  auto ic = config(HandshakeKind::kReconnect, Role::kInitiator, "alpha", ConnectionRole::kBulk);
  ic.remote_static = p.resp_key.public_key();
  auto rc = config(HandshakeKind::kReconnect, Role::kResponder, "beta", ConnectionRole::kBulk);
  int checks = 0;
  rc.check_remote = [&](const PublicKey& k) {
    ++checks;
    return k == p.init_key.public_key();
  };
  auto init = HandshakeEngine::create(ic, p.init_key);
  auto resp = HandshakeEngine::create(rc, p.resp_key);
  ASSERT_TRUE(init && resp);
  std::vector<Frame> transcript;
  ASSERT_EQ(run(*init, *resp, &transcript), ErrorCode::kNoError);
  EXPECT_EQ(checks, 1);
  ASSERT_EQ(transcript.size(), 2u);
  EXPECT_EQ(transcript[0].payload[0], 0x02);
  auto a = init->take_result();
  auto b = resp->take_result();
  ASSERT_TRUE(a && b);
  EXPECT_EQ(b->remote_payload.role, ConnectionRole::kBulk);
  EXPECT_EQ(a->remote_payload.device_name, "beta");
  expect_keys_work(*a, *b);
}

TEST(HandshakeIK, UntrustedInitiatorIsRefusedSilently) {  // H5, H6
  Peers p;
  auto ic = config(HandshakeKind::kReconnect, Role::kInitiator, "alpha");
  ic.remote_static = p.resp_key.public_key();
  auto rc = config(HandshakeKind::kReconnect, Role::kResponder, "beta");
  rc.check_remote = [](const PublicKey&) { return false; };
  auto init = HandshakeEngine::create(ic, p.init_key);
  auto resp = HandshakeEngine::create(rc, p.resp_key);
  ASSERT_TRUE(init && resp);
  Bytes msg1;
  ASSERT_EQ(init->start(msg1), ErrorCode::kNoError);
  Bytes reply;
  EXPECT_EQ(deliver(*resp, msg1, reply), ErrorCode::kUnknownPeer);
  EXPECT_TRUE(reply.empty());  // nothing goes on the wire
  EXPECT_FALSE(resp->complete());
}

TEST(HandshakeIK, ChangedResponderKeyFailsOnResponder) {  // §4.8
  Peers p;
  auto ic = config(HandshakeKind::kReconnect, Role::kInitiator, "alpha");
  ic.remote_static = StaticKeyPair::generate().public_key();  // stale pin
  auto init = HandshakeEngine::create(ic, p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kReconnect, Role::kResponder, "beta"),
                                      p.resp_key);
  ASSERT_TRUE(init && resp);
  Bytes msg1;
  ASSERT_EQ(init->start(msg1), ErrorCode::kNoError);
  Bytes reply;
  EXPECT_EQ(deliver(*resp, msg1, reply), ErrorCode::kHandshakeFailed);
  EXPECT_TRUE(reply.empty());
}

TEST(HandshakeIK, InitiatorNeedsPinnedKey) {
  Peers p;
  EXPECT_FALSE(HandshakeEngine::create(
      config(HandshakeKind::kReconnect, Role::kInitiator, "alpha"), p.init_key));
}

// --- frame checks (H6, H7) ----------------------------------------------------

struct Started {
  Peers p;
  std::optional<HandshakeEngine> init;
  std::optional<HandshakeEngine> resp;
  Frame msg1;
};

Started started_xx() {
  Started s;
  s.init = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, "a"), s.p.init_key);
  s.resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"), s.p.resp_key);
  Bytes wire;
  EXPECT_EQ(s.init->start(wire), ErrorCode::kNoError);
  s.msg1 = parse(wire).at(0);
  return s;
}

ErrorCode feed(HandshakeEngine& e, const Frame& f, Bytes& reply) {
  return e.on_frame(f.header, f.payload, reply);
}

TEST(HandshakeChecks, KindMismatchOnFirstFrame) {  // H7
  Started s = started_xx();
  s.msg1.payload[0] = 0x02;
  auto resp = HandshakeEngine::create(
      config(HandshakeKind::kPair, Role::kResponder, "b"), s.p.resp_key);
  Bytes reply;
  EXPECT_EQ(feed(*resp, s.msg1, reply), ErrorCode::kProtocolError);
  EXPECT_TRUE(reply.empty());
}

TEST(HandshakeChecks, KindChangedMidHandshake) {  // H7
  Started s = started_xx();
  Bytes msg2;
  ASSERT_EQ(feed(*s.resp, s.msg1, msg2), ErrorCode::kNoError);
  Frame f = parse(msg2).at(0);
  f.payload[0] = 0x02;
  Bytes reply;
  EXPECT_EQ(feed(*s.init, f, reply), ErrorCode::kProtocolError);
  EXPECT_TRUE(reply.empty());
}

TEST(HandshakeChecks, WrongSeqConnIdOrTypeIsRejected) {
  {
    Started s = started_xx();
    s.msg1.header.seq = 1;
    Bytes reply;
    EXPECT_EQ(feed(*s.resp, s.msg1, reply), ErrorCode::kProtocolError);
    EXPECT_TRUE(reply.empty());
  }
  {
    Started s = started_xx();
    Bytes msg2;
    ASSERT_EQ(feed(*s.resp, s.msg1, msg2), ErrorCode::kNoError);
    Frame f = parse(msg2).at(0);
    f.header.conn_id ^= 1;
    Bytes reply;
    EXPECT_EQ(feed(*s.init, f, reply), ErrorCode::kProtocolError);
    EXPECT_TRUE(reply.empty());
  }
  {
    Started s = started_xx();
    Frame ping;
    ping.header.type = FrameType::kPing;
    ping.header.conn_id = kConnId;
    ping.header.length = 24;
    ping.payload.assign(24, 0);
    Bytes reply;
    EXPECT_EQ(feed(*s.resp, ping, reply), ErrorCode::kProtocolError);
  }
}

TEST(HandshakeChecks, TamperedNoiseMessageFailsWithoutReply) {  // H6
  Started s = started_xx();
  Bytes msg2;
  ASSERT_EQ(feed(*s.resp, s.msg1, msg2), ErrorCode::kNoError);
  Frame f = parse(msg2).at(0);
  f.payload.back() ^= 1;
  Bytes reply;
  EXPECT_EQ(feed(*s.init, f, reply), ErrorCode::kHandshakeFailed);
  EXPECT_TRUE(reply.empty());
  EXPECT_EQ(feed(*s.init, f, reply), ErrorCode::kHandshakeFailed);  // sticky
}

TEST(HandshakeChecks, ReplayedFrameIsRejected) {
  Started s = started_xx();
  Bytes msg2;
  ASSERT_EQ(feed(*s.resp, s.msg1, msg2), ErrorCode::kNoError);
  Bytes reply;
  EXPECT_EQ(feed(*s.resp, s.msg1, reply), ErrorCode::kProtocolError);
  EXPECT_TRUE(reply.empty());
}

TEST(HandshakeChecks, FrameAfterCompletionIsRejected) {
  Peers p;
  auto init = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kInitiator, "a"), p.init_key);
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"), p.resp_key);
  std::vector<Frame> t;
  ASSERT_EQ(run(*init, *resp, &t), ErrorCode::kNoError);
  Bytes reply;
  Frame extra = t.back();
  extra.header.seq = 3;
  EXPECT_EQ(feed(*resp, extra, reply), ErrorCode::kProtocolError);
}

TEST(HandshakeChecks, ResponderCannotStart) {
  Peers p;
  auto resp = HandshakeEngine::create(config(HandshakeKind::kPair, Role::kResponder, "b"), p.resp_key);
  Bytes out;
  EXPECT_EQ(resp->start(out), ErrorCode::kInternalError);
  EXPECT_TRUE(out.empty());
}

}  // namespace
