// Session layer, spec v0.1.2 §5 (threat model S2–S5).

#include "twolink/session/session.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "twolink/crypto/keys.hpp"
#include "twolink/crypto/noise.hpp"
#include "twolink/framing/frame.hpp"
#include "twolink/framing/frame_parser.hpp"

namespace {

using twolink::ErrorCode;
using twolink::crypto::CipherState;
using twolink::crypto::Handshake;
using twolink::crypto::HandshakeAction;
using twolink::crypto::HandshakeConfig;
using twolink::crypto::kKeySize;
using twolink::crypto::Pattern;
using twolink::crypto::Role;
using twolink::crypto::StaticKeyPair;
using twolink::framing::FrameHeader;
using twolink::framing::FrameParser;
using twolink::framing::FrameType;
using twolink::framing::FrameView;
using twolink::framing::kAeadTagSize;
using twolink::framing::kControlStream;
using twolink::framing::kHeaderSize;
using twolink::framing::kMessagingStream;
using twolink::session::Clock;
using twolink::session::kMaxPlaintext;
using twolink::session::kRekeyInterval;
using twolink::session::RekeyPolicy;
using twolink::session::Session;

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint64_t kConnId = 0x0123456789ABCDEFull;
const Clock::time_point kT0{};  // fake clock: tests pass time explicitly

Bytes text(std::string_view s) { return Bytes(s.begin(), s.end()); }

std::array<std::uint8_t, kKeySize> filled(std::uint8_t v) {
  std::array<std::uint8_t, kKeySize> a{};
  a.fill(v);
  return a;
}

struct RawKeys {
  Handshake::Keys init;
  Handshake::Keys resp;
};

// Runs an XX handshake. deterministic fixes every key, so two calls give the
// same session keys (lets tamper tests start from a fresh receiver each time).
RawKeys handshake(bool deterministic = false) {
  static const Bytes prologue = text("2LINK/1");
  const StaticKeyPair ik =
      deterministic ? StaticKeyPair::from_private_key(filled(1)) : StaticKeyPair::generate();
  const StaticKeyPair rk =
      deterministic ? StaticKeyPair::from_private_key(filled(2)) : StaticKeyPair::generate();
  HandshakeConfig ic{Pattern::kXX, Role::kInitiator, prologue, std::nullopt, std::nullopt};
  HandshakeConfig rc{Pattern::kXX, Role::kResponder, prologue, std::nullopt, std::nullopt};
  if (deterministic) {
    ic.fixed_ephemeral_for_testing = filled(3);
    rc.fixed_ephemeral_for_testing = filled(4);
  }
  auto init = Handshake::create(ic, ik);
  auto resp = Handshake::create(rc, rk);
  EXPECT_TRUE(init && resp);

  std::array<std::uint8_t, 1024> msg{};
  std::array<std::uint8_t, 1024> payload{};
  Handshake* writer = &*init;
  Handshake* reader = &*resp;
  while (writer->action() == HandshakeAction::kWriteMessage) {
    const auto n = writer->write_message({}, msg);
    EXPECT_TRUE(n.has_value());
    EXPECT_TRUE(reader->read_message(std::span(msg).first(*n), payload).has_value());
    std::swap(writer, reader);
  }
  auto ikeys = init->split();
  auto rkeys = resp->split();
  EXPECT_TRUE(ikeys && rkeys);
  return RawKeys{std::move(*ikeys), std::move(*rkeys)};
}

struct Pair {
  Session a;  // initiator
  Session b;  // responder
};

Pair make_pair(RekeyPolicy policy = {}, bool deterministic = false) {
  RawKeys k = handshake(deterministic);
  auto a = Session::create(std::move(k.init), kConnId, kT0, policy);
  auto b = Session::create(std::move(k.resp), kConnId, kT0, policy);
  EXPECT_TRUE(a && b);
  return Pair{std::move(*a), std::move(*b)};
}

struct Frame {
  FrameHeader header;
  Bytes payload;
};

// Splits wire bytes into frames with the real parser.
std::vector<Frame> parse(const Bytes& wire) {
  std::vector<Frame> frames;
  FrameParser parser;
  const auto err = parser.feed(wire, [&](const FrameView& v) {
    frames.push_back(Frame{v.header, Bytes(v.payload.begin(), v.payload.end())});
  });
  EXPECT_EQ(err, twolink::framing::FrameError::kOk);
  EXPECT_EQ(parser.buffered(), 0u);
  return frames;
}

Frame seal_msg(Session& s, const Bytes& plaintext, Clock::time_point now = kT0) {
  Bytes wire;
  EXPECT_EQ(s.seal(now, FrameType::kMsg, kMessagingStream, plaintext, wire), ErrorCode::kNoError);
  auto frames = parse(wire);
  EXPECT_EQ(frames.size(), 1u);
  return frames.empty() ? Frame{} : frames.front();
}

ErrorCode open(Session& s, const Frame& f, Bytes* plaintext = nullptr) {
  Bytes out;
  const ErrorCode e = s.open(f.header, f.payload, out);
  if (plaintext) *plaintext = out;
  return e;
}

// --- round trip and seq (S4) --------------------------------------------------

TEST(Session, CreateRejectsUnusableKeys) {
  RawKeys k = handshake();
  CipherState taken = std::move(k.init.send);  // leaves k.init.send empty
  EXPECT_FALSE(Session::create(std::move(k.init), kConnId, kT0));
}

TEST(Session, CreateRejectsRekeyFramesBelowTwo) {
  RawKeys k = handshake();
  EXPECT_FALSE(Session::create(std::move(k.init), kConnId, kT0, RekeyPolicy{1, kRekeyInterval}));
}

TEST(Session, RoundTripBothDirections) {
  Pair p = make_pair();
  for (int i = 0; i < 3; ++i) {
    const Bytes msg = text("hello " + std::to_string(i));
    Bytes got;
    ASSERT_EQ(open(p.b, seal_msg(p.a, msg), &got), ErrorCode::kNoError);
    EXPECT_EQ(got, msg);
    ASSERT_EQ(open(p.a, seal_msg(p.b, msg), &got), ErrorCode::kNoError);
    EXPECT_EQ(got, msg);
  }
}

TEST(Session, FrameLayoutFollowsSpec) {  // §5.2
  Pair p = make_pair();
  const Bytes msg = text("abc");
  const Frame f = seal_msg(p.a, msg);
  EXPECT_EQ(f.header.type, FrameType::kMsg);
  EXPECT_EQ(f.header.stream_id, kMessagingStream);
  EXPECT_EQ(f.header.conn_id, kConnId);
  EXPECT_EQ(f.header.seq, 0u);
  EXPECT_EQ(f.header.length, msg.size() + kAeadTagSize);
  EXPECT_EQ(f.payload.size(), f.header.length);
}

TEST(Session, SeqEqualsBothCountersForEveryFrame) {  // S4
  Pair p = make_pair(RekeyPolicy{5, std::chrono::hours(1)});
  for (std::uint64_t i = 0; i < 40; ++i) {
    const std::uint64_t sender_counter = p.a.next_send_seq();
    const std::uint64_t receiver_counter = p.b.next_recv_seq();
    Bytes wire;
    ASSERT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, text("x"), wire),
              ErrorCode::kNoError);
    std::uint64_t expected = sender_counter;
    for (const Frame& f : parse(wire)) {  // a REKEY may come first
      EXPECT_EQ(f.header.seq, expected);
      EXPECT_EQ(p.b.next_recv_seq(), f.header.seq);
      ASSERT_EQ(open(p.b, f), ErrorCode::kNoError);
      ++expected;
    }
    EXPECT_EQ(receiver_counter, sender_counter);
    EXPECT_EQ(p.a.next_send_seq(), p.b.next_recv_seq());
  }
  EXPECT_GE(p.a.next_send_seq(), 40u);  // rekeys took seq values; nothing reset
}

TEST(Session, LargestPlaintextFits) {  // §2.1
  Pair p = make_pair();
  const Bytes big(kMaxPlaintext, 0x5A);
  Bytes got;
  ASSERT_EQ(open(p.b, seal_msg(p.a, big), &got), ErrorCode::kNoError);
  EXPECT_EQ(got, big);
}

TEST(Session, EmptyPlaintextRoundTrips) {
  Pair p = make_pair();
  Bytes wire;
  ASSERT_EQ(p.a.seal(kT0, FrameType::kPairConfirm, kControlStream, {}, wire), ErrorCode::kNoError);
  const auto frames = parse(wire);
  ASSERT_EQ(frames.size(), 1u);
  Bytes got = text("junk");
  EXPECT_EQ(open(p.b, frames[0], &got), ErrorCode::kNoError);
  EXPECT_TRUE(got.empty());
}

// --- seal argument checks (not sticky) ---------------------------------------

TEST(SessionSeal, RejectsBadArgumentsWithoutSideEffects) {
  Pair p = make_pair();
  Bytes wire = text("keep");
  const Bytes too_big(kMaxPlaintext + 1, 0);
  EXPECT_EQ(p.a.seal(kT0, FrameType::kHandshake, kControlStream, {}, wire),
            ErrorCode::kProtocolError);
  EXPECT_EQ(p.a.seal(kT0, FrameType::kMsg, kControlStream, text("x"), wire),
            ErrorCode::kProtocolError);  // MSG belongs on stream 1
  EXPECT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, too_big, wire),
            ErrorCode::kProtocolError);
  EXPECT_EQ(p.a.seal(kT0, FrameType::kRekey, kControlStream, text("x"), wire),
            ErrorCode::kProtocolError);
  EXPECT_EQ(wire, text("keep"));
  EXPECT_EQ(p.a.next_send_seq(), 0u);
  EXPECT_FALSE(p.a.failed());
  ASSERT_EQ(open(p.b, seal_msg(p.a, text("still fine"))), ErrorCode::kNoError);
}

TEST(SessionSeal, AppendsToExistingOutput) {
  Pair p = make_pair();
  Bytes wire;
  ASSERT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, text("one"), wire),
            ErrorCode::kNoError);
  ASSERT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, text("two"), wire),
            ErrorCode::kNoError);
  const auto frames = parse(wire);
  ASSERT_EQ(frames.size(), 2u);
  Bytes got;
  ASSERT_EQ(open(p.b, frames[0], &got), ErrorCode::kNoError);
  EXPECT_EQ(got, text("one"));
  ASSERT_EQ(open(p.b, frames[1], &got), ErrorCode::kNoError);
  EXPECT_EQ(got, text("two"));
}

TEST(SessionSeal, SeqLimitKeepsLastValueForClose) {  // §5.3
  using twolink::session::kLastSeq;
  using twolink::session::seq_allows;
  static_assert(seq_allows(0, FrameType::kMsg));
  static_assert(seq_allows(kLastSeq - 1, FrameType::kRekey));
  static_assert(!seq_allows(kLastSeq, FrameType::kMsg));
  static_assert(seq_allows(kLastSeq, FrameType::kClose));
  static_assert(!seq_allows(UINT64_MAX, FrameType::kClose));  // reserved by Noise
}

// --- tampering (S2) -----------------------------------------------------------

// Flips every bit of a sealed frame and opens it on a fresh receiver with the
// same keys. Nothing may be accepted. Flips that leave conn_id, seq and length
// alone reach the AEAD and must fail there; the others are caught earlier.
TEST(SessionTamper, EveryBitFlipIsRejected) {
  Bytes wire;
  {
    Pair p = make_pair({}, true);
    ASSERT_EQ(p.a.seal(kT0, FrameType::kPing, kControlStream, text("12345678"), wire),
              ErrorCode::kNoError);
  }
  const FrameHeader original = parse(wire).at(0).header;

  int reached_aead = 0;
  for (std::size_t byte = 0; byte < wire.size(); ++byte) {
    for (int bit = 0; bit < 8; ++bit) {
      Bytes bad = wire;
      bad[byte] = static_cast<std::uint8_t>(bad[byte] ^ (1u << bit));

      FrameHeader h;
      if (twolink::framing::decode_header(bad, h) != twolink::framing::FrameError::kOk) {
        continue;  // the parser rejects it before the session sees it
      }
      const std::span<const std::uint8_t> payload =
          std::span<const std::uint8_t>(bad).subspan(kHeaderSize);

      Pair fresh = make_pair({}, true);
      Bytes got;
      const ErrorCode e = fresh.b.open(h, payload, got);
      SCOPED_TRACE(::testing::Message() << "byte " << byte << " bit " << bit);
      EXPECT_NE(e, ErrorCode::kNoError);
      EXPECT_TRUE(got.empty());
      EXPECT_TRUE(fresh.b.failed());
      if (h.conn_id == original.conn_id && h.seq == original.seq &&
          h.length == original.length) {
        EXPECT_EQ(e, ErrorCode::kDecryptFailed);
        ++reached_aead;
      }
    }
  }
  // Type/stream variants that stay valid plus every payload bit.
  EXPECT_GE(reached_aead, static_cast<int>(8 * (wire.size() - kHeaderSize)));
}

TEST(SessionTamper, ChangingTypeWithinTheStreamFailsDecryption) {
  Pair p = make_pair();
  Frame f = seal_msg(p.a, text("hi"));
  f.header.type = FrameType::kMsgAck;
  EXPECT_EQ(open(p.b, f), ErrorCode::kDecryptFailed);
}

TEST(SessionTamper, LengthNotMatchingPayloadIsRejected) {
  Pair p = make_pair();
  Frame f = seal_msg(p.a, text("hi"));
  f.payload.push_back(0);
  EXPECT_EQ(open(p.b, f), ErrorCode::kProtocolError);
}

TEST(SessionTamper, HandshakeFrameIsRejected) {
  Pair p = make_pair();
  FrameHeader h;
  h.type = FrameType::kHandshake;
  h.conn_id = kConnId;
  h.length = 1;
  Bytes got;
  EXPECT_EQ(p.b.open(h, Bytes{0}, got), ErrorCode::kProtocolError);
}

// --- replay (S3) --------------------------------------------------------------

TEST(SessionReplay, DuplicateIsFatal) {
  Pair p = make_pair();
  const Frame f = seal_msg(p.a, text("once"));
  ASSERT_EQ(open(p.b, f), ErrorCode::kNoError);
  EXPECT_EQ(open(p.b, f), ErrorCode::kReplayDetected);
}

TEST(SessionReplay, GapIsFatal) {
  Pair p = make_pair();
  static_cast<void>(seal_msg(p.a, text("dropped")));
  EXPECT_EQ(open(p.b, seal_msg(p.a, text("next"))), ErrorCode::kReplayDetected);
}

TEST(SessionReplay, ReorderIsFatal) {
  Pair p = make_pair();
  const Frame first = seal_msg(p.a, text("1"));
  const Frame second = seal_msg(p.a, text("2"));
  EXPECT_EQ(open(p.b, second), ErrorCode::kReplayDetected);
  EXPECT_EQ(open(p.b, first), ErrorCode::kReplayDetected);  // sticky
}

TEST(SessionReplay, ForgedSeqStillFailsDecryption) {
  // A frame relabelled with the expected seq passes the seq check but its
  // nonce does not match (§5.3).
  Pair p = make_pair();
  static_cast<void>(seal_msg(p.a, text("dropped")));
  Frame f = seal_msg(p.a, text("next"));
  f.header.seq = 0;
  EXPECT_EQ(open(p.b, f), ErrorCode::kDecryptFailed);
}

TEST(SessionReplay, ErrorsAreSticky) {
  Pair p = make_pair();
  const Frame f = seal_msg(p.a, text("x"));
  Frame bad = f;
  bad.payload.back() ^= 1;
  EXPECT_EQ(open(p.b, bad), ErrorCode::kDecryptFailed);
  EXPECT_EQ(open(p.b, f), ErrorCode::kDecryptFailed);
  EXPECT_EQ(p.b.error(), ErrorCode::kDecryptFailed);
  Bytes wire;
  EXPECT_EQ(p.b.seal(kT0, FrameType::kMsg, kMessagingStream, text("y"), wire),
            ErrorCode::kDecryptFailed);
  EXPECT_EQ(p.b.send_rekey(kT0, wire), ErrorCode::kDecryptFailed);
  EXPECT_TRUE(wire.empty());
}

TEST(SessionReplay, CloseCanStillBeSentAfterReceiveError) {  // §7.1
  Pair p = make_pair();
  Frame bad = seal_msg(p.a, text("x"));
  bad.payload.back() ^= 1;
  ASSERT_EQ(open(p.b, bad), ErrorCode::kDecryptFailed);
  const Bytes close_payload{0x00, 0x04, 0x00, 0x00};  // DECRYPT_FAILED, no reason
  Bytes wire;
  ASSERT_EQ(p.b.seal(kT0, FrameType::kClose, kControlStream, close_payload, wire),
            ErrorCode::kNoError);
  Bytes got;
  ASSERT_EQ(open(p.a, parse(wire).at(0), &got), ErrorCode::kNoError);
  EXPECT_EQ(got, close_payload);
}

// --- splicing (S5) ------------------------------------------------------------

TEST(SessionSplice, WrongConnIdIsRejected) {
  Pair p = make_pair();
  Frame f = seal_msg(p.a, text("x"));
  f.header.conn_id ^= 1;
  EXPECT_EQ(open(p.b, f), ErrorCode::kProtocolError);
}

TEST(SessionSplice, FrameFromAnotherConnectionFailsDecryption) {
  // Same conn_id and seq, different keys: only the AEAD can catch it.
  Pair conn_a = make_pair();
  Pair conn_b = make_pair();
  EXPECT_EQ(open(conn_b.b, seal_msg(conn_a.a, text("x"))), ErrorCode::kDecryptFailed);
}

TEST(SessionSplice, ReflectedFrameFailsDecryption) {
  // A frame sent back to its own sender: directions use different keys (§5.1).
  Pair p = make_pair();
  EXPECT_EQ(open(p.a, seal_msg(p.a, text("x"))), ErrorCode::kDecryptFailed);
}

// --- rekey (§5.4) -------------------------------------------------------------

std::vector<FrameType> types(const std::vector<Frame>& frames) {
  std::vector<FrameType> t;
  for (const Frame& f : frames) t.push_back(f.header.type);
  return t;
}

TEST(SessionRekey, AfterMaxFramesUnderOneKey) {
  Pair p = make_pair(RekeyPolicy{3, std::chrono::hours(1)});
  Bytes wire;
  for (int i = 0; i < 6; ++i) {
    ASSERT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, text("m"), wire),
              ErrorCode::kNoError);
  }
  const auto frames = parse(wire);
  // At most 3 frames per key, the REKEY being the last frame under the old key.
  const std::vector<FrameType> expected{FrameType::kMsg, FrameType::kMsg,   FrameType::kRekey,
                                        FrameType::kMsg, FrameType::kMsg,   FrameType::kRekey,
                                        FrameType::kMsg, FrameType::kMsg};
  ASSERT_EQ(types(frames), expected);
  for (std::size_t i = 0; i < frames.size(); ++i) {
    EXPECT_EQ(frames[i].header.seq, i);  // seq not reset by rekey
    Bytes got;
    ASSERT_EQ(open(p.b, frames[i], &got), ErrorCode::kNoError);
    if (frames[i].header.type == FrameType::kMsg) {
      EXPECT_EQ(got, text("m"));
    }
  }
}

TEST(SessionRekey, AfterMaxAge) {
  Pair p = make_pair();
  ASSERT_EQ(open(p.b, seal_msg(p.a, text("early"))), ErrorCode::kNoError);
  const auto later = kT0 + twolink::session::kRekeyInterval;
  EXPECT_FALSE(p.a.rekey_due(later - std::chrono::seconds(1)));
  EXPECT_TRUE(p.a.rekey_due(later));

  Bytes wire;
  ASSERT_EQ(p.a.seal(later, FrameType::kMsg, kMessagingStream, text("late"), wire),
            ErrorCode::kNoError);
  const auto frames = parse(wire);
  ASSERT_EQ(types(frames), (std::vector<FrameType>{FrameType::kRekey, FrameType::kMsg}));
  for (const Frame& f : frames) ASSERT_EQ(open(p.b, f), ErrorCode::kNoError);

  // The interval restarts with the new key.
  EXPECT_FALSE(p.a.rekey_due(later + std::chrono::minutes(59)));
}

TEST(SessionRekey, ExplicitRekeyAndSealingRekeyAreTheSame) {
  Pair p = make_pair();
  Bytes wire;
  ASSERT_EQ(p.a.send_rekey(kT0, wire), ErrorCode::kNoError);
  ASSERT_EQ(p.a.seal(kT0, FrameType::kRekey, kControlStream, {}, wire), ErrorCode::kNoError);
  ASSERT_EQ(p.a.seal(kT0, FrameType::kMsg, kMessagingStream, text("after"), wire),
            ErrorCode::kNoError);
  const auto frames = parse(wire);
  ASSERT_EQ(types(frames),
            (std::vector<FrameType>{FrameType::kRekey, FrameType::kRekey, FrameType::kMsg}));
  Bytes got;
  for (const Frame& f : frames) ASSERT_EQ(open(p.b, f, &got), ErrorCode::kNoError);
  EXPECT_EQ(got, text("after"));
}

TEST(SessionRekey, DirectionsRekeyIndependently) {
  Pair p = make_pair();
  Bytes wire;
  ASSERT_EQ(p.a.send_rekey(kT0, wire), ErrorCode::kNoError);
  for (const Frame& f : parse(wire)) ASSERT_EQ(open(p.b, f), ErrorCode::kNoError);
  // b -> a still uses the original key.
  Bytes got;
  ASSERT_EQ(open(p.a, seal_msg(p.b, text("reply")), &got), ErrorCode::kNoError);
  EXPECT_EQ(got, text("reply"));
}

TEST(SessionRekey, ReceiverThatMissesRekeyCannotDecrypt) {
  // A REKEY dropped and the next frame relabelled to hide the gap: the receiver
  // still has the old key, so decryption fails.
  Pair p = make_pair();
  Bytes dropped;
  ASSERT_EQ(p.a.send_rekey(kT0, dropped), ErrorCode::kNoError);
  Frame f = seal_msg(p.a, text("new key"));
  ASSERT_EQ(f.header.seq, 1u);
  f.header.seq = 0;
  EXPECT_EQ(open(p.b, f), ErrorCode::kDecryptFailed);
}

TEST(SessionRekey, RekeyWithPayloadIsFatal) {
  // Built by hand with the raw CipherState: Session::seal refuses to make it.
  RawKeys k = handshake();
  auto b = Session::create(std::move(k.resp), kConnId, kT0);
  ASSERT_TRUE(b);

  FrameHeader h;
  h.type = FrameType::kRekey;
  h.stream_id = kControlStream;
  h.conn_id = kConnId;
  h.seq = k.init.send.nonce();
  h.length = 1 + kAeadTagSize;
  Bytes frame(kHeaderSize + h.length, 0);
  ASSERT_EQ(twolink::framing::encode_header(h, std::span(frame).first<kHeaderSize>()),
            twolink::framing::FrameError::kOk);
  frame[kHeaderSize] = 0x42;
  ASSERT_TRUE(k.init.send.encrypt_in_place(std::span(frame).first(kHeaderSize),
                                           std::span(frame).subspan(kHeaderSize), 1));
  Bytes got;
  EXPECT_EQ(b->open(h, std::span(frame).subspan(kHeaderSize), got), ErrorCode::kProtocolError);
}

}  // namespace
