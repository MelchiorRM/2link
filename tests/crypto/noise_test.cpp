// twolink::crypto Noise wrapper: conformance (X1), spec v0.1.1 §4–5 behaviour,
// and the error rule (X3).

#include "twolink/crypto/noise.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "cacophony_vectors.hpp"
#include "twolink/crypto/keys.hpp"

namespace {

using namespace twolink::crypto;
using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kNoiseMaxMessage = 65535;

Bytes hex(std::string_view s) {
  Bytes out(s.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(std::stoi(std::string(s.substr(2 * i, 2)), nullptr, 16));
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> hex_array(std::string_view s) {
  const Bytes b = hex(s);
  std::array<std::uint8_t, N> out{};
  std::copy(b.begin(), b.end(), out.begin());
  return out;
}

Bytes text(std::string_view s) { return Bytes(s.begin(), s.end()); }

const Bytes kPrologue = text("2LINK/1");

// --- handshake driver --------------------------------------------------------

struct Pair {
  StaticKeyPair init_key;
  StaticKeyPair resp_key;
  std::optional<Handshake> init;
  std::optional<Handshake> resp;
};

struct Transcript {
  std::vector<Bytes> wire;      // handshake messages as sent
  std::vector<Bytes> received;  // payloads as decrypted by the reader
};

Pair make_pair(Pattern pattern, const Bytes& init_prologue = kPrologue,
               const Bytes& resp_prologue = kPrologue,
               std::optional<PublicKey> pinned = std::nullopt) {
  Pair p{StaticKeyPair::generate(), StaticKeyPair::generate(), std::nullopt, std::nullopt};
  HandshakeConfig ic{pattern, Role::kInitiator, init_prologue, std::nullopt, std::nullopt};
  if (pattern == Pattern::kIK) ic.remote_static = pinned ? *pinned : p.resp_key.public_key();
  HandshakeConfig rc{pattern, Role::kResponder, resp_prologue, std::nullopt, std::nullopt};
  p.init = Handshake::create(ic, p.init_key);
  p.resp = Handshake::create(rc, p.resp_key);
  EXPECT_TRUE(p.init.has_value());
  EXPECT_TRUE(p.resp.has_value());
  return p;
}

// Moves one message from w to r; tamper flips the last byte on the wire.
bool step(Handshake& w, Handshake& r, const Bytes& payload, Transcript& t, bool tamper) {
  Bytes msg(kNoiseMaxMessage);
  const auto n = w.write_message(payload, msg);
  if (!n) return false;
  msg.resize(*n);
  if (tamper) msg.back() ^= 0x01;
  t.wire.push_back(msg);
  Bytes out(kNoiseMaxMessage);
  const auto m = r.read_message(msg, out);
  if (!m) return false;
  out.resize(*m);
  t.received.push_back(out);
  return true;
}

// Runs the handshake until both sides reach kSplit. False as soon as one fails.
bool run(Handshake& init, Handshake& resp, const std::vector<Bytes>& payloads, Transcript& t,
         int tamper_index = -1) {
  for (std::size_t i = 0;; ++i) {
    const HandshakeAction ai = init.action();
    const HandshakeAction ar = resp.action();
    if (ai == HandshakeAction::kSplit && ar == HandshakeAction::kSplit) return true;
    const Bytes payload = i < payloads.size() ? payloads[i] : Bytes{};
    const bool tamper = static_cast<int>(i) == tamper_index;
    if (ai == HandshakeAction::kWriteMessage && ar == HandshakeAction::kReadMessage) {
      if (!step(init, resp, payload, t, tamper)) return false;
    } else if (ar == HandshakeAction::kWriteMessage && ai == HandshakeAction::kReadMessage) {
      if (!step(resp, init, payload, t, tamper)) return false;
    } else {
      return false;
    }
  }
}

bool run(Pair& p, const std::vector<Bytes>& payloads, Transcript& t, int tamper_index = -1) {
  return run(*p.init, *p.resp, payloads, t, tamper_index);
}

// --- transport helpers -------------------------------------------------------

Bytes seal(CipherState& cs, const Bytes& ad, const Bytes& plaintext) {
  Bytes buf = plaintext;
  buf.resize(plaintext.size() + kTagSize);
  EXPECT_TRUE(cs.encrypt_in_place(ad, buf, plaintext.size()));
  return buf;
}

bool open(CipherState& cs, const Bytes& ad, Bytes ciphertext, Bytes* plaintext = nullptr) {
  if (!cs.decrypt_in_place(ad, ciphertext)) return false;
  if (plaintext) {
    *plaintext = Bytes(ciphertext.begin(), ciphertext.end() - static_cast<std::ptrdiff_t>(kTagSize));
  }
  return true;
}

// Stand-in for a 28-byte frame header carrying seq: the AD of a frame.
Bytes fake_header(std::uint64_t seq) {
  Bytes h(28, 0);
  for (int i = 0; i < 8; ++i) h[16 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(seq >> (56 - 8 * i));
  return h;
}

struct Session {
  Pair p;
  Handshake::Keys init;
  Handshake::Keys resp;
};

Session established() {
  Pair p = make_pair(Pattern::kXX);
  Transcript t;
  EXPECT_TRUE(run(p, {}, t));
  auto ik = p.init->split();
  auto rk = p.resp->split();
  EXPECT_TRUE(ik && rk);
  return Session{std::move(p), std::move(*ik), std::move(*rk)};
}

// --- 1. Cacophony reference vectors (X1) ----------------------------------------

void check_vector(const twolink::test::Vector& v, Pattern pattern, std::size_t handshake_messages) {
  const Bytes prologue = hex(v.prologue);
  const StaticKeyPair ik = StaticKeyPair::from_private_key(hex_array<kKeySize>(v.init_static));
  const StaticKeyPair rk = StaticKeyPair::from_private_key(hex_array<kKeySize>(v.resp_static));
  HandshakeConfig ic{pattern, Role::kInitiator, prologue, std::nullopt,
                     hex_array<kKeySize>(v.init_ephemeral)};
  if (!v.init_remote_static.empty()) ic.remote_static = hex_array<kKeySize>(v.init_remote_static);
  HandshakeConfig rc{pattern, Role::kResponder, prologue, std::nullopt,
                     hex_array<kKeySize>(v.resp_ephemeral)};
  auto init = Handshake::create(ic, ik);
  auto resp = Handshake::create(rc, rk);
  ASSERT_TRUE(init && resp);

  std::vector<Bytes> payloads;
  for (std::size_t i = 0; i < handshake_messages; ++i) payloads.push_back(hex(v.messages[i].payload));
  Transcript t;
  ASSERT_TRUE(run(*init, *resp, payloads, t));
  ASSERT_EQ(t.wire.size(), handshake_messages);
  for (std::size_t i = 0; i < handshake_messages; ++i) {
    EXPECT_EQ(t.wire[i], hex(v.messages[i].ciphertext)) << "handshake message " << i;
    EXPECT_EQ(t.received[i], payloads[i]) << "handshake message " << i;
  }
  EXPECT_EQ(init->handshake_hash(), resp->handshake_hash());

  auto is = init->split();
  auto rs = resp->split();
  ASSERT_TRUE(is && rs);
  for (std::size_t i = handshake_messages; i < v.messages.size(); ++i) {
    const bool from_init = i % 2 == 0;  // transport messages alternate, initiator first
    CipherState& send = from_init ? is->send : rs->send;
    CipherState& recv = from_init ? rs->recv : is->recv;
    const Bytes payload = hex(v.messages[i].payload);
    const Bytes ct = seal(send, {}, payload);
    EXPECT_EQ(ct, hex(v.messages[i].ciphertext)) << "transport message " << i;
    Bytes pt;
    ASSERT_TRUE(open(recv, {}, ct, &pt));
    EXPECT_EQ(pt, payload);
  }
}

TEST(CacophonyVectors, XX_25519_ChaChaPoly_BLAKE2b) {
  check_vector(twolink::test::kXX, Pattern::kXX, 3);
}
TEST(CacophonyVectors, IK_25519_ChaChaPoly_BLAKE2b) {
  check_vector(twolink::test::kIK, Pattern::kIK, 2);
}

// --- 2. Key pairs ------------------------------------------------------------------

TEST(StaticKeyPair, FromPrivateKeyReproducesPublicKey) {
  const StaticKeyPair a = StaticKeyPair::generate();
  const StaticKeyPair b = StaticKeyPair::from_private_key(a.private_key());
  EXPECT_EQ(a.public_key(), b.public_key());
  EXPECT_NE(a.public_key(), PublicKey{});
}

TEST(StaticKeyPair, GeneratedKeysDiffer) {
  EXPECT_NE(StaticKeyPair::generate().public_key(), StaticKeyPair::generate().public_key());
}

TEST(StaticKeyPair, MovedFromIsWiped) {  // L4
  StaticKeyPair a = StaticKeyPair::generate();
  const PublicKey pub = a.public_key();
  StaticKeyPair b = std::move(a);
  EXPECT_EQ(b.public_key(), pub);
  const auto priv = a.private_key();  // NOLINT(bugprone-use-after-move): checking the wipe
  EXPECT_TRUE(std::all_of(priv.begin(), priv.end(), [](std::uint8_t x) { return x == 0; }));
}

// --- 3. Handshakes with 2Link parameters (spec §4) -------------------------------------

TEST(Handshake, XXExposesHashAndRemoteStatic) {
  Pair p = make_pair(Pattern::kXX);
  Transcript t;
  ASSERT_TRUE(run(p, {{}, text("resp-identity-tlv"), text("init-identity-tlv")}, t));
  EXPECT_EQ(t.received[1], text("resp-identity-tlv"));
  EXPECT_EQ(t.received[2], text("init-identity-tlv"));

  const auto hi = p.init->handshake_hash();
  ASSERT_TRUE(hi.has_value());
  EXPECT_EQ(hi, p.resp->handshake_hash());
  EXPECT_NE(*hi, HandshakeHash{});
  EXPECT_EQ(p.init->remote_static(), p.resp_key.public_key());
  EXPECT_EQ(p.resp->remote_static(), p.init_key.public_key());
}

TEST(Handshake, TwoXXRunsGiveDifferentHashes) {  // basis of the MITM-detecting SAS (H1)
  Pair a = make_pair(Pattern::kXX);
  Pair b = make_pair(Pattern::kXX);
  Transcript ta;
  Transcript tb;
  ASSERT_TRUE(run(a, {}, ta));
  ASSERT_TRUE(run(b, {}, tb));
  EXPECT_NE(a.init->handshake_hash(), b.init->handshake_hash());
}

TEST(Handshake, IKResponderLearnsInitiatorKeyAfterFirstMessage) {  // trust lookup, §4.8
  Pair p = make_pair(Pattern::kIK);
  EXPECT_FALSE(p.resp->remote_static().has_value());
  Transcript t;
  ASSERT_TRUE(step(*p.init, *p.resp, text("init-identity-tlv"), t, false));
  EXPECT_EQ(p.resp->remote_static(), p.init_key.public_key());
  ASSERT_TRUE(step(*p.resp, *p.init, text("resp-identity-tlv"), t, false));
  EXPECT_EQ(p.init->action(), HandshakeAction::kSplit);
  EXPECT_EQ(p.resp->action(), HandshakeAction::kSplit);
  EXPECT_EQ(p.init->handshake_hash(), p.resp->handshake_hash());
  EXPECT_EQ(t.wire.size(), 2u);
}

TEST(Handshake, IKWithWrongPinnedKeyFailsOnResponder) {  // §4.8: changed responder key
  Pair p = make_pair(Pattern::kIK, kPrologue, kPrologue, StaticKeyPair::generate().public_key());
  Transcript t;
  EXPECT_FALSE(step(*p.init, *p.resp, {}, t, false));
  EXPECT_EQ(p.resp->action(), HandshakeAction::kFailed);
}

TEST(Handshake, PrologueMismatchFails) {  // §4.2
  Pair p = make_pair(Pattern::kXX, text("2LINK/1"), text("2LINK/2"));
  Transcript t;
  EXPECT_FALSE(run(p, {}, t));
}

TEST(Handshake, TamperedMessageFails) {
  for (int i = 1; i < 3; ++i) {  // message 0 (plain "e") authenticates nothing yet
    Pair p = make_pair(Pattern::kXX);
    Transcript t;
    EXPECT_FALSE(run(p, {}, t, i)) << "tampered message " << i;
  }
}

// --- 4. Error rule (X3) ------------------------------------------------------------

TEST(HandshakeErrors, InvalidConfigurationsAreRejected) {
  const StaticKeyPair k = StaticKeyPair::generate();
  const PublicKey pin = StaticKeyPair::generate().public_key();
  EXPECT_FALSE(Handshake::create({Pattern::kIK, Role::kInitiator, kPrologue, std::nullopt, std::nullopt}, k));
  EXPECT_FALSE(Handshake::create({Pattern::kIK, Role::kResponder, kPrologue, pin, std::nullopt}, k));
  EXPECT_FALSE(Handshake::create({Pattern::kXX, Role::kInitiator, kPrologue, pin, std::nullopt}, k));
  EXPECT_FALSE(Handshake::create({Pattern::kXX, Role::kResponder, kPrologue, pin, std::nullopt}, k));
}

TEST(HandshakeErrors, CallOutOfTurnKillsTheHandshake) {
  Pair p = make_pair(Pattern::kXX);
  Bytes buf(kNoiseMaxMessage);
  EXPECT_FALSE(p.resp->read_message({}, buf));   // empty message
  EXPECT_EQ(p.resp->action(), HandshakeAction::kFailed);
  EXPECT_FALSE(p.init->read_message(buf, buf));  // initiator must write first
  EXPECT_EQ(p.init->action(), HandshakeAction::kFailed);
  EXPECT_FALSE(p.init->write_message({}, buf));  // dead stays dead
}

TEST(HandshakeErrors, GarbageMessageLeavesNothingUsable) {
  Pair p = make_pair(Pattern::kXX);
  Transcript t;
  ASSERT_TRUE(step(*p.init, *p.resp, {}, t, false));
  Bytes garbage(200, 0xAB);
  Bytes out(kNoiseMaxMessage);
  EXPECT_FALSE(p.init->read_message(garbage, out));
  EXPECT_EQ(p.init->action(), HandshakeAction::kFailed);
  EXPECT_FALSE(p.init->remote_static().has_value());
  EXPECT_FALSE(p.init->handshake_hash().has_value());
  EXPECT_FALSE(p.init->split().has_value());
}

TEST(HandshakeErrors, OutputBufferTooSmallFails) {
  Pair p = make_pair(Pattern::kXX);
  Bytes tiny(8);  // message 1 ("e") needs 32 bytes
  EXPECT_FALSE(p.init->write_message({}, tiny));
  EXPECT_EQ(p.init->action(), HandshakeAction::kFailed);
}

TEST(HandshakeErrors, SplitOnlyOnce) {
  Pair p = make_pair(Pattern::kXX);
  Transcript t;
  ASSERT_TRUE(run(p, {}, t));
  ASSERT_TRUE(p.init->split().has_value());
  EXPECT_EQ(p.init->action(), HandshakeAction::kFinished);
  EXPECT_FALSE(p.init->split().has_value());
  EXPECT_FALSE(p.init->handshake_hash().has_value());
  EXPECT_EQ(p.init->action(), HandshakeAction::kFinished);
}

TEST(HandshakeErrors, SplitBeforeCompletionFails) {
  Pair p = make_pair(Pattern::kXX);
  EXPECT_FALSE(p.init->split().has_value());
  EXPECT_EQ(p.init->action(), HandshakeAction::kFailed);
}

// --- 5. Transport: implicit counter, no SetNonce (spec §5.2–5.3) ------------------------

TEST(Transport, CounterTracksSeqWithHeaderAsAd) {
  Session s = established();
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    ASSERT_EQ(s.init.send.nonce(), seq);
    const Bytes ct = seal(s.init.send, fake_header(seq), text("frame"));
    ASSERT_EQ(s.resp.recv.nonce(), seq);
    Bytes pt;
    ASSERT_TRUE(open(s.resp.recv, fake_header(seq), ct, &pt));
    ASSERT_EQ(pt, text("frame"));
  }
}

TEST(Transport, DirectionsAreIndependent) {
  Session s = established();
  const Bytes a = seal(s.init.send, {}, text("same"));
  const Bytes b = seal(s.resp.send, {}, text("same"));
  EXPECT_NE(a, b);
  EXPECT_FALSE(open(s.init.recv, {}, a));  // own frame does not decrypt
}

TEST(Transport, ReorderFails) {
  Session s = established();
  seal(s.init.send, fake_header(0), text("f0"));
  const Bytes f1 = seal(s.init.send, fake_header(1), text("f1"));
  EXPECT_FALSE(open(s.resp.recv, fake_header(1), f1));
}

TEST(Transport, ReplayFails) {
  Session s = established();
  const Bytes f0 = seal(s.init.send, fake_header(0), text("f0"));
  ASSERT_TRUE(open(s.resp.recv, fake_header(0), f0));
  EXPECT_FALSE(open(s.resp.recv, fake_header(0), f0));
}

TEST(Transport, HeaderTamperFails) {
  Session s = established();
  const Bytes ct = seal(s.init.send, fake_header(0), text("f0"));
  Bytes header = fake_header(0);
  header[1] ^= 0x01;
  EXPECT_FALSE(open(s.resp.recv, header, ct));
}

TEST(Transport, FailedCipherStateRefusesWork) {
  Session s = established();
  Bytes junk(32, 0);
  EXPECT_FALSE(s.resp.recv.decrypt_in_place({}, junk));
  EXPECT_FALSE(s.resp.recv.usable());
  EXPECT_EQ(s.resp.recv.nonce(), 0u);
  EXPECT_FALSE(s.resp.recv.rekey());
  Bytes buf(16 + kTagSize);
  EXPECT_FALSE(s.resp.recv.encrypt_in_place({}, buf, 16));
}

TEST(Transport, LargestFrameFitsTheNoiseLimit) {  // spec v0.1.1 §2.1
  Session s = established();
  const Bytes header = fake_header(0);
  Bytes buf(kNoiseMaxMessage);
  constexpr std::size_t kMaxPlaintext = kNoiseMaxMessage - kTagSize;  // 65 519
  ASSERT_TRUE(s.init.send.encrypt_in_place(header, buf, kMaxPlaintext));
  EXPECT_TRUE(s.resp.recv.decrypt_in_place(header, buf));

  Bytes too_big(kNoiseMaxMessage + 1);
  EXPECT_FALSE(s.init.send.encrypt_in_place(header, too_big, kMaxPlaintext + 1));
  EXPECT_FALSE(s.resp.recv.decrypt_in_place(header, too_big));
}

TEST(Transport, EncryptNeedsRoomForTheTag) {
  Session s = established();
  Bytes buf(20);
  EXPECT_FALSE(s.init.send.encrypt_in_place({}, buf, 5));  // 5 + 16 > 20
  EXPECT_FALSE(s.init.send.usable());
}

// --- 6. Rekey through the wrapper (spec §5.4) --------------------------------------

TEST(Rekey, BothSidesStayInSyncAndCounterKeepsCounting) {
  Session s = established();
  std::uint64_t seq = 0;
  auto send_ok = [&](const char* label) {
    const Bytes ct = seal(s.init.send, fake_header(seq), text(label));
    Bytes pt;
    ASSERT_TRUE(open(s.resp.recv, fake_header(seq), ct, &pt)) << seq;
    ASSERT_EQ(pt, text(label));
    ++seq;
  };
  for (int i = 0; i < 10; ++i) send_ok("old key");
  ASSERT_TRUE(s.init.send.rekey());
  ASSERT_TRUE(s.resp.recv.rekey());
  EXPECT_EQ(s.init.send.nonce(), 10u);
  for (int i = 0; i < 10; ++i) send_ok("new key");
  EXPECT_EQ(s.init.send.nonce(), 20u);
  EXPECT_EQ(s.resp.recv.nonce(), 20u);
}

TEST(Rekey, OneSidedRekeyFails) {
  Session s = established();
  ASSERT_TRUE(s.init.send.rekey());
  const Bytes ct = seal(s.init.send, {}, text("x"));
  EXPECT_FALSE(open(s.resp.recv, {}, ct));
}

}  // namespace
