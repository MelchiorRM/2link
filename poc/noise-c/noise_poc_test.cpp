// Noise library proof-of-concept (task 0.7): verifies that noise-c + libsodium
// provides what spec v0.1 §4–5 requires, on every CI platform.

#include <gtest/gtest.h>
#include <noise/protocol.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "noise_rekey.h"
#include "vectors.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::string_view kXXName = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
constexpr std::string_view kIKName = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
constexpr std::size_t kMac = 16;
constexpr std::size_t kHashLen = 64;  // BLAKE2b

class NoiseEnvironment : public ::testing::Environment {
 public:
  void SetUp() override {
    ASSERT_GE(sodium_init(), 0);
    ASSERT_EQ(noise_init(), NOISE_ERROR_NONE);
  }
};
[[maybe_unused]] const auto* const kEnv =
    ::testing::AddGlobalTestEnvironment(new NoiseEnvironment);

Bytes hex(std::string_view s) {
  Bytes out(s.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(std::stoi(std::string(s.substr(2 * i, 2)), nullptr, 16));
  }
  return out;
}

Bytes text(std::string_view s) { return Bytes(s.begin(), s.end()); }

struct HsDeleter {
  void operator()(NoiseHandshakeState* p) const { noise_handshakestate_free(p); }
};
struct CsDeleter {
  void operator()(NoiseCipherState* p) const { noise_cipherstate_free(p); }
};
using Hs = std::unique_ptr<NoiseHandshakeState, HsDeleter>;
using Cs = std::unique_ptr<NoiseCipherState, CsDeleter>;

Hs make_hs(std::string_view name, int role) {
  NoiseHandshakeState* p = nullptr;
  EXPECT_EQ(noise_handshakestate_new_by_name(&p, std::string(name).c_str(), role), NOISE_ERROR_NONE);
  return Hs(p);
}

Bytes public_key(const NoiseDHState* dh) {
  Bytes out(noise_dhstate_get_public_key_length(dh));
  EXPECT_EQ(noise_dhstate_get_public_key(dh, out.data(), out.size()), NOISE_ERROR_NONE);
  return out;
}

Bytes handshake_hash(const NoiseHandshakeState* hs) {
  Bytes h(kHashLen);
  EXPECT_EQ(noise_handshakestate_get_handshake_hash(hs, h.data(), h.size()), NOISE_ERROR_NONE);
  return h;
}

// --- handshake driver --------------------------------------------------------

struct Pair {
  Hs init;
  Hs resp;
};

struct Transcript {
  std::vector<Bytes> wire;      // bytes on the wire, per message
  std::vector<Bytes> received;  // payload decrypted by the reader, per message
};

// Moves one message from w to r. tamper flips a byte on the wire.
bool step(NoiseHandshakeState* w, NoiseHandshakeState* r, Bytes payload, Transcript& t,
          bool tamper) {
  Bytes msg(NOISE_MAX_PAYLOAD_LEN);
  NoiseBuffer mbuf;
  NoiseBuffer pbuf;
  noise_buffer_set_output(mbuf, msg.data(), msg.size());
  noise_buffer_set_input(pbuf, payload.data(), payload.size());
  if (noise_handshakestate_write_message(w, &mbuf, payload.empty() ? nullptr : &pbuf) !=
      NOISE_ERROR_NONE) {
    return false;
  }
  msg.resize(mbuf.size);
  if (tamper) msg.back() ^= 0x01;
  t.wire.push_back(msg);

  Bytes out(NOISE_MAX_PAYLOAD_LEN);
  NoiseBuffer in;
  NoiseBuffer obuf;
  noise_buffer_set_input(in, msg.data(), msg.size());
  noise_buffer_set_output(obuf, out.data(), out.size());
  if (noise_handshakestate_read_message(r, &in, &obuf) != NOISE_ERROR_NONE) return false;
  out.resize(obuf.size);
  t.received.push_back(out);
  return true;
}

// Runs the handshake to completion. Returns false as soon as a side fails.
bool run_handshake(Pair& p, const std::vector<Bytes>& payloads, Transcript& t,
                   int tamper_index = -1) {
  for (std::size_t i = 0;; ++i) {
    const int ai = noise_handshakestate_get_action(p.init.get());
    const int ar = noise_handshakestate_get_action(p.resp.get());
    if (ai == NOISE_ACTION_SPLIT && ar == NOISE_ACTION_SPLIT) return true;
    NoiseHandshakeState* w = nullptr;
    NoiseHandshakeState* r = nullptr;
    if (ai == NOISE_ACTION_WRITE_MESSAGE && ar == NOISE_ACTION_READ_MESSAGE) {
      w = p.init.get();
      r = p.resp.get();
    } else if (ar == NOISE_ACTION_WRITE_MESSAGE && ai == NOISE_ACTION_READ_MESSAGE) {
      w = p.resp.get();
      r = p.init.get();
    } else {
      return false;
    }
    const Bytes payload = i < payloads.size() ? payloads[i] : Bytes{};
    if (!step(w, r, payload, t, static_cast<int>(i) == tamper_index)) return false;
  }
}

void generate_static(NoiseHandshakeState* hs) {
  ASSERT_EQ(noise_dhstate_generate_keypair(noise_handshakestate_get_local_keypair_dh(hs)),
            NOISE_ERROR_NONE);
}

void set_prologue(NoiseHandshakeState* hs, const Bytes& prologue) {
  ASSERT_EQ(noise_handshakestate_set_prologue(hs, prologue.data(), prologue.size()),
            NOISE_ERROR_NONE);
}

// XX pair with fresh static keys and the 2Link prologue.
Pair make_xx(const Bytes& init_prologue = text("2LINK/1"),
             const Bytes& resp_prologue = text("2LINK/1")) {
  Pair p{make_hs(kXXName, NOISE_ROLE_INITIATOR), make_hs(kXXName, NOISE_ROLE_RESPONDER)};
  generate_static(p.init.get());
  generate_static(p.resp.get());
  set_prologue(p.init.get(), init_prologue);
  set_prologue(p.resp.get(), resp_prologue);
  EXPECT_EQ(noise_handshakestate_start(p.init.get()), NOISE_ERROR_NONE);
  EXPECT_EQ(noise_handshakestate_start(p.resp.get()), NOISE_ERROR_NONE);
  return p;
}

// IK pair. The initiator pins pinned_key, or the responder's real key if empty.
Pair make_ik(const Bytes& pinned_key = {}) {
  Pair p{make_hs(kIKName, NOISE_ROLE_INITIATOR), make_hs(kIKName, NOISE_ROLE_RESPONDER)};
  generate_static(p.init.get());
  generate_static(p.resp.get());
  set_prologue(p.init.get(), text("2LINK/1"));
  set_prologue(p.resp.get(), text("2LINK/1"));
  const Bytes key = pinned_key.empty()
                        ? public_key(noise_handshakestate_get_local_keypair_dh(p.resp.get()))
                        : pinned_key;
  EXPECT_EQ(noise_dhstate_set_public_key(noise_handshakestate_get_remote_public_key_dh(p.init.get()),
                                         key.data(), key.size()),
            NOISE_ERROR_NONE);
  EXPECT_EQ(noise_handshakestate_start(p.init.get()), NOISE_ERROR_NONE);
  EXPECT_EQ(noise_handshakestate_start(p.resp.get()), NOISE_ERROR_NONE);
  return p;
}

struct Split {
  Cs send;
  Cs recv;
};

Split split(NoiseHandshakeState* hs) {
  NoiseCipherState* s = nullptr;
  NoiseCipherState* r = nullptr;
  EXPECT_EQ(noise_handshakestate_split(hs, &s, &r), NOISE_ERROR_NONE);
  return {Cs(s), Cs(r)};
}

// --- transport helpers -------------------------------------------------------

Bytes seal(NoiseCipherState* cs, const Bytes& ad, const Bytes& plaintext) {
  Bytes buf = plaintext;
  buf.resize(plaintext.size() + kMac);
  NoiseBuffer b;
  noise_buffer_set_inout(b, buf.data(), plaintext.size(), buf.size());
  EXPECT_EQ(noise_cipherstate_encrypt_with_ad(cs, ad.empty() ? nullptr : ad.data(), ad.size(), &b),
            NOISE_ERROR_NONE);
  buf.resize(b.size);
  return buf;
}

int open(NoiseCipherState* cs, const Bytes& ad, Bytes ciphertext, Bytes* plaintext = nullptr) {
  NoiseBuffer b;
  noise_buffer_set_inout(b, ciphertext.data(), ciphertext.size(), ciphertext.size());
  const int err =
      noise_cipherstate_decrypt_with_ad(cs, ad.empty() ? nullptr : ad.data(), ad.size(), &b);
  if (err == NOISE_ERROR_NONE && plaintext) {
    *plaintext = Bytes(ciphertext.begin(), ciphertext.begin() + static_cast<std::ptrdiff_t>(b.size));
  }
  return err;
}

// Stand-in for a 28-byte 2Link frame header carrying seq (AD for the frame).
Bytes fake_header(std::uint64_t seq) {
  Bytes h(28, 0);
  for (int i = 0; i < 8; ++i) h[16 + i] = static_cast<std::uint8_t>(seq >> (56 - 8 * i));
  return h;
}

// ChaCha20-Poly1305 straight from libsodium, with the Noise nonce encoding
// (4 zero bytes || little-endian 64-bit counter). Independent of noise-c.
Bytes sodium_seal(const Bytes& key, std::uint64_t n, const Bytes& ad, const Bytes& plaintext) {
  std::array<std::uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> nonce{};
  for (int i = 0; i < 8; ++i) nonce[4 + i] = static_cast<std::uint8_t>(n >> (8 * i));
  Bytes out(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long out_len = 0;
  crypto_aead_chacha20poly1305_ietf_encrypt(out.data(), &out_len, plaintext.data(),
                                            plaintext.size(), ad.empty() ? nullptr : ad.data(),
                                            ad.size(), nullptr, nonce.data(), key.data());
  out.resize(out_len);
  return out;
}

Cs cipher_with_key(const Bytes& key) {
  NoiseCipherState* cs = nullptr;
  EXPECT_EQ(noise_cipherstate_new_by_name(&cs, "ChaChaPoly"), NOISE_ERROR_NONE);
  EXPECT_EQ(noise_cipherstate_init_key(cs, key.data(), key.size()), NOISE_ERROR_NONE);
  return Cs(cs);
}

// --- 1. Interoperability: Cacophony test vectors ------------------------------

void check_vector(const poc::Vector& v, std::size_t handshake_messages) {
  Pair p{make_hs(v.name, NOISE_ROLE_INITIATOR), make_hs(v.name, NOISE_ROLE_RESPONDER)};
  const Bytes prologue = hex(v.prologue);
  set_prologue(p.init.get(), prologue);
  set_prologue(p.resp.get(), prologue);
  auto set_private = [](NoiseDHState* dh, std::string_view key) {
    const Bytes k = hex(key);
    ASSERT_EQ(noise_dhstate_set_keypair_private(dh, k.data(), k.size()), NOISE_ERROR_NONE);
  };
  set_private(noise_handshakestate_get_local_keypair_dh(p.init.get()), v.init_static);
  set_private(noise_handshakestate_get_fixed_ephemeral_dh(p.init.get()), v.init_ephemeral);
  set_private(noise_handshakestate_get_local_keypair_dh(p.resp.get()), v.resp_static);
  set_private(noise_handshakestate_get_fixed_ephemeral_dh(p.resp.get()), v.resp_ephemeral);
  if (!v.init_remote_static.empty()) {
    const Bytes rs = hex(v.init_remote_static);
    ASSERT_EQ(noise_dhstate_set_public_key(
                  noise_handshakestate_get_remote_public_key_dh(p.init.get()), rs.data(), rs.size()),
              NOISE_ERROR_NONE);
  }
  ASSERT_EQ(noise_handshakestate_start(p.init.get()), NOISE_ERROR_NONE);
  ASSERT_EQ(noise_handshakestate_start(p.resp.get()), NOISE_ERROR_NONE);

  std::vector<Bytes> payloads;
  for (std::size_t i = 0; i < handshake_messages; ++i) payloads.push_back(hex(v.messages[i].payload));
  Transcript t;
  ASSERT_TRUE(run_handshake(p, payloads, t));
  ASSERT_EQ(t.wire.size(), handshake_messages);
  for (std::size_t i = 0; i < handshake_messages; ++i) {
    EXPECT_EQ(t.wire[i], hex(v.messages[i].ciphertext)) << "handshake message " << i;
    EXPECT_EQ(t.received[i], payloads[i]) << "handshake message " << i;
  }
  EXPECT_EQ(handshake_hash(p.init.get()), handshake_hash(p.resp.get()));

  // Transport messages alternate, starting with the initiator for even indices.
  Split is = split(p.init.get());
  Split rs = split(p.resp.get());
  for (std::size_t i = handshake_messages; i < v.messages.size(); ++i) {
    const bool from_init = i % 2 == 0;
    NoiseCipherState* send = from_init ? is.send.get() : rs.send.get();
    NoiseCipherState* recv = from_init ? rs.recv.get() : is.recv.get();
    const Bytes payload = hex(v.messages[i].payload);
    const Bytes ct = seal(send, {}, payload);
    EXPECT_EQ(ct, hex(v.messages[i].ciphertext)) << "transport message " << i;
    Bytes pt;
    ASSERT_EQ(open(recv, {}, ct, &pt), NOISE_ERROR_NONE);
    EXPECT_EQ(pt, payload);
  }
}

TEST(CacophonyVectors, XX_25519_ChaChaPoly_BLAKE2b) { check_vector(poc::kXX, 3); }
TEST(CacophonyVectors, IK_25519_ChaChaPoly_BLAKE2b) { check_vector(poc::kIK, 2); }

// --- 2. Handshakes with 2Link parameters -------------------------------------

TEST(Handshake, XXExposesHashAndRemoteStatic) {
  Pair p = make_xx();
  Transcript t;
  ASSERT_TRUE(run_handshake(p, {{}, text("resp-identity-tlv"), text("init-identity-tlv")}, t));
  EXPECT_EQ(t.received[1], text("resp-identity-tlv"));
  EXPECT_EQ(t.received[2], text("init-identity-tlv"));

  const Bytes hi = handshake_hash(p.init.get());
  EXPECT_EQ(hi.size(), kHashLen);
  EXPECT_EQ(hi, handshake_hash(p.resp.get()));
  EXPECT_NE(hi, Bytes(kHashLen, 0));

  // Each side learned the other's authenticated static key.
  EXPECT_EQ(public_key(noise_handshakestate_get_remote_public_key_dh(p.init.get())),
            public_key(noise_handshakestate_get_local_keypair_dh(p.resp.get())));
  EXPECT_EQ(public_key(noise_handshakestate_get_remote_public_key_dh(p.resp.get())),
            public_key(noise_handshakestate_get_local_keypair_dh(p.init.get())));
}

TEST(Handshake, TwoXXRunsGiveDifferentHashes) {  // basis of the MITM-detecting SAS
  Pair a = make_xx();
  Pair b = make_xx();
  Transcript ta;
  Transcript tb;
  ASSERT_TRUE(run_handshake(a, {}, ta));
  ASSERT_TRUE(run_handshake(b, {}, tb));
  EXPECT_NE(handshake_hash(a.init.get()), handshake_hash(b.init.get()));
}

TEST(Handshake, IKWithPinnedKey) {
  Pair p = make_ik();
  Transcript t;
  ASSERT_TRUE(run_handshake(p, {text("init-identity-tlv"), text("resp-identity-tlv")}, t));
  EXPECT_EQ(t.wire.size(), 2u);
  EXPECT_EQ(handshake_hash(p.init.get()), handshake_hash(p.resp.get()));
  EXPECT_EQ(public_key(noise_handshakestate_get_remote_public_key_dh(p.resp.get())),
            public_key(noise_handshakestate_get_local_keypair_dh(p.init.get())));
}

TEST(Handshake, IKWithWrongPinnedKeyFails) {  // spec §4.8: changed responder key
  Bytes wrong(32);
  randombytes_buf(wrong.data(), wrong.size());
  Pair p = make_ik(wrong);
  Transcript t;
  EXPECT_FALSE(run_handshake(p, {}, t));
}

TEST(Handshake, PrologueMismatchFails) {  // spec §4.2
  Pair p = make_xx(text("2LINK/1"), text("2LINK/2"));
  Transcript t;
  EXPECT_FALSE(run_handshake(p, {}, t));
}

TEST(Handshake, TamperedMessageFails) {
  for (int i = 1; i < 3; ++i) {  // message 0 (plain "e") has nothing to authenticate yet
    Pair p = make_xx();
    Transcript t;
    EXPECT_FALSE(run_handshake(p, {}, t, i)) << "tampered message " << i;
  }
}

TEST(Handshake, Curve448IsCleanlyUnavailable) {
  // Finding: on failure noise-c frees the object but leaves the out-pointer
  // dangling, so callers must discard it whenever the return value is an error.
  NoiseHandshakeState* hs = nullptr;
  EXPECT_NE(noise_handshakestate_new_by_name(&hs, "Noise_XX_448_ChaChaPoly_BLAKE2b",
                                             NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
}

// --- 3. CipherState: implicit counter, no SetNonce (spec §5.2–5.3) ------------

struct Session {
  Pair p;
  Split init;
  Split resp;
};

Session established_session() {
  Session s{make_xx(), {}, {}};
  Transcript t;
  EXPECT_TRUE(run_handshake(s.p, {}, t));
  s.init = split(s.p.init.get());
  s.resp = split(s.p.resp.get());
  return s;
}

TEST(Transport, CounterTracksSeqWithHeaderAsAd) {
  Session s = established_session();
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    ASSERT_EQ(poc_noise_cipherstate_nonce(s.init.send.get()), seq);
    const Bytes ct = seal(s.init.send.get(), fake_header(seq), text("frame"));
    ASSERT_EQ(poc_noise_cipherstate_nonce(s.resp.recv.get()), seq);
    Bytes pt;
    ASSERT_EQ(open(s.resp.recv.get(), fake_header(seq), ct, &pt), NOISE_ERROR_NONE);
    ASSERT_EQ(pt, text("frame"));
  }
}

TEST(Transport, DirectionsAreIndependent) {
  Session s = established_session();
  const Bytes a = seal(s.init.send.get(), {}, text("same"));
  const Bytes b = seal(s.resp.send.get(), {}, text("same"));
  EXPECT_NE(a, b);  // different keys per direction
  EXPECT_NE(open(s.init.recv.get(), {}, a), NOISE_ERROR_NONE);  // own frame does not decrypt
}

TEST(Transport, ReorderFails) {
  Session s = established_session();
  seal(s.init.send.get(), fake_header(0), text("f0"));
  const Bytes f1 = seal(s.init.send.get(), fake_header(1), text("f1"));
  EXPECT_NE(open(s.resp.recv.get(), fake_header(1), f1), NOISE_ERROR_NONE);
}

TEST(Transport, ReplayFails) {
  Session s = established_session();
  const Bytes f0 = seal(s.init.send.get(), fake_header(0), text("f0"));
  ASSERT_EQ(open(s.resp.recv.get(), fake_header(0), f0), NOISE_ERROR_NONE);
  EXPECT_NE(open(s.resp.recv.get(), fake_header(0), f0), NOISE_ERROR_NONE);
}

TEST(Transport, HeaderTamperFails) {
  Session s = established_session();
  const Bytes ct = seal(s.init.send.get(), fake_header(0), text("f0"));
  Bytes header = fake_header(0);
  header[1] ^= 0x01;
  EXPECT_NE(open(s.resp.recv.get(), header, ct), NOISE_ERROR_NONE);
}

TEST(Transport, ReservedMaxNonceRefused) {
  // SetNonce is used here only to reach the limit in a test; 2Link never calls it.
  Cs cs = cipher_with_key(Bytes(32, 0x42));
  ASSERT_EQ(noise_cipherstate_set_nonce(cs.get(), 0xFFFFFFFFFFFFFFFFull), NOISE_ERROR_NONE);
  Bytes buf(16 + kMac);
  NoiseBuffer b;
  noise_buffer_set_inout(b, buf.data(), 16, buf.size());
  EXPECT_EQ(noise_cipherstate_encrypt_with_ad(cs.get(), nullptr, 0, &b), NOISE_ERROR_INVALID_NONCE);
}

// --- 4. Rekey (spec §5.4) ----------------------------------------------------

TEST(Rekey, BackendMatchesLibsodiumNonceEncoding) {
  Bytes key(32);
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
  Cs cs = cipher_with_key(key);
  for (std::uint64_t n = 0; n < 4; ++n) {
    EXPECT_EQ(seal(cs.get(), fake_header(n), text("x")), sodium_seal(key, n, fake_header(n), text("x")));
  }
}

TEST(Rekey, MatchesSpecDefinitionAndKeepsCounter) {
  Bytes key(32);
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(0xA0 + i);
  Cs cs = cipher_with_key(key);
  for (int i = 0; i < 5; ++i) seal(cs.get(), {}, text("before"));

  ASSERT_EQ(poc_noise_cipherstate_rekey(cs.get()), NOISE_ERROR_NONE);
  EXPECT_EQ(poc_noise_cipherstate_nonce(cs.get()), 5u);  // counter unchanged

  // k' = first 32 bytes of ENCRYPT(k, 2^64-1, empty ad, 32 zero bytes)
  Bytes new_key = sodium_seal(key, 0xFFFFFFFFFFFFFFFFull, {}, Bytes(32, 0));
  new_key.resize(32);
  EXPECT_EQ(seal(cs.get(), fake_header(5), text("after")),
            sodium_seal(new_key, 5, fake_header(5), text("after")));
}

TEST(Rekey, BothSidesStayInSync) {
  Session s = established_session();
  std::uint64_t seq = 0;
  auto send_ok = [&](const char* label) {
    const Bytes ct = seal(s.init.send.get(), fake_header(seq), text(label));
    Bytes pt;
    ASSERT_EQ(open(s.resp.recv.get(), fake_header(seq), ct, &pt), NOISE_ERROR_NONE) << seq;
    ASSERT_EQ(pt, text(label));
    ++seq;
  };
  for (int i = 0; i < 10; ++i) send_ok("old key");
  // Sender sends REKEY (simulated), then both apply Rekey() to that direction.
  ASSERT_EQ(poc_noise_cipherstate_rekey(s.init.send.get()), NOISE_ERROR_NONE);
  ASSERT_EQ(poc_noise_cipherstate_rekey(s.resp.recv.get()), NOISE_ERROR_NONE);
  for (int i = 0; i < 10; ++i) send_ok("new key");
  EXPECT_EQ(poc_noise_cipherstate_nonce(s.init.send.get()), 20u);
  EXPECT_EQ(poc_noise_cipherstate_nonce(s.resp.recv.get()), 20u);
}

TEST(Rekey, OneSidedRekeyFails) {
  Session s = established_session();
  ASSERT_EQ(poc_noise_cipherstate_rekey(s.init.send.get()), NOISE_ERROR_NONE);
  const Bytes ct = seal(s.init.send.get(), {}, text("x"));
  EXPECT_NE(open(s.resp.recv.get(), {}, ct), NOISE_ERROR_NONE);
}

TEST(Rekey, OldKeyNoLongerDecrypts) {
  Bytes key(32, 0x11);
  Cs a = cipher_with_key(key);
  Cs b = cipher_with_key(key);
  ASSERT_EQ(poc_noise_cipherstate_rekey(a.get()), NOISE_ERROR_NONE);
  const Bytes ct = seal(a.get(), {}, text("x"));
  EXPECT_NE(open(b.get(), {}, ct), NOISE_ERROR_NONE);
}

TEST(Rekey, RequiresKey) {
  NoiseCipherState* raw = nullptr;
  ASSERT_EQ(noise_cipherstate_new_by_name(&raw, "ChaChaPoly"), NOISE_ERROR_NONE);
  Cs cs(raw);
  EXPECT_EQ(poc_noise_cipherstate_rekey(cs.get()), NOISE_ERROR_INVALID_STATE);
  EXPECT_EQ(poc_noise_cipherstate_rekey(nullptr), NOISE_ERROR_INVALID_PARAM);
}

}  // namespace
