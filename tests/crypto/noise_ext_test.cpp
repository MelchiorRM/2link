// 2Link's Rekey() extension to noise-c, checked at the C level against an
// independent libsodium computation (threat model X2, spec §5.1, §5.4).

#include "twolink/noise_ext.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <noise/protocol.h>
#include <sodium.h>

namespace {

using Bytes = std::vector<std::uint8_t>;
constexpr std::size_t kMac = 16;

struct CsDeleter {
  void operator()(NoiseCipherState* p) const { noise_cipherstate_free(p); }
};
using Cs = std::unique_ptr<NoiseCipherState, CsDeleter>;

Cs cipher_with_key(const Bytes& key) {
  NoiseCipherState* cs = nullptr;
  EXPECT_EQ(noise_cipherstate_new_by_id(&cs, NOISE_CIPHER_CHACHAPOLY), NOISE_ERROR_NONE);
  EXPECT_EQ(noise_cipherstate_init_key(cs, key.data(), key.size()), NOISE_ERROR_NONE);
  return Cs(cs);
}

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

bool open(NoiseCipherState* cs, Bytes ciphertext) {
  NoiseBuffer b;
  noise_buffer_set_inout(b, ciphertext.data(), ciphertext.size(), ciphertext.size());
  return noise_cipherstate_decrypt_with_ad(cs, nullptr, 0, &b) == NOISE_ERROR_NONE;
}

// ChaCha20-Poly1305 straight from libsodium with the Noise nonce encoding
// (4 zero bytes || little-endian 64-bit counter). Independent of noise-c.
Bytes sodium_seal(const Bytes& key, std::uint64_t n, const Bytes& ad, const Bytes& plaintext) {
  std::array<std::uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> nonce{};
  for (std::size_t i = 0; i < 8; ++i) nonce[4 + i] = static_cast<std::uint8_t>(n >> (8 * i));
  Bytes out(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long out_len = 0;
  crypto_aead_chacha20poly1305_ietf_encrypt(out.data(), &out_len, plaintext.data(),
                                            plaintext.size(), ad.empty() ? nullptr : ad.data(),
                                            ad.size(), nullptr, nonce.data(), key.data());
  out.resize(static_cast<std::size_t>(out_len));
  return out;
}

Bytes text(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }

Bytes counting_key(std::uint8_t start) {
  Bytes key(32);
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(start + i);
  return key;
}

TEST(NoiseRekeyExt, BackendMatchesLibsodiumNonceEncoding) {
  const Bytes key = counting_key(0);
  Cs cs = cipher_with_key(key);
  const Bytes ad = text("header");
  for (std::uint64_t n = 0; n < 4; ++n) {
    EXPECT_EQ(seal(cs.get(), ad, text("x")), sodium_seal(key, n, ad, text("x")));
  }
}

TEST(NoiseRekeyExt, MatchesSpecDefinitionAndKeepsCounter) {
  const Bytes key = counting_key(0xA0);
  Cs cs = cipher_with_key(key);
  for (int i = 0; i < 5; ++i) seal(cs.get(), {}, text("before"));

  ASSERT_EQ(twolink_noise_cipherstate_rekey(cs.get()), NOISE_ERROR_NONE);
  EXPECT_EQ(twolink_noise_cipherstate_nonce(cs.get()), 5u);  // counter unchanged

  // k' = first 32 bytes of ENCRYPT(k, 2^64-1, empty ad, 32 zero bytes)
  Bytes new_key = sodium_seal(key, 0xFFFFFFFFFFFFFFFFull, {}, Bytes(32, 0));
  new_key.resize(32);
  const Bytes ad = text("header");
  EXPECT_EQ(seal(cs.get(), ad, text("after")), sodium_seal(new_key, 5, ad, text("after")));
}

TEST(NoiseRekeyExt, OldKeyNoLongerDecrypts) {
  const Bytes key(32, 0x11);
  Cs a = cipher_with_key(key);
  Cs b = cipher_with_key(key);
  ASSERT_EQ(twolink_noise_cipherstate_rekey(a.get()), NOISE_ERROR_NONE);
  EXPECT_FALSE(open(b.get(), seal(a.get(), {}, text("x"))));
}

TEST(NoiseRekeyExt, RequiresKey) {
  NoiseCipherState* raw = nullptr;
  ASSERT_EQ(noise_cipherstate_new_by_id(&raw, NOISE_CIPHER_CHACHAPOLY), NOISE_ERROR_NONE);
  Cs cs(raw);
  EXPECT_EQ(twolink_noise_cipherstate_rekey(cs.get()), NOISE_ERROR_INVALID_STATE);
  EXPECT_EQ(twolink_noise_cipherstate_rekey(nullptr), NOISE_ERROR_INVALID_PARAM);
  EXPECT_EQ(twolink_noise_cipherstate_nonce(nullptr), 0u);
}

TEST(NoiseRekeyExt, ReservedMaxNonceRefused) {  // spec §5.3
  // SetNonce is used only here, to reach the limit; 2Link never calls it.
  Cs cs = cipher_with_key(Bytes(32, 0x42));
  ASSERT_EQ(noise_cipherstate_set_nonce(cs.get(), 0xFFFFFFFFFFFFFFFFull), NOISE_ERROR_NONE);
  Bytes buf(16 + kMac);
  NoiseBuffer b;
  noise_buffer_set_inout(b, buf.data(), 16, buf.size());
  EXPECT_EQ(noise_cipherstate_encrypt_with_ad(cs.get(), nullptr, 0, &b), NOISE_ERROR_INVALID_NONCE);
}

}  // namespace
