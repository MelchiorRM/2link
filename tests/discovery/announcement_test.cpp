// Discovery announcements, spec v0.1.3 §8.1 (threat model D2, D3).

#include "twolink/discovery/announcement.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "twolink/core/tlv.hpp"
#include "twolink/crypto/keys.hpp"

namespace {

using namespace twolink::discovery;
using twolink::append_tlv;
using twolink::crypto::StaticKeyPair;
using Bytes = std::vector<std::uint8_t>;

Announcement sample() {
  return make_announcement("laptop", StaticKeyPair::generate().public_key(), 47821);
}

Bytes header() { return Bytes{'2', 'L', 'N', 'K', 1, 1}; }

// A datagram built by hand: lets tests drop, repeat or corrupt fields.
struct Builder {
  Announcement a = sample();
  bool name = true, id = true, key = true, port = true;
  Bytes extra;

  Bytes build() const {
    Bytes d = header();
    if (name) append_tlv(d, 0x01, Bytes(a.device_name.begin(), a.device_name.end()));
    if (id) append_tlv(d, 0x10, Bytes(a.device_id.begin(), a.device_id.end()));
    if (key) append_tlv(d, 0x11, Bytes(a.static_key.begin(), a.static_key.end()));
    if (port) append_tlv(d, 0x12, Bytes{static_cast<std::uint8_t>(a.tcp_port >> 8),
                                        static_cast<std::uint8_t>(a.tcp_port)});
    d.insert(d.end(), extra.begin(), extra.end());
    return d;
  }
};

AnnounceError decode(const Bytes& d, Announcement* out = nullptr) {
  Announcement a;
  const AnnounceError e = decode_announcement(d, a);
  if (out) *out = a;
  return e;
}

TEST(Announcement, RoundTrip) {
  const Announcement a = sample();
  Bytes d;
  ASSERT_EQ(encode_announcement(a, d), AnnounceError::kOk);
  EXPECT_LE(d.size(), kMaxDatagramSize);
  Announcement got;
  ASSERT_EQ(decode(d, &got), AnnounceError::kOk);
  EXPECT_EQ(got, a);
}

TEST(Announcement, LayoutMatchesSpec) {
  Builder b;
  Bytes d;
  ASSERT_EQ(encode_announcement(b.a, d), AnnounceError::kOk);
  EXPECT_EQ(d, b.build());
  EXPECT_EQ(Bytes(d.begin(), d.begin() + 6), header());
}

TEST(Announcement, MismatchedDeviceIdIsDropped) {  // D2
  Builder b;
  b.a.device_id[0] ^= 1;
  EXPECT_EQ(decode(b.build()), AnnounceError::kIdMismatch);
  Builder other;
  other.a.static_key = StaticKeyPair::generate().public_key();  // id of one key, another key
  EXPECT_EQ(decode(other.build()), AnnounceError::kIdMismatch);
}

TEST(Announcement, BadHeaderIsDropped) {
  const Bytes good = Builder{}.build();
  for (std::size_t i = 0; i < 6; ++i) {
    Bytes bad = good;
    bad[i] ^= 0x01;
    EXPECT_EQ(decode(bad), AnnounceError::kBadHeader) << i;
  }
  EXPECT_EQ(decode(Bytes{'2', 'L', 'N', 'K', 1}), AnnounceError::kBadHeader);
  EXPECT_EQ(decode({}), AnnounceError::kBadHeader);
}

TEST(Announcement, OversizedDatagramIsDropped) {  // D3
  Builder b;
  append_tlv(b.extra, 0x7F, Bytes(450, 0));
  const Bytes d = b.build();
  ASSERT_GT(d.size(), kMaxDatagramSize);
  EXPECT_EQ(decode(d), AnnounceError::kTooLarge);
}

TEST(Announcement, TlvRulesApply) {  // §4.3 via §8.1
  Builder optional;
  append_tlv(optional.extra, 0x7F, Bytes{1, 2});
  EXPECT_EQ(decode(optional.build()), AnnounceError::kOk);

  Builder critical;
  append_tlv(critical.extra, 0x80, {});
  EXPECT_EQ(decode(critical.build()), AnnounceError::kBadTlv);

  Builder dup;
  append_tlv(dup.extra, 0x01, Bytes{'x'});
  EXPECT_EQ(decode(dup.build()), AnnounceError::kBadTlv);
}

TEST(Announcement, MissingFieldsAreDropped) {
  for (int i = 0; i < 4; ++i) {
    Builder b;
    (i == 0 ? b.name : i == 1 ? b.id : i == 2 ? b.key : b.port) = false;
    EXPECT_EQ(decode(b.build()), AnnounceError::kMissing) << i;
  }
}

TEST(Announcement, MalformedValuesAreDropped) {
  auto with = [](std::uint8_t tag, const Bytes& v) {
    Builder b;
    if (tag == 0x01) b.name = false;
    if (tag == 0x10) b.id = false;
    if (tag == 0x11) b.key = false;
    if (tag == 0x12) b.port = false;
    append_tlv(b.extra, tag, v);
    return b.build();
  };
  EXPECT_EQ(decode(with(0x01, {})), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x01, Bytes(65, 'x'))), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x01, Bytes{0xFF})), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x10, Bytes(31, 0))), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x11, Bytes(33, 0))), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x12, Bytes{0x01})), AnnounceError::kBadTlv);
  EXPECT_EQ(decode(with(0x12, Bytes{0x00, 0x00})), AnnounceError::kBadTlv);  // port 0
}

TEST(Announcement, EveryTruncationIsDropped) {
  const Bytes d = Builder{}.build();
  for (std::size_t n = 0; n < d.size(); ++n) {
    EXPECT_NE(decode(Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(n))),
              AnnounceError::kOk)
        << n;
  }
}

TEST(Announcement, EncodeRejectsInvalidFields) {
  Bytes d = {9};
  Announcement a = sample();
  a.device_name.clear();
  EXPECT_NE(encode_announcement(a, d), AnnounceError::kOk);
  a = sample();
  a.tcp_port = 0;
  EXPECT_NE(encode_announcement(a, d), AnnounceError::kOk);
  EXPECT_EQ(d, Bytes{9});
}

}  // namespace
