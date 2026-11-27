// Handshake TLV payload, spec v0.1.2 §4.3 (threat model H7), and SAS §4.5 (H1).

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "twolink/handshake/payload.hpp"
#include "twolink/handshake/sas.hpp"

namespace {

using twolink::handshake::ConnectionRole;
using twolink::handshake::decode_payload;
using twolink::handshake::encode_payload;
using twolink::handshake::HandshakePayload;
using twolink::handshake::PayloadError;

using Bytes = std::vector<std::uint8_t>;

void tlv(Bytes& out, std::uint8_t tag, const Bytes& value) {
  out.push_back(tag);
  out.push_back(static_cast<std::uint8_t>(value.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }

// DEVICE_NAME "pc" and ROLE primary.
Bytes minimal() {
  Bytes b;
  tlv(b, 0x01, str("pc"));
  tlv(b, 0x02, {0});
  return b;
}

PayloadError decode(const Bytes& b, HandshakePayload* out = nullptr) {
  HandshakePayload p;
  const PayloadError e = decode_payload(b, p);
  if (out) *out = p;
  return e;
}

TEST(Payload, EncodeIsTheSpecLayout) {
  Bytes b;
  ASSERT_EQ(encode_payload(HandshakePayload{"pc", ConnectionRole::kBulk, 0}, b), PayloadError::kOk);
  EXPECT_EQ(b, (Bytes{0x01, 0, 2, 'p', 'c', 0x02, 0, 1, 1, 0x03, 0, 4, 0, 0, 0, 0}));
}

TEST(Payload, RoundTrip) {
  for (const HandshakePayload& p :
       {HandshakePayload{"laptop", ConnectionRole::kPrimary, std::nullopt},
        HandshakePayload{std::string(64, 'x'), ConnectionRole::kBulk, 0x12345678u},
        HandshakePayload{"caf\xC3\xA9", ConnectionRole::kPrimary, 0u}}) {
    Bytes b;
    ASSERT_EQ(encode_payload(p, b), PayloadError::kOk);
    HandshakePayload got;
    ASSERT_EQ(decode(b, &got), PayloadError::kOk);
    EXPECT_EQ(got, p);
  }
}

TEST(Payload, EncodeRejectsInvalidNames) {
  Bytes b;
  EXPECT_EQ(encode_payload(HandshakePayload{"", ConnectionRole::kPrimary, {}}, b),
            PayloadError::kBadDeviceName);
  EXPECT_EQ(encode_payload(HandshakePayload{std::string(65, 'x'), ConnectionRole::kPrimary, {}}, b),
            PayloadError::kBadDeviceName);
  EXPECT_EQ(encode_payload(HandshakePayload{"\xFF", ConnectionRole::kPrimary, {}}, b),
            PayloadError::kBadDeviceName);
  EXPECT_TRUE(b.empty());
}

TEST(Payload, OrderOfTagsDoesNotMatter) {
  Bytes b;
  tlv(b, 0x02, {1});
  tlv(b, 0x01, str("pc"));
  HandshakePayload got;
  ASSERT_EQ(decode(b, &got), PayloadError::kOk);
  EXPECT_EQ(got.role, ConnectionRole::kBulk);
}

TEST(Payload, UnknownOptionalTagIsIgnored) {  // H7
  for (int tag : {0x00, 0x04, 0x7F}) {
    Bytes b = minimal();
    tlv(b, static_cast<std::uint8_t>(tag), str("future"));
    HandshakePayload got;
    EXPECT_EQ(decode(b, &got), PayloadError::kOk) << tag;
    EXPECT_EQ(got.device_name, "pc");
  }
}

TEST(Payload, UnknownCriticalTagRejectsTheList) {  // H7
  for (int tag : {0x80, 0x81, 0xFF}) {
    Bytes b = minimal();
    tlv(b, static_cast<std::uint8_t>(tag), {});
    EXPECT_EQ(decode(b), PayloadError::kUnknownCritical) << tag;
  }
}

TEST(Payload, DuplicateTagsAreFatal) {
  Bytes known = minimal();
  tlv(known, 0x01, str("other"));
  EXPECT_EQ(decode(known), PayloadError::kDuplicateTag);

  Bytes unknown = minimal();
  tlv(unknown, 0x7F, {});
  tlv(unknown, 0x7F, {});
  EXPECT_EQ(decode(unknown), PayloadError::kDuplicateTag);
}

TEST(Payload, MissingRequiredTagIsFatal) {
  Bytes no_role;
  tlv(no_role, 0x01, str("pc"));
  EXPECT_EQ(decode(no_role), PayloadError::kMissingRequired);
  Bytes no_name;
  tlv(no_name, 0x02, {0});
  EXPECT_EQ(decode(no_name), PayloadError::kMissingRequired);
  EXPECT_EQ(decode({}), PayloadError::kMissingRequired);
}

TEST(Payload, TruncationIsFatal) {
  const Bytes full = minimal();
  for (std::size_t n = 1; n < full.size(); ++n) {
    const Bytes cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
    const PayloadError e = decode(cut);
    EXPECT_TRUE(e == PayloadError::kTruncated || e == PayloadError::kMissingRequired) << n;
  }
  Bytes overlong = minimal();
  overlong.insert(overlong.end(), {0x7F, 0x00, 0x05, 'a'});  // claims 5 bytes, has 1
  EXPECT_EQ(decode(overlong), PayloadError::kTruncated);
}

TEST(Payload, MalformedValuesAreFatal) {
  auto with = [](std::uint8_t tag, const Bytes& v) {
    Bytes b;
    if (tag != 0x01) tlv(b, 0x01, str("pc"));
    if (tag != 0x02) tlv(b, 0x02, {0});
    tlv(b, tag, v);
    return b;
  };
  EXPECT_EQ(decode(with(0x01, {})), PayloadError::kBadDeviceName);
  EXPECT_EQ(decode(with(0x01, Bytes(65, 'x'))), PayloadError::kBadDeviceName);
  EXPECT_EQ(decode(with(0x01, {0xC3})), PayloadError::kBadDeviceName);
  EXPECT_EQ(decode(with(0x02, {2})), PayloadError::kBadRole);
  EXPECT_EQ(decode(with(0x02, {0, 0})), PayloadError::kBadRole);
  EXPECT_EQ(decode(with(0x02, {})), PayloadError::kBadRole);
  EXPECT_EQ(decode(with(0x03, {0, 0, 0})), PayloadError::kBadFeatures);
}

// --- SAS (§4.5) ---------------------------------------------------------------

using twolink::crypto::HandshakeHash;
using twolink::handshake::format_sas;
using twolink::handshake::sas_string;

TEST(Sas, KnownAnswers) {  // H1; expected values computed with Python hashlib
  HandshakeHash zeros{};
  EXPECT_EQ(sas_string(zeros), "491 600");

  HandshakeHash counting{};
  for (std::size_t i = 0; i < counting.size(); ++i) counting[i] = static_cast<std::uint8_t>(i);
  EXPECT_EQ(sas_string(counting), "041 444");

  HandshakeHash ones{};
  ones.fill(0xFF);
  EXPECT_EQ(sas_string(ones), "543 582");

  HandshakeHash small{};  // 1013 as a 64-byte big-endian integer
  small[62] = 0x03;
  small[63] = 0xF5;
  EXPECT_EQ(sas_string(small), "000 271");
}

TEST(Sas, Formatting) {
  EXPECT_EQ(format_sas(0), "000 000");
  EXPECT_EQ(format_sas(7), "000 007");
  EXPECT_EQ(format_sas(123456), "123 456");
  EXPECT_EQ(format_sas(999999), "999 999");
}

}  // namespace
