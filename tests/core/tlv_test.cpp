// Generic TLV rules, spec v0.1.3 §4.3.

#include "twolink/core/tlv.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {

using twolink::append_tlv;
using twolink::parse_tlv;
using twolink::TlvError;
using twolink::TlvVisit;
using Bytes = std::vector<std::uint8_t>;

// Knows tag 0x01 (value must be 1 byte); everything else is unknown.
TlvError parse(const Bytes& b, std::vector<std::uint8_t>* tags = nullptr) {
  return parse_tlv(b, [&](std::uint8_t tag, std::span<const std::uint8_t> v) {
    if (tags) tags->push_back(tag);
    if (tag != 0x01) return TlvVisit::kUnknown;
    return v.size() == 1 ? TlvVisit::kAccepted : TlvVisit::kBadValue;
  });
}

TEST(Tlv, AppendLayout) {
  Bytes b;
  append_tlv(b, 0x05, Bytes{0xAA, 0xBB});
  EXPECT_EQ(b, (Bytes{0x05, 0x00, 0x02, 0xAA, 0xBB}));
}

TEST(Tlv, VisitsInOrderAndIgnoresUnknownOptional) {
  Bytes b;
  append_tlv(b, 0x01, Bytes{1});
  append_tlv(b, 0x7F, Bytes{1, 2, 3});
  append_tlv(b, 0x00, {});
  std::vector<std::uint8_t> tags;
  EXPECT_EQ(parse(b, &tags), TlvError::kOk);
  EXPECT_EQ(tags, (std::vector<std::uint8_t>{0x01, 0x7F, 0x00}));
  EXPECT_EQ(parse({}), TlvError::kOk);
}

TEST(Tlv, Errors) {
  Bytes critical;
  append_tlv(critical, 0x80, {});
  EXPECT_EQ(parse(critical), TlvError::kUnknownCritical);

  Bytes dup;
  append_tlv(dup, 0x22, {});
  append_tlv(dup, 0x22, {});
  EXPECT_EQ(parse(dup), TlvError::kDuplicateTag);

  Bytes bad;
  append_tlv(bad, 0x01, Bytes{1, 2});
  EXPECT_EQ(parse(bad), TlvError::kBadValue);

  EXPECT_EQ(parse(Bytes{0x01}), TlvError::kTruncated);
  EXPECT_EQ(parse(Bytes{0x01, 0x00}), TlvError::kTruncated);
  EXPECT_EQ(parse(Bytes{0x01, 0x00, 0x02, 0x00}), TlvError::kTruncated);
}

}  // namespace
