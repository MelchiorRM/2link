// Control-frame and MSG payloads, spec v0.1.2 §3.1-3.2.

#include "twolink/connection/payloads.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

using namespace twolink::connection;
using twolink::ErrorCode;

TEST(Payloads, Ping) {
  const Bytes b = encode_ping(0x0102030405060708ull);
  EXPECT_EQ(b, (Bytes{1, 2, 3, 4, 5, 6, 7, 8}));
  EXPECT_EQ(decode_ping(b), 0x0102030405060708ull);
  EXPECT_FALSE(decode_ping(Bytes(7, 0)));
  EXPECT_FALSE(decode_ping(Bytes(9, 0)));
}

TEST(Payloads, PairReject) {
  EXPECT_EQ(encode_pair_reject(ErrorCode::kPairingRejected), (Bytes{0x00, 0x09}));
  EXPECT_EQ(decode_pair_reject(Bytes{0x00, 0x09}), ErrorCode::kPairingRejected);
  EXPECT_EQ(decode_pair_reject(Bytes{0x12, 0x34}), ErrorCode::kProtocolError);  // unknown code
  EXPECT_FALSE(decode_pair_reject(Bytes{0x00}));
  EXPECT_FALSE(decode_pair_reject(Bytes{0x00, 0x09, 0x00}));
}

TEST(Payloads, Close) {
  const Bytes b = encode_close(ErrorCode::kTimeout, "idle");
  EXPECT_EQ(b, (Bytes{0x00, 0x0C, 0x00, 0x04, 'i', 'd', 'l', 'e'}));
  const auto c = decode_close(b);
  ASSERT_TRUE(c);
  EXPECT_EQ(c->code, ErrorCode::kTimeout);
  EXPECT_EQ(c->reason, "idle");

  EXPECT_FALSE(decode_close(Bytes{0x00, 0x00, 0x00, 0x02, 'a'}));        // short
  EXPECT_FALSE(decode_close(Bytes{0x00, 0x00, 0x00, 0x00, 'a'}));        // trailing
  EXPECT_FALSE(decode_close(Bytes{0x00, 0x00, 0x00, 0x01, 0xFF}));       // not UTF-8
  Bytes too_long{0x00, 0x00, 0x01, 0x01};                                // 257 bytes
  too_long.resize(4 + 257, 'a');
  EXPECT_FALSE(decode_close(too_long));
  EXPECT_EQ(decode_close(Bytes{0xFF, 0xFF, 0, 0})->code, ErrorCode::kProtocolError);
}

TEST(Payloads, CloseReasonIsCutAtACharacterBoundary) {
  std::string reason(255, 'a');
  reason += "\xC3\xA9";  // 2-byte character straddling the 256-byte limit
  const auto c = decode_close(encode_close(ErrorCode::kNoError, reason));
  ASSERT_TRUE(c);
  EXPECT_EQ(c->reason, std::string(255, 'a'));
}

TEST(Payloads, Msg) {
  const Bytes b = encode_msg("hi");
  EXPECT_EQ(b, (Bytes{0, 0, 0, 2, 'h', 'i'}));
  EXPECT_EQ(decode_msg(b), "hi");
  EXPECT_EQ(decode_msg(encode_msg("")), "");

  const std::string max(kMaxMessageText, 'x');
  EXPECT_TRUE(is_valid_message_text(max));
  EXPECT_EQ(decode_msg(encode_msg(max)), max);
  EXPECT_FALSE(is_valid_message_text(max + "x"));

  Bytes over{0x00, 0x00, 0xF0, 0x01};  // 61441
  over.resize(4 + 61441, 'x');
  EXPECT_FALSE(decode_msg(over));
  EXPECT_FALSE(decode_msg(Bytes{0, 0, 0, 3, 'a', 'b'}));
  EXPECT_FALSE(decode_msg(Bytes{0, 0, 0, 1, 'a', 'b'}));
  EXPECT_FALSE(decode_msg(Bytes{0, 0, 0, 1, 0x80}));
  EXPECT_FALSE(is_valid_message_text("\xC3"));
}

}  // namespace
