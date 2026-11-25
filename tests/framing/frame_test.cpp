#include "twolink/framing/frame.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "test_util.hpp"

namespace {

using namespace twolink::framing;
using twolink::ErrorCode;
using test::msg_header;
using test::pattern;
using test::raw_header;

constexpr std::uint8_t kV = 1;
constexpr std::uint8_t kMsgType = 0x10;

FrameError decode(const std::array<std::uint8_t, kHeaderSize>& bytes) {
  FrameHeader h;
  return decode_header(bytes, h);
}

TEST(FrameHeader, ConstantsMatchSpec) {
  EXPECT_EQ(kHeaderSize, 28u);
  EXPECT_EQ(kMaxPayload, 524288u);
  EXPECT_EQ(kMaxHandshakePayload, 65535u);
  EXPECT_EQ(kAeadTagSize, 16u);
}

TEST(FrameHeader, WireLayoutIsExact) {
  FrameHeader h;
  h.type = FrameType::kChunkData;
  h.stream_id = 0x0A0B0C0Du;
  h.conn_id = 0x0102030405060708ull;
  h.seq = 0x1112131415161718ull;
  h.length = 0x00001000u;

  std::array<std::uint8_t, kHeaderSize> out{};
  ASSERT_EQ(encode_header(h, out), FrameError::kOk);
  const std::array<std::uint8_t, kHeaderSize> expected{
      0x01, 0x24, 0x00, 0x00,                          // version, type, flags, reserved
      0x0A, 0x0B, 0x0C, 0x0D,                          // stream_id
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // conn_id
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,  // seq
      0x00, 0x00, 0x10, 0x00};                         // length
  EXPECT_EQ(out, expected);
}

TEST(FrameHeader, RoundTrip) {
  const FrameHeader h = msg_header(42, 100);
  std::array<std::uint8_t, kHeaderSize> bytes{};
  ASSERT_EQ(encode_header(h, bytes), FrameError::kOk);
  FrameHeader back;
  ASSERT_EQ(decode_header(bytes, back), FrameError::kOk);
  EXPECT_EQ(back, h);
}

TEST(FrameHeader, RoundTripEveryKnownType) {
  for (unsigned raw = 0; raw <= 0xFF; ++raw) {
    const auto t = static_cast<std::uint8_t>(raw);
    if (!is_known_frame_type(t)) continue;
    const auto type = static_cast<FrameType>(t);
    FrameHeader h;
    h.type = type;
    h.stream_id = stream_class_for(type) == StreamClass::kControl     ? kControlStream
                  : stream_class_for(type) == StreamClass::kMessaging ? kMessagingStream
                                                                      : 7u;
    h.length = static_cast<std::uint32_t>(min_payload(type));
    std::array<std::uint8_t, kHeaderSize> bytes{};
    ASSERT_EQ(encode_header(h, bytes), FrameError::kOk) << raw;
    FrameHeader back;
    ASSERT_EQ(decode_header(bytes, back), FrameError::kOk) << raw;
    EXPECT_EQ(back, h);
  }
}

TEST(FrameHeader, KnownTypeRegistry) {
  int known = 0;
  for (unsigned raw = 0; raw <= 0xFF; ++raw) known += is_known_frame_type(static_cast<std::uint8_t>(raw));
  EXPECT_EQ(known, 7 + 4 + 9);
  EXPECT_FALSE(is_known_frame_type(0x00));
  EXPECT_FALSE(is_known_frame_type(0x08));
  EXPECT_FALSE(is_known_frame_type(0x14));
  EXPECT_FALSE(is_known_frame_type(0x29));
  EXPECT_FALSE(is_known_frame_type(0xFF));
}

TEST(FrameHeader, OnlyHandshakeIsPlaintext) {
  EXPECT_FALSE(is_encrypted(FrameType::kHandshake));
  EXPECT_TRUE(is_encrypted(FrameType::kPairConfirm));
  EXPECT_TRUE(is_encrypted(FrameType::kChunkData));
}

TEST(FrameHeader, StreamClasses) {
  EXPECT_EQ(stream_class_of(0), StreamClass::kControl);
  EXPECT_EQ(stream_class_of(1), StreamClass::kMessaging);
  EXPECT_EQ(stream_class_of(2), StreamClass::kTransfer);
  EXPECT_EQ(stream_class_of(0xFFFFFFFFu), StreamClass::kTransfer);
}

TEST(FrameHeaderDecode, RejectsTruncatedInput) {
  const auto bytes = raw_header(kV, kMsgType, 0, 0, 1, 0, 0, 16);
  FrameHeader h;
  for (std::size_t n = 0; n < kHeaderSize; ++n) {
    EXPECT_EQ(decode_header(std::span(bytes).first(n), h), FrameError::kTruncated) << n;
  }
}

TEST(FrameHeaderDecode, RejectsBadVersion) {
  EXPECT_EQ(decode(raw_header(0, kMsgType, 0, 0, 1, 0, 0, 16)), FrameError::kUnsupportedVersion);
  EXPECT_EQ(decode(raw_header(2, kMsgType, 0, 0, 1, 0, 0, 16)), FrameError::kUnsupportedVersion);
}

TEST(FrameHeaderDecode, RejectsNonZeroFlagsAndReserved) {
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0x01, 0, 1, 0, 0, 16)), FrameError::kInvalidFlags);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0x80, 0, 1, 0, 0, 16)), FrameError::kInvalidFlags);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0x01, 1, 0, 0, 16)), FrameError::kInvalidReserved);
}

TEST(FrameHeaderDecode, RejectsUnknownTypes) {
  for (int t : {0x00, 0x08, 0x0F, 0x14, 0x1F, 0x29, 0x7F, 0xFF}) {
    EXPECT_EQ(decode(raw_header(kV, static_cast<std::uint8_t>(t), 0, 0, 0, 0, 0, 16)), FrameError::kUnknownType) << t;
  }
}

TEST(FrameHeaderDecode, RejectsTypeOnWrongStream) {
  EXPECT_EQ(decode(raw_header(kV, 0x01, 0, 0, 1, 0, 0, 16)), FrameError::kWrongStream);  // HANDSHAKE on msg
  EXPECT_EQ(decode(raw_header(kV, 0x07, 0, 0, 5, 0, 0, 16)), FrameError::kWrongStream);  // CLOSE on transfer
  EXPECT_EQ(decode(raw_header(kV, 0x10, 0, 0, 0, 0, 0, 16)), FrameError::kWrongStream);  // MSG on control
  EXPECT_EQ(decode(raw_header(kV, 0x10, 0, 0, 2, 0, 0, 16)), FrameError::kWrongStream);  // MSG on transfer
  EXPECT_EQ(decode(raw_header(kV, 0x24, 0, 0, 0, 0, 0, 16)), FrameError::kWrongStream);  // CHUNK on control
  EXPECT_EQ(decode(raw_header(kV, 0x24, 0, 0, 1, 0, 0, 16)), FrameError::kWrongStream);  // CHUNK on msg
}

TEST(FrameHeaderDecode, EnforcesEncryptedLengthBounds) {
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, 0)), FrameError::kPayloadTooShort);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, 15)), FrameError::kPayloadTooShort);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, 16)), FrameError::kOk);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, kMaxPayload)), FrameError::kOk);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, kMaxPayload + 1)),
            FrameError::kPayloadTooLarge);
  EXPECT_EQ(decode(raw_header(kV, kMsgType, 0, 0, 1, 0, 0, 0xFFFFFFFFu)),
            FrameError::kPayloadTooLarge);
}

TEST(FrameHeaderDecode, EnforcesHandshakeLengthBounds) {
  EXPECT_EQ(decode(raw_header(kV, 0x01, 0, 0, 0, 0, 0, 0)), FrameError::kPayloadTooShort);
  EXPECT_EQ(decode(raw_header(kV, 0x01, 0, 0, 0, 0, 0, 1)), FrameError::kOk);
  EXPECT_EQ(decode(raw_header(kV, 0x01, 0, 0, 0, 0, 0, 65535)), FrameError::kOk);
  EXPECT_EQ(decode(raw_header(kV, 0x01, 0, 0, 0, 0, 0, 65536)), FrameError::kPayloadTooLarge);
}

TEST(FrameHeaderDecode, OutputUntouchedOnError) {
  FrameHeader h = msg_header(9, 99);
  const FrameHeader before = h;
  ASSERT_NE(decode_header(raw_header(2, kMsgType, 0, 0, 1, 0, 0, 16), h), FrameError::kOk);
  EXPECT_EQ(h, before);
}

TEST(FrameHeaderDecode, IgnoresBytesAfterHeader) {
  std::vector<std::uint8_t> buf(kHeaderSize + 10, 0xEE);
  const auto head = raw_header(kV, kMsgType, 0, 0, 1, 3, 4, 16);
  std::copy(head.begin(), head.end(), buf.begin());
  FrameHeader h;
  ASSERT_EQ(decode_header(buf, h), FrameError::kOk);
  EXPECT_EQ(h.conn_id, 3u);
  EXPECT_EQ(h.seq, 4u);
}

TEST(FrameEncode, RejectsInvalidHeaders) {
  std::array<std::uint8_t, kHeaderSize> out{};
  out.fill(0xAB);
  FrameHeader h = msg_header(0, 16);
  h.flags = 1;
  EXPECT_EQ(encode_header(h, out), FrameError::kInvalidFlags);
  h = msg_header(0, 16);
  h.stream_id = kControlStream;
  EXPECT_EQ(encode_header(h, out), FrameError::kWrongStream);
  h = msg_header(0, 8);
  EXPECT_EQ(encode_header(h, out), FrameError::kPayloadTooShort);
  for (auto b : out) EXPECT_EQ(b, 0xAB);  // nothing written
}

TEST(FrameEncode, WholeFrame) {
  const auto payload = pattern(40);
  std::vector<std::uint8_t> out;
  ASSERT_EQ(encode_frame(msg_header(1, 40), payload, out), FrameError::kOk);
  ASSERT_EQ(out.size(), kHeaderSize + 40);
  FrameHeader h;
  ASSERT_EQ(decode_header(out, h), FrameError::kOk);
  EXPECT_EQ(h.length, 40u);
  EXPECT_TRUE(std::equal(payload.begin(), payload.end(), out.begin() + kHeaderSize));
}

TEST(FrameEncode, RejectsLengthMismatch) {
  const auto payload = pattern(40);
  std::vector<std::uint8_t> out{1, 2, 3};
  EXPECT_EQ(encode_frame(msg_header(1, 41), payload, out), FrameError::kLengthMismatch);
  EXPECT_EQ(out, (std::vector<std::uint8_t>{1, 2, 3}));
}

TEST(FrameError, MapsToCloseCodes) {
  EXPECT_EQ(to_error_code(FrameError::kPayloadTooLarge), ErrorCode::kFrameTooLarge);
  EXPECT_EQ(to_error_code(FrameError::kWrongStream), ErrorCode::kInvalidStream);
  EXPECT_EQ(to_error_code(FrameError::kUnsupportedVersion), ErrorCode::kUnsupportedVersion);
  EXPECT_EQ(to_error_code(FrameError::kUnknownType), ErrorCode::kProtocolError);
  EXPECT_EQ(to_error_code(FrameError::kOk), ErrorCode::kNoError);
}

}  // namespace
