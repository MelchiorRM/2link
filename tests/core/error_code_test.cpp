#include "twolink/core/error_code.hpp"

#include <gtest/gtest.h>

namespace {

using twolink::ErrorCode;

TEST(ErrorCode, WireValuesMatchSpec) {
  EXPECT_EQ(static_cast<std::uint16_t>(ErrorCode::kNoError), 0x0000);
  EXPECT_EQ(static_cast<std::uint16_t>(ErrorCode::kDecryptFailed), 0x0004);
  EXPECT_EQ(static_cast<std::uint16_t>(ErrorCode::kPairingTimeout), 0x000A);
  EXPECT_EQ(static_cast<std::uint16_t>(ErrorCode::kInternalError), 0x000F);
}

TEST(ErrorCode, UnknownWireCodeIsProtocolError) {
  EXPECT_EQ(twolink::error_code_from_wire(0x0005), ErrorCode::kReplayDetected);
  EXPECT_EQ(twolink::error_code_from_wire(0x0010), ErrorCode::kProtocolError);
  EXPECT_EQ(twolink::error_code_from_wire(0xFFFF), ErrorCode::kProtocolError);
}

TEST(ErrorCode, LocalOnlyCodes) {
  EXPECT_TRUE(twolink::is_local_only(ErrorCode::kHandshakeFailed));
  EXPECT_TRUE(twolink::is_local_only(ErrorCode::kUnknownPeer));
  EXPECT_TRUE(twolink::is_local_only(ErrorCode::kIdentityChanged));
  EXPECT_FALSE(twolink::is_local_only(ErrorCode::kDecryptFailed));
  EXPECT_FALSE(twolink::is_local_only(ErrorCode::kNoError));
}

TEST(ErrorCode, EveryCodeHasAName) {
  for (std::uint16_t raw = 0; raw <= 0x000F; ++raw) {
    EXPECT_NE(twolink::to_string(static_cast<ErrorCode>(raw)), "UNKNOWN") << raw;
  }
}

}  // namespace
