#include "twolink/core/utf8.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

using twolink::is_valid_utf8;

TEST(Utf8, AcceptsValidText) {
  EXPECT_TRUE(is_valid_utf8(""));
  EXPECT_TRUE(is_valid_utf8("plain ascii"));
  EXPECT_TRUE(is_valid_utf8("caf\xC3\xA9"));              // U+00E9
  EXPECT_TRUE(is_valid_utf8("\xE2\x82\xAC"));             // U+20AC
  EXPECT_TRUE(is_valid_utf8("\xF0\x9F\x98\x80"));         // U+1F600
  EXPECT_TRUE(is_valid_utf8("\xED\x9F\xBF"));             // U+D7FF, just below surrogates
  EXPECT_TRUE(is_valid_utf8("\xEE\x80\x80"));             // U+E000, just above
  EXPECT_TRUE(is_valid_utf8("\xF4\x8F\xBF\xBF"));         // U+10FFFF
  EXPECT_TRUE(is_valid_utf8(std::string("a\0b", 3)));     // NUL is valid UTF-8
}

TEST(Utf8, RejectsMalformedText) {
  EXPECT_FALSE(is_valid_utf8("\x80"));                    // lone continuation
  EXPECT_FALSE(is_valid_utf8("\xC3"));                    // truncated
  EXPECT_FALSE(is_valid_utf8("\xE2\x82"));                // truncated
  EXPECT_FALSE(is_valid_utf8("\xC3\x28"));                // bad continuation
  EXPECT_FALSE(is_valid_utf8("\xE2\x28\xA1"));
  EXPECT_FALSE(is_valid_utf8("\xF0\x9F\x98\x28"));
  EXPECT_FALSE(is_valid_utf8("\xC0\xAF"));                // overlong '/'
  EXPECT_FALSE(is_valid_utf8("\xC1\xBF"));
  EXPECT_FALSE(is_valid_utf8("\xE0\x80\xAF"));            // overlong
  EXPECT_FALSE(is_valid_utf8("\xF0\x80\x80\xAF"));        // overlong
  EXPECT_FALSE(is_valid_utf8("\xED\xA0\x80"));            // U+D800 surrogate
  EXPECT_FALSE(is_valid_utf8("\xED\xBF\xBF"));            // U+DFFF surrogate
  EXPECT_FALSE(is_valid_utf8("\xF4\x90\x80\x80"));        // U+110000
  EXPECT_FALSE(is_valid_utf8("\xF5\x80\x80\x80"));
  EXPECT_FALSE(is_valid_utf8("\xFF"));
  EXPECT_FALSE(is_valid_utf8("ok\xC3"));                  // truncated at the end
}

}  // namespace
