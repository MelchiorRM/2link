#include <gtest/gtest.h>

#include "twolink/framing/frame.hpp"

TEST(Framing, MaxFrameSizeIsBounded) {
  EXPECT_GT(twolink::framing::max_frame_size(), 0u);
  EXPECT_LE(twolink::framing::max_frame_size(), 16u * 1024u * 1024u);
}
