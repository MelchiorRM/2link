#include <gtest/gtest.h>

#include "twolink/core/version.hpp"

TEST(Smoke, VersionIsSet) {
  EXPECT_FALSE(twolink::library_version().empty());
  EXPECT_EQ(twolink::kProtocolVersion, 1);
}
