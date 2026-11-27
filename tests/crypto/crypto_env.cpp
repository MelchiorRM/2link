// Initialises libsodium and noise-c once for every test in the binary.

#include <gtest/gtest.h>

#include "twolink/crypto/keys.hpp"

namespace {

class CryptoEnvironment : public ::testing::Environment {
 public:
  void SetUp() override { ASSERT_TRUE(twolink::crypto::initialize()); }
};

[[maybe_unused]] const auto* const kEnv =
    ::testing::AddGlobalTestEnvironment(new CryptoEnvironment);

}  // namespace
