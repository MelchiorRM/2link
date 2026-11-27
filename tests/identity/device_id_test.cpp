// device_id derivation and display form (spec §4.1).

#include "twolink/identity/device_id.hpp"

#include <gtest/gtest.h>

namespace {

using namespace twolink;

crypto::PublicKey counting_key() {
  crypto::PublicKey k{};
  for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(i);
  return k;
}

TEST(DeviceId, IsBlake2b256OfThePublicKey) {
  // Expected value computed independently with Python's hashlib.blake2b.
  EXPECT_EQ(identity::to_hex(identity::device_id_from_key(counting_key())),
            "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6");
}

TEST(DeviceId, DisplayFormIsFirstEightBytesInFourGroups) {
  EXPECT_EQ(identity::display_form(identity::device_id_from_key(counting_key())),
            "cb2f-5160-fc1f-7e05");
  identity::DeviceId zero{};
  EXPECT_EQ(identity::display_form(zero), "0000-0000-0000-0000");
}

TEST(DeviceId, ChangedKeyGivesChangedId) {  // spec §4.8: a new key is a new device
  crypto::PublicKey k = counting_key();
  const identity::DeviceId a = identity::device_id_from_key(k);
  k[31] ^= 0x01;
  EXPECT_NE(identity::device_id_from_key(k), a);
}

}  // namespace
