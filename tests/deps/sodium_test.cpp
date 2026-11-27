// Checks that libsodium from vcpkg links and works on every platform.

#include <sodium.h>

#include <array>
#include <cstddef>
#include <string>

#include <gtest/gtest.h>

namespace {

std::string to_hex(const unsigned char* data, std::size_t size) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out += kDigits[data[i] >> 4];
    out += kDigits[data[i] & 0x0F];
  }
  return out;
}

}  // namespace

TEST(Sodium, Initialises) { EXPECT_GE(sodium_init(), 0); }

TEST(Sodium, Blake2b256OfEmptyInputMatchesKnownAnswer) {
  ASSERT_GE(sodium_init(), 0);
  std::array<unsigned char, 32> out{};
  ASSERT_EQ(crypto_generichash(out.data(), out.size(), nullptr, 0, nullptr, 0), 0);
  EXPECT_EQ(to_hex(out.data(), out.size()),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
}
