#include "twolink/core/byte_io.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

namespace {

using twolink::ByteReader;
using twolink::ByteWriter;
using twolink::load_be;
using twolink::store_be;

TEST(ByteIo, StoreIsBigEndian) {
  std::array<std::uint8_t, 8> b{};
  store_be<std::uint64_t>(b, 0x0102030405060708ull);
  EXPECT_EQ(b, (std::array<std::uint8_t, 8>{1, 2, 3, 4, 5, 6, 7, 8}));

  std::array<std::uint8_t, 4> w{};
  store_be<std::uint32_t>(w, 0xDEADBEEFu);
  EXPECT_EQ(w, (std::array<std::uint8_t, 4>{0xDE, 0xAD, 0xBE, 0xEF}));

  std::array<std::uint8_t, 2> h{};
  store_be<std::uint16_t>(h, 0xABCDu);
  EXPECT_EQ(h, (std::array<std::uint8_t, 2>{0xAB, 0xCD}));
}

TEST(ByteIo, LoadRoundTripsExtremes) {
  for (std::uint64_t v : {0ull, 1ull, 0xFFull, 0x8000000000000000ull, ~0ull}) {
    std::array<std::uint8_t, 8> b{};
    store_be<std::uint64_t>(b, v);
    EXPECT_EQ(load_be<std::uint64_t>(b), v);
  }
}

TEST(ByteIo, ConstexprUsable) {
  constexpr auto v = [] {
    std::array<std::uint8_t, 4> b{};
    store_be<std::uint32_t>(b, 0x11223344u);
    return load_be<std::uint32_t>(b);
  }();
  static_assert(v == 0x11223344u);
}

TEST(ByteIo, ReaderReadsSequentially) {
  const std::array<std::uint8_t, 7> data{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  ByteReader r{data};
  std::uint8_t a = 0;
  std::uint16_t b = 0;
  std::uint32_t c = 0;
  ASSERT_TRUE(r.read(a));
  ASSERT_TRUE(r.read(b));
  ASSERT_TRUE(r.read(c));
  EXPECT_EQ(a, 0x01);
  EXPECT_EQ(b, 0x0203);
  EXPECT_EQ(c, 0x04050607u);
  EXPECT_EQ(r.remaining(), 0u);
}

TEST(ByteIo, ReaderFailedReadConsumesNothing) {
  const std::array<std::uint8_t, 3> data{0xAA, 0xBB, 0xCC};
  ByteReader r{data};
  std::uint32_t v = 0x12345678u;
  EXPECT_FALSE(r.read(v));
  EXPECT_EQ(v, 0x12345678u);
  EXPECT_EQ(r.position(), 0u);

  std::array<std::uint8_t, 4> out{};
  EXPECT_FALSE(r.read_bytes(out));
  std::span<const std::uint8_t> view;
  EXPECT_FALSE(r.view_bytes(4, view));
  EXPECT_EQ(r.position(), 0u);

  ASSERT_TRUE(r.view_bytes(3, view));
  EXPECT_EQ(view.size(), 3u);
  EXPECT_EQ(view[2], 0xCC);
}

TEST(ByteIo, ReaderOnEmptyInput) {
  ByteReader r{std::span<const std::uint8_t>{}};
  std::uint8_t v = 0;
  EXPECT_FALSE(r.read(v));
  std::span<const std::uint8_t> view;
  EXPECT_TRUE(r.view_bytes(0, view));
}

TEST(ByteIo, WriterRespectsBounds) {
  std::array<std::uint8_t, 5> buf{};
  ByteWriter w{buf};
  ASSERT_TRUE(w.write<std::uint32_t>(0xA1B2C3D4u));
  EXPECT_FALSE(w.write<std::uint16_t>(0xFFFFu));
  EXPECT_EQ(w.position(), 4u);
  const std::array<std::uint8_t, 2> two{9, 9};
  EXPECT_FALSE(w.write_bytes(two));
  ASSERT_TRUE(w.write<std::uint8_t>(0xE5));
  EXPECT_EQ(buf, (std::array<std::uint8_t, 5>{0xA1, 0xB2, 0xC3, 0xD4, 0xE5}));
}

}  // namespace
