#include "twolink/framing/frame_parser.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <vector>

#include "test_util.hpp"

namespace {

using namespace twolink::framing;
using test::make_frame;
using test::msg_header;
using test::pattern;
using test::raw_header;

struct Received {
  FrameHeader header;
  std::vector<std::uint8_t> payload;
};

class Collector {
 public:
  FrameParser::Handler handler() {
    return [this](const FrameView& f) {
      frames.push_back({f.header, {f.payload.begin(), f.payload.end()}});
    };
  }
  std::vector<Received> frames;
};

// Three valid frames of different sizes, concatenated.
std::vector<std::uint8_t> three_frames() {
  std::vector<std::uint8_t> stream;
  for (std::uint64_t seq = 0; seq < 3; ++seq) {
    const auto len = static_cast<std::uint32_t>(16 + seq * 37);
    const auto f = make_frame(msg_header(seq, len), pattern(len, static_cast<std::uint8_t>(seq)));
    stream.insert(stream.end(), f.begin(), f.end());
  }
  return stream;
}

void expect_three_frames(const std::vector<Received>& frames) {
  ASSERT_EQ(frames.size(), 3u);
  for (std::uint64_t seq = 0; seq < 3; ++seq) {
    const auto len = static_cast<std::uint32_t>(16 + seq * 37);
    EXPECT_EQ(frames[seq].header, msg_header(seq, len));
    EXPECT_EQ(frames[seq].payload, pattern(len, static_cast<std::uint8_t>(seq)));
  }
}

TEST(FrameParser, SingleFrameInOneRead) {
  FrameParser p;
  Collector c;
  const auto f = make_frame(msg_header(7, 20), pattern(20));
  ASSERT_EQ(p.feed(f, c.handler()), FrameError::kOk);
  ASSERT_EQ(c.frames.size(), 1u);
  EXPECT_EQ(c.frames[0].header, msg_header(7, 20));
  EXPECT_EQ(c.frames[0].payload, pattern(20));
  EXPECT_EQ(p.buffered(), 0u);
}

TEST(FrameParser, SeveralFramesInOneRead) {
  FrameParser p;
  Collector c;
  ASSERT_EQ(p.feed(three_frames(), c.handler()), FrameError::kOk);
  expect_three_frames(c.frames);
  EXPECT_EQ(p.buffered(), 0u);
}

TEST(FrameParser, OneByteAtATime) {
  FrameParser p;
  Collector c;
  const auto stream = three_frames();
  for (std::size_t i = 0; i < stream.size(); ++i) {
    ASSERT_EQ(p.feed(std::span(stream).subspan(i, 1), c.handler()), FrameError::kOk) << i;
  }
  expect_three_frames(c.frames);
}

TEST(FrameParser, EverySplitPoint) {
  const auto stream = three_frames();
  for (std::size_t split = 0; split <= stream.size(); ++split) {
    FrameParser p;
    Collector c;
    ASSERT_EQ(p.feed(std::span(stream).first(split), c.handler()), FrameError::kOk);
    ASSERT_EQ(p.feed(std::span(stream).subspan(split), c.handler()), FrameError::kOk);
    expect_three_frames(c.frames);
    EXPECT_EQ(p.buffered(), 0u) << split;
  }
}

TEST(FrameParser, RandomChunking) {
  const auto stream = three_frames();
  std::mt19937 rng(12345);
  for (int round = 0; round < 200; ++round) {
    FrameParser p;
    Collector c;
    std::size_t pos = 0;
    while (pos < stream.size()) {
      const std::size_t n = std::min<std::size_t>(rng() % 64 + 1, stream.size() - pos);
      ASSERT_EQ(p.feed(std::span(stream).subspan(pos, n), c.handler()), FrameError::kOk);
      pos += n;
    }
    expect_three_frames(c.frames);
  }
}

TEST(FrameParser, MaxSizeFrameAcrossReads) {
  FrameParser p;
  Collector c;
  const auto f = make_frame(msg_header(0, kMaxPayload), pattern(kMaxPayload));
  ASSERT_EQ(f.size(), kMaxFrameSize);
  const std::size_t step = 1500;  // typical MTU-sized reads
  for (std::size_t pos = 0; pos < f.size(); pos += step) {
    ASSERT_EQ(p.feed(std::span(f).subspan(pos, std::min(step, f.size() - pos)), c.handler()),
              FrameError::kOk);
    EXPECT_LE(p.buffered(), kMaxFrameSize);
  }
  ASSERT_EQ(c.frames.size(), 1u);
  EXPECT_EQ(c.frames[0].payload.size(), kMaxPayload);
}

TEST(FrameParser, PartialHeaderIsBuffered) {
  FrameParser p;
  Collector c;
  const auto f = make_frame(msg_header(0, 16), pattern(16));
  ASSERT_EQ(p.feed(std::span(f).first(10), c.handler()), FrameError::kOk);
  EXPECT_EQ(p.buffered(), 10u);
  EXPECT_TRUE(c.frames.empty());
  ASSERT_EQ(p.feed(std::span(f).subspan(10, 25), c.handler()), FrameError::kOk);
  EXPECT_EQ(p.buffered(), 35u);
  ASSERT_EQ(p.feed(std::span(f).subspan(35), c.handler()), FrameError::kOk);
  EXPECT_EQ(c.frames.size(), 1u);
  EXPECT_EQ(p.buffered(), 0u);
}

TEST(FrameParser, EmptyFeedIsNoOp) {
  FrameParser p;
  Collector c;
  EXPECT_EQ(p.feed({}, c.handler()), FrameError::kOk);
  EXPECT_TRUE(c.frames.empty());
}

TEST(FrameParser, OversizeLengthRejectedBeforePayload) {
  FrameParser p;
  Collector c;
  const auto head = raw_header(1, 0x10, 0, 0, 1, 0, 0, 0xFFFFFFFFu);
  EXPECT_EQ(p.feed(head, c.handler()), FrameError::kPayloadTooLarge);
  EXPECT_TRUE(p.failed());
  EXPECT_EQ(p.buffered(), 0u);
  EXPECT_TRUE(c.frames.empty());
}

TEST(FrameParser, OversizeLengthRejectedWhenHeaderSplit) {
  FrameParser p;
  Collector c;
  const auto head = raw_header(1, 0x10, 0, 0, 1, 0, 0, kMaxPayload + 1);
  ASSERT_EQ(p.feed(std::span(head).first(27), c.handler()), FrameError::kOk);
  EXPECT_EQ(p.feed(std::span(head).subspan(27), c.handler()), FrameError::kPayloadTooLarge);
}

TEST(FrameParser, GoodFramesBeforeErrorAreDelivered) {
  FrameParser p;
  Collector c;
  auto stream = make_frame(msg_header(0, 16), pattern(16));
  const auto bad = raw_header(9, 0x10, 0, 0, 1, 0, 1, 16);
  stream.insert(stream.end(), bad.begin(), bad.end());
  EXPECT_EQ(p.feed(stream, c.handler()), FrameError::kUnsupportedVersion);
  EXPECT_EQ(c.frames.size(), 1u);
}

TEST(FrameParser, ErrorIsSticky) {
  FrameParser p;
  Collector c;
  const auto bad = raw_header(1, 0x00, 0, 0, 0, 0, 0, 16);
  ASSERT_EQ(p.feed(bad, c.handler()), FrameError::kUnknownType);
  const auto good = make_frame(msg_header(0, 16), pattern(16));
  EXPECT_EQ(p.feed(good, c.handler()), FrameError::kUnknownType);
  EXPECT_EQ(p.error(), FrameError::kUnknownType);
  EXPECT_TRUE(c.frames.empty());
}

TEST(FrameParser, ResetRecovers) {
  FrameParser p;
  Collector c;
  const auto bad = raw_header(1, 0x00, 0, 0, 0, 0, 0, 16);
  ASSERT_NE(p.feed(bad, c.handler()), FrameError::kOk);
  p.reset();
  EXPECT_FALSE(p.failed());
  const auto good = make_frame(msg_header(0, 16), pattern(16));
  EXPECT_EQ(p.feed(good, c.handler()), FrameError::kOk);
  EXPECT_EQ(c.frames.size(), 1u);
}

TEST(FrameParser, RandomGarbageNeverOverBuffers) {
  std::mt19937 rng(777);
  for (int round = 0; round < 500; ++round) {
    FrameParser p;
    std::vector<std::uint8_t> junk(rng() % 4096);
    for (auto& b : junk) b = static_cast<std::uint8_t>(rng());
    // Make some rounds start with a plausible header to reach payload states.
    if (round % 2 == 0 && junk.size() >= kHeaderSize) {
      const auto h = raw_header(1, 0x10, 0, 0, 1, 0, 0, static_cast<std::uint32_t>(rng() % 2048 + 16));
      std::copy(h.begin(), h.end(), junk.begin());
    }
    std::size_t delivered = 0;
    (void)p.feed(junk, [&](const FrameView& f) { delivered += kHeaderSize + f.payload.size(); });
    EXPECT_LE(p.buffered(), kMaxFrameSize);
    EXPECT_LE(delivered + p.buffered(), junk.size());
  }
}

}  // namespace
