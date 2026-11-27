// Pairing window, limits and rate limiter, spec v0.1.2 §4.6 (threat model H2, H9).

#include "twolink/connection/pairing_gate.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>

namespace {

using namespace std::chrono_literals;
using twolink::connection::Clock;
using twolink::connection::kMaxPairHandshakes;
using twolink::connection::PairAttempt;
using twolink::connection::PairingGate;
using twolink::connection::PairingWindow;
using twolink::connection::RateLimiter;
using Admit = PairingGate::Admit;

const Clock::time_point kT0{};

TEST(PairingWindow, OpensForFiveMinutes) {
  PairingWindow w;
  EXPECT_FALSE(w.is_open(kT0));
  w.open(kT0);
  EXPECT_TRUE(w.is_open(kT0));
  EXPECT_TRUE(w.is_open(kT0 + 5min - 1s));
  EXPECT_FALSE(w.is_open(kT0 + 5min));
  w.open(kT0);
  w.close();
  EXPECT_FALSE(w.is_open(kT0));
}

TEST(RateLimiter, BlocksAfterThreeFailuresInTenMinutes) {  // H2
  RateLimiter l;
  EXPECT_TRUE(l.allowed("a", kT0));
  l.record_failure("a", kT0);
  l.record_failure("a", kT0 + 1min);
  EXPECT_TRUE(l.allowed("a", kT0 + 2min));
  l.record_failure("a", kT0 + 2min);
  EXPECT_FALSE(l.allowed("a", kT0 + 2min));
  EXPECT_FALSE(l.allowed("a", kT0 + 12min - 1s));
  EXPECT_TRUE(l.allowed("a", kT0 + 12min));  // block lasts 10 min
  // Counting starts afresh after a block.
  l.record_failure("a", kT0 + 13min);
  EXPECT_TRUE(l.allowed("a", kT0 + 13min));
}

TEST(RateLimiter, OldFailuresExpire) {
  RateLimiter l;
  l.record_failure("a", kT0);
  l.record_failure("a", kT0 + 1min);
  l.record_failure("a", kT0 + 10min);  // the first one is 10 min old: dropped
  EXPECT_TRUE(l.allowed("a", kT0 + 10min));
  l.record_failure("a", kT0 + 10min + 30s);
  EXPECT_FALSE(l.allowed("a", kT0 + 10min + 30s));
}

TEST(RateLimiter, NoGlobalLockout) {  // H2
  RateLimiter l;
  for (int i = 0; i < 3; ++i) l.record_failure("a", kT0);
  EXPECT_FALSE(l.allowed("a", kT0));
  EXPECT_TRUE(l.allowed("b", kT0));
}

TEST(RateLimiter, TableIsBoundedAndEvictsLeastRecentlySeen) {  // H2, H9
  RateLimiter l;
  for (int i = 0; i < 3; ++i) l.record_failure("kept", kT0);
  for (int i = 0; i < 300; ++i) {
    l.record_failure("src" + std::to_string(i), kT0);
    EXPECT_FALSE(l.allowed("kept", kT0));  // seen each time: stays recent and blocked
  }
  EXPECT_EQ(l.size(), 256u);
  EXPECT_TRUE(l.allowed("src0", kT0));  // evicted first: no state left
}

TEST(RateLimiter, UnseenBlockedSourceIsEvictedWhenTheTableIsFull) {  // spec: LRU first
  RateLimiter l;
  for (int i = 0; i < 3; ++i) l.record_failure("old", kT0);
  for (int i = 0; i < 256; ++i) l.record_failure("src" + std::to_string(i), kT0);
  EXPECT_EQ(l.size(), 256u);
  EXPECT_TRUE(l.allowed("old", kT0));
}

TEST(PairingGate, RefusesOutsideTheWindow) {  // H2
  PairingGate g;
  std::optional<PairAttempt> a;
  EXPECT_EQ(g.admit("a", kT0, a), Admit::kWindowClosed);
  g.window().open(kT0);
  EXPECT_EQ(g.admit("a", kT0, a), Admit::kAccepted);
  ASSERT_TRUE(a);
  g.fail(*a, kT0);
  EXPECT_EQ(g.admit("a", kT0 + 5min, a), Admit::kWindowClosed);
}

TEST(PairingGate, WindowClosesAfterOneSuccess) {  // H2
  PairingGate g;
  g.window().open(kT0);
  std::optional<PairAttempt> a;
  ASSERT_EQ(g.admit("a", kT0, a), Admit::kAccepted);
  ASSERT_TRUE(g.promote(*a));
  g.succeed(*a);
  std::optional<PairAttempt> b;
  EXPECT_EQ(g.admit("b", kT0, b), Admit::kWindowClosed);
}

TEST(PairingGate, AtMostFourHandshakesAndOneAwaitingConfirm) {  // H9
  PairingGate g;
  g.window().open(kT0);
  std::vector<PairAttempt> attempts;
  for (std::size_t i = 0; i < kMaxPairHandshakes; ++i) {
    std::optional<PairAttempt> a;
    ASSERT_EQ(g.admit("s" + std::to_string(i), kT0, a), Admit::kAccepted);
    attempts.push_back(std::move(*a));
  }
  std::optional<PairAttempt> extra;
  EXPECT_EQ(g.admit("x", kT0, extra), Admit::kBusy);
  EXPECT_EQ(g.handshaking(), 4u);

  ASSERT_TRUE(g.promote(attempts[0]));
  EXPECT_FALSE(g.promote(attempts[1]));  // one AWAIT_CONFIRM at a time
  EXPECT_TRUE(g.awaiting_confirm());
  EXPECT_EQ(g.handshaking(), 3u);
  EXPECT_EQ(g.admit("x", kT0, extra), Admit::kAccepted);  // a slot freed up
  g.fail(*extra, kT0);

  g.fail(attempts[0], kT0);
  EXPECT_FALSE(g.awaiting_confirm());
  EXPECT_TRUE(g.promote(attempts[1]));
  // Finishing twice is harmless.
  g.fail(attempts[0], kT0);
  EXPECT_TRUE(g.awaiting_confirm());
}

TEST(PairingGate, FailuresFeedTheRateLimiter) {  // H2: A blocked, B accepted
  PairingGate g;
  g.window().open(kT0);
  for (int i = 0; i < 3; ++i) {
    std::optional<PairAttempt> a;
    ASSERT_EQ(g.admit("A", kT0, a), Admit::kAccepted);
    g.fail(*a, kT0);
  }
  std::optional<PairAttempt> a;
  EXPECT_EQ(g.admit("A", kT0, a), Admit::kRateLimited);
  std::optional<PairAttempt> b;
  EXPECT_EQ(g.admit("B", kT0, b), Admit::kAccepted);
  g.fail(*b, kT0);
  g.window().open(kT0 + 10min);
  EXPECT_EQ(g.admit("A", kT0 + 10min, a), Admit::kAccepted);
  g.fail(*a, kT0 + 10min);
}

TEST(PairingGate, OutgoingPairingUsesOnlyTheConfirmSlot) {
  PairingGate g;  // no window needed for an outgoing pairing
  PairAttempt out = g.begin_outgoing();
  ASSERT_TRUE(g.promote(out));
  g.fail(out, kT0);  // no source: nothing recorded
  EXPECT_FALSE(g.awaiting_confirm());
  EXPECT_EQ(g.handshaking(), 0u);
}

}  // namespace
