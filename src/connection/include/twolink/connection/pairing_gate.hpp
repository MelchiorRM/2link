#pragma once

// Pairing window, bounded concurrency and per-source rate limiting, spec
// v0.1.2 §4.6 (threat model H2, H9). Pure: time is passed in.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "twolink/session/session.hpp"

namespace twolink::connection {

using Clock = session::Clock;
using namespace std::chrono_literals;

// §4.6 / §6.5 / §9.
inline constexpr Clock::duration kPairWindow = 5min;
inline constexpr std::size_t kMaxPairHandshakes = 4;
inline constexpr std::size_t kPairFailLimit = 3;
inline constexpr Clock::duration kPairFailPeriod = 10min;
inline constexpr Clock::duration kPairBlock = 10min;
inline constexpr std::size_t kPairSourceTable = 256;

// The local pairing window: PAIR is accepted only while it is open.
class PairingWindow {
 public:
  void open(Clock::time_point now, Clock::duration length = kPairWindow) noexcept {
    closes_at_ = now + length;
  }
  void close() noexcept { closes_at_.reset(); }
  [[nodiscard]] bool is_open(Clock::time_point now) const noexcept {
    return closes_at_ && now < *closes_at_;
  }

 private:
  std::optional<Clock::time_point> closes_at_;
};

// Failed PAIR attempts per source (remote IP). After kPairFailLimit failures
// within kPairFailPeriod the source is refused for kPairBlock. At most
// kPairSourceTable sources are tracked; the least recently seen is evicted.
class RateLimiter {
 public:
  struct Config {
    std::size_t fail_limit = kPairFailLimit;
    Clock::duration fail_period = kPairFailPeriod;
    Clock::duration block = kPairBlock;
    std::size_t max_sources = kPairSourceTable;
  };

  RateLimiter() : RateLimiter(Config{}) {}
  explicit RateLimiter(Config config) : config_(config) {}

  // True if a new attempt from source may start. Counts as "seen".
  [[nodiscard]] bool allowed(const std::string& source, Clock::time_point now);

  void record_failure(const std::string& source, Clock::time_point now);

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    std::vector<Clock::time_point> failures;  // within fail_period, oldest first
    std::optional<Clock::time_point> blocked_until;
    std::list<std::string>::iterator lru;
  };

  void touch(Entry& e);

  Config config_;
  std::unordered_map<std::string, Entry> entries_;
  std::list<std::string> lru_;  // front: most recently seen
};

// One PAIR attempt, from admission until success or failure. Every attempt
// must end in PairingGate::succeed() or fail(), or its slot stays taken.
class PairAttempt {
 public:
  PairAttempt(const PairAttempt&) = delete;
  PairAttempt& operator=(const PairAttempt&) = delete;
  PairAttempt(PairAttempt&& other) noexcept;
  PairAttempt& operator=(PairAttempt&&) = delete;
  ~PairAttempt() = default;

  [[nodiscard]] const std::string& source() const noexcept { return source_; }

 private:
  friend class PairingGate;
  enum class Stage : std::uint8_t { kHandshaking, kAwaitConfirm, kDone };
  explicit PairAttempt(std::string source) : source_(std::move(source)) {}

  std::string source_;
  Stage stage_ = Stage::kHandshaking;
};

// Decides whether incoming PAIR attempts may proceed (§4.6). One gate per
// device. Outgoing pairings only take the AWAIT_CONFIRM slot.
class PairingGate {
 public:
  enum class Admit : std::uint8_t {
    kAccepted,
    kWindowClosed,  // no local pairing window open
    kRateLimited,   // source blocked
    kBusy,          // kMaxPairHandshakes PAIR handshakes already running
  };

  PairingGate() = default;
  explicit PairingGate(RateLimiter::Config limiter) : limiter_(limiter) {}

  PairingWindow& window() noexcept { return window_; }

  // Incoming PAIR, first HANDSHAKE frame. On kAccepted, attempt is set and
  // holds a handshake slot until promoted or finished.
  [[nodiscard]] Admit admit(const std::string& source, Clock::time_point now,
                            std::optional<PairAttempt>& attempt);

  // Outgoing PAIR (an explicit user action): no window or limiter applies.
  [[nodiscard]] PairAttempt begin_outgoing();

  // XX completed: takes the single AWAIT_CONFIRM slot. False if another
  // pairing is awaiting confirmation; the caller then fails the attempt.
  [[nodiscard]] bool promote(PairAttempt& attempt) noexcept;

  // Pairing succeeded: releases the slot and closes the window (§4.6).
  void succeed(PairAttempt& attempt) noexcept;

  // Rejected, timed out, handshake failed or connection closed early: releases
  // the slot and counts a failure against the source (incoming only).
  void fail(PairAttempt& attempt, Clock::time_point now);

  [[nodiscard]] std::size_t handshaking() const noexcept { return handshaking_; }
  [[nodiscard]] bool awaiting_confirm() const noexcept { return awaiting_; }

 private:
  void release(PairAttempt& attempt) noexcept;

  PairingWindow window_;
  RateLimiter limiter_;
  std::size_t handshaking_ = 0;
  bool awaiting_ = false;
};

}  // namespace twolink::connection
