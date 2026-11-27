#include "twolink/connection/pairing_gate.hpp"

#include <algorithm>
#include <utility>

namespace twolink::connection {

void RateLimiter::touch(Entry& e) { lru_.splice(lru_.begin(), lru_, e.lru); }

bool RateLimiter::allowed(const std::string& source, Clock::time_point now) {
  const auto it = entries_.find(source);
  if (it == entries_.end()) return true;  // successes and unknown sources keep no state
  Entry& e = it->second;
  touch(e);
  if (e.blocked_until) {
    if (now < *e.blocked_until) return false;
    e.blocked_until.reset();  // block over: start counting afresh
    e.failures.clear();
  }
  return true;
}

void RateLimiter::record_failure(const std::string& source, Clock::time_point now) {
  auto it = entries_.find(source);
  if (it == entries_.end()) {
    if (entries_.size() >= config_.max_sources && !lru_.empty()) {
      entries_.erase(lru_.back());
      lru_.pop_back();
    }
    lru_.push_front(source);
    it = entries_.emplace(source, Entry{{}, std::nullopt, lru_.begin()}).first;
  } else {
    touch(it->second);
  }
  Entry& e = it->second;
  if (e.blocked_until && now < *e.blocked_until) return;  // already blocked

  std::erase_if(e.failures, [&](Clock::time_point t) { return now - t >= config_.fail_period; });
  e.failures.push_back(now);
  if (e.failures.size() >= config_.fail_limit) {
    e.blocked_until = now + config_.block;
    e.failures.clear();
  }
}

PairAttempt::PairAttempt(PairAttempt&& other) noexcept
    : source_(std::move(other.source_)), stage_(std::exchange(other.stage_, Stage::kDone)) {}

PairingGate::Admit PairingGate::admit(const std::string& source, Clock::time_point now,
                                      std::optional<PairAttempt>& attempt) {
  if (!window_.is_open(now)) return Admit::kWindowClosed;
  if (!limiter_.allowed(source, now)) return Admit::kRateLimited;
  if (handshaking_ >= kMaxPairHandshakes) return Admit::kBusy;
  ++handshaking_;
  attempt.emplace(PairAttempt(source));
  return Admit::kAccepted;
}

PairAttempt PairingGate::begin_outgoing() {
  ++handshaking_;
  return PairAttempt(std::string{});
}

bool PairingGate::promote(PairAttempt& attempt) noexcept {
  if (attempt.stage_ != PairAttempt::Stage::kHandshaking || awaiting_) return false;
  --handshaking_;
  awaiting_ = true;
  attempt.stage_ = PairAttempt::Stage::kAwaitConfirm;
  return true;
}

void PairingGate::release(PairAttempt& attempt) noexcept {
  switch (attempt.stage_) {
    case PairAttempt::Stage::kHandshaking: --handshaking_; break;
    case PairAttempt::Stage::kAwaitConfirm: awaiting_ = false; break;
    case PairAttempt::Stage::kDone: break;
  }
  attempt.stage_ = PairAttempt::Stage::kDone;
}

void PairingGate::succeed(PairAttempt& attempt) noexcept {
  if (attempt.stage_ == PairAttempt::Stage::kDone) return;
  release(attempt);
  window_.close();  // one successful pairing closes the window (§4.6)
}

void PairingGate::fail(PairAttempt& attempt, Clock::time_point now) {
  if (attempt.stage_ == PairAttempt::Stage::kDone) return;
  release(attempt);
  if (!attempt.source_.empty()) limiter_.record_failure(attempt.source_, now);
}

}  // namespace twolink::connection
