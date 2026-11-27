#pragma once

// Devices seen on the LAN, spec v0.1.3 §8 (threat model D1, D4). Pure: time is
// passed in.
//
// Bounded against announcement floods (D4):
// - at most max_devices entries; entries not refreshed within `expiry` vanish;
// - when full, the oldest entry that is not a paired device is evicted first,
//   so a flood of forged devices cannot push paired peers out;
// - each source address may deliver at most per_source_burst announcements per
//   per_source_window; the source table itself is bounded (LRU).
//
// Paired / unverified status is computed against the trust store when asked,
// never stored: discovery does not grant trust (D1).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "twolink/discovery/announcement.hpp"
#include "twolink/identity/trust_store.hpp"

namespace twolink::discovery {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

inline constexpr Clock::duration kAnnounceInterval = 5s;  // §8.1

struct DiscoveredDevice {
  Announcement announcement;
  std::string address;  // source IP of the last announcement
  Clock::time_point last_seen{};
};

enum class DeviceStatus : std::uint8_t {
  kPaired,                // key is in the trust store (trusted only after IK succeeds)
  kUnverified,            // unknown key
  kUnverifiedNameClash,   // unknown key announcing a trusted peer's name: warn (D1)
};

[[nodiscard]] DeviceStatus classify(const Announcement& a, const identity::TrustStore& trust);

struct DeviceTableConfig {
  std::size_t max_devices = 128;
  Clock::duration expiry = 3 * kAnnounceInterval;
  std::size_t max_sources = 256;
  std::size_t per_source_burst = 8;
  Clock::duration per_source_window = kAnnounceInterval;
};

class DeviceTable {
 public:
  using Config = DeviceTableConfig;

  enum class Update : std::uint8_t { kAdded, kRefreshed, kRateLimited, kDropped };

  // `is_paired` tells the table which devices to protect from eviction.
  explicit DeviceTable(Config config = {},
                       std::function<bool(const Announcement&)> is_paired = {})
      : config_(config), is_paired_(std::move(is_paired)) {}

  Update update(const Announcement& a, const std::string& source, Clock::time_point now);

  // Drops entries older than `expiry`.
  void expire(Clock::time_point now);

  // Fresh entries, most recently seen first.
  [[nodiscard]] std::vector<DiscoveredDevice> devices(Clock::time_point now) const;
  [[nodiscard]] std::optional<DiscoveredDevice> find(const identity::DeviceId& id,
                                                     Clock::time_point now) const;
  [[nodiscard]] std::size_t size() const noexcept { return devices_.size(); }
  [[nodiscard]] std::size_t source_count() const noexcept { return sources_.size(); }

 private:
  struct Source {
    Clock::time_point window_start{};
    std::size_t count = 0;
    std::list<std::string>::iterator lru;
  };

  bool allow_source(const std::string& source, Clock::time_point now);
  void evict_one();

  Config config_;
  std::function<bool(const Announcement&)> is_paired_;
  std::map<identity::DeviceId, DiscoveredDevice> devices_;
  std::unordered_map<std::string, Source> sources_;
  std::list<std::string> source_lru_;  // front: most recent
};

}  // namespace twolink::discovery
