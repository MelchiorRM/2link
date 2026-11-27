#include "twolink/discovery/device_table.hpp"

#include <algorithm>

namespace twolink::discovery {

DeviceStatus classify(const Announcement& a, const identity::TrustStore& trust) {
  if (const identity::PeerRecord* r = trust.find_by_key(a.static_key);
      r && r->device_id == a.device_id) {
    return DeviceStatus::kPaired;
  }
  return trust.find_by_name(a.device_name).empty() ? DeviceStatus::kUnverified
                                                   : DeviceStatus::kUnverifiedNameClash;
}

bool DeviceTable::allow_source(const std::string& source, Clock::time_point now) {
  auto it = sources_.find(source);
  if (it == sources_.end()) {
    if (sources_.size() >= config_.max_sources && !source_lru_.empty()) {
      sources_.erase(source_lru_.back());
      source_lru_.pop_back();
    }
    source_lru_.push_front(source);
    it = sources_.emplace(source, Source{now, 0, source_lru_.begin()}).first;
  } else {
    source_lru_.splice(source_lru_.begin(), source_lru_, it->second.lru);
  }
  Source& s = it->second;
  if (now - s.window_start >= config_.per_source_window) {
    s.window_start = now;
    s.count = 0;
  }
  if (s.count >= config_.per_source_burst) return false;
  ++s.count;
  return true;
}

void DeviceTable::evict_one() {
  // Oldest unpaired entry first; only if every entry is paired, the oldest.
  auto victim = devices_.end();
  bool victim_paired = true;
  for (auto it = devices_.begin(); it != devices_.end(); ++it) {
    const bool paired = is_paired_ && is_paired_(it->second.announcement);
    const bool better = victim == devices_.end() || (victim_paired && !paired) ||
                        (victim_paired == paired && it->second.last_seen < victim->second.last_seen);
    if (better) {
      victim = it;
      victim_paired = paired;
    }
  }
  if (victim != devices_.end()) devices_.erase(victim);
}

DeviceTable::Update DeviceTable::update(const Announcement& a, const std::string& source,
                                        Clock::time_point now) {
  if (!allow_source(source, now)) return Update::kRateLimited;
  expire(now);
  if (const auto it = devices_.find(a.device_id); it != devices_.end()) {
    it->second.announcement = a;  // the name or port may change; the key cannot
    it->second.address = source;
    it->second.last_seen = now;
    return Update::kRefreshed;
  }
  if (config_.max_devices == 0) return Update::kDropped;
  if (devices_.size() >= config_.max_devices) {
    const bool new_is_paired = is_paired_ && is_paired_(a);
    // A full table of paired devices does not make room for an unpaired one.
    const bool any_unpaired = std::any_of(devices_.begin(), devices_.end(), [&](const auto& kv) {
      return !(is_paired_ && is_paired_(kv.second.announcement));
    });
    if (!new_is_paired && !any_unpaired) return Update::kDropped;
    evict_one();
  }
  devices_.emplace(a.device_id, DiscoveredDevice{a, source, now});
  return Update::kAdded;
}

void DeviceTable::expire(Clock::time_point now) {
  std::erase_if(devices_, [&](const auto& kv) { return now - kv.second.last_seen >= config_.expiry; });
}

std::vector<DiscoveredDevice> DeviceTable::devices(Clock::time_point now) const {
  std::vector<DiscoveredDevice> out;
  for (const auto& [id, d] : devices_) {
    if (now - d.last_seen < config_.expiry) out.push_back(d);
  }
  std::sort(out.begin(), out.end(),
            [](const DiscoveredDevice& x, const DiscoveredDevice& y) { return x.last_seen > y.last_seen; });
  return out;
}

std::optional<DiscoveredDevice> DeviceTable::find(const identity::DeviceId& id,
                                                  Clock::time_point now) const {
  const auto it = devices_.find(id);
  if (it == devices_.end() || now - it->second.last_seen >= config_.expiry) return std::nullopt;
  return it->second;
}

}  // namespace twolink::discovery
