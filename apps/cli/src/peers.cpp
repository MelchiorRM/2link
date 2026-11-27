#include "peers.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>

#include "twolink/core/utf8.hpp"

namespace twolink::cli {

namespace {

constexpr std::string_view kDefaultName = "2link-device";
constexpr std::size_t kMaxName = 64;

}  // namespace

PeerMatch resolve_peer(const identity::TrustStore& trust, std::string_view query) {
  PeerMatch m;
  for (const identity::PeerRecord& r : trust.peers()) {
    if (r.name == query) m.matches.push_back(&r);
  }
  if (m.matches.empty()) {
    std::string hex;
    for (const char c : query) {
      if (c == '-') continue;
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        hex.clear();
        break;
      }
      hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (hex.size() >= 4) {
      for (const identity::PeerRecord& r : trust.peers()) {
        if (identity::to_hex(r.device_id).starts_with(hex)) m.matches.push_back(&r);
      }
    }
  }
  m.result = m.matches.empty()       ? PeerMatch::Result::kNotFound
             : m.matches.size() == 1 ? PeerMatch::Result::kFound
                                     : PeerMatch::Result::kAmbiguous;
  return m;
}

std::string sanitize_device_name(std::string_view raw) {
  std::string name;
  // Keep valid UTF-8 sequences and printable ASCII; replace the rest with '-'.
  std::size_t i = 0;
  while (i < raw.size()) {
    const auto b = static_cast<unsigned char>(raw[i]);
    std::size_t len = b < 0x80 ? 1 : b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : b >= 0xC0 ? 2 : 1;
    len = std::min(len, raw.size() - i);
    const std::string_view ch = raw.substr(i, len);
    const bool ok = len == 1 ? (b >= 0x20 && b < 0x7F) : is_valid_utf8(ch);
    if (name.size() + (ok ? len : 1) > kMaxName) break;
    name += ok ? std::string(ch) : std::string("-");
    i += ok ? len : 1;
  }
  while (!name.empty() && name.back() == ' ') name.pop_back();
  return name.empty() ? std::string(kDefaultName) : name;
}

std::string format_utc(std::int64_t unix_seconds) {
  using namespace std::chrono;
  const sys_seconds t{seconds{unix_seconds}};
  const auto day = floor<days>(t);
  const year_month_day ymd{day};
  const hh_mm_ss hms{t - day};
  char buf[64];
  std::snprintf(buf, sizeof buf, "%04d-%02u-%02u %02d:%02d UTC", static_cast<int>(ymd.year()),
                static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                static_cast<int>(hms.hours().count()), static_cast<int>(hms.minutes().count()));
  return buf;
}

}  // namespace twolink::cli
