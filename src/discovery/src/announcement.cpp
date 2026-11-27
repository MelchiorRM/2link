#include "twolink/discovery/announcement.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "twolink/core/byte_io.hpp"
#include "twolink/core/tlv.hpp"
#include "twolink/core/utf8.hpp"

namespace twolink::discovery {

namespace {

constexpr std::array<std::uint8_t, 4> kMagic{'2', 'L', 'N', 'K'};
constexpr std::size_t kMaxNameSize = 64;

bool valid_name(std::string_view name) noexcept {
  return !name.empty() && name.size() <= kMaxNameSize && is_valid_utf8(name);
}

std::uint8_t tag(AnnounceTag t) { return static_cast<std::uint8_t>(t); }

}  // namespace

Announcement make_announcement(std::string device_name, const crypto::PublicKey& static_key,
                               std::uint16_t tcp_port) {
  return Announcement{std::move(device_name), identity::device_id_from_key(static_key), static_key,
                      tcp_port};
}

std::string_view to_string(AnnounceError error) noexcept {
  switch (error) {
    case AnnounceError::kOk: return "ok";
    case AnnounceError::kTooLarge: return "datagram too large";
    case AnnounceError::kBadHeader: return "bad header";
    case AnnounceError::kBadTlv: return "bad TLV list";
    case AnnounceError::kMissing: return "missing required tag";
    case AnnounceError::kIdMismatch: return "DEVICE_ID does not match the key";
  }
  return "unknown";
}

AnnounceError encode_announcement(const Announcement& a, std::vector<std::uint8_t>& out) {
  if (!valid_name(a.device_name) || a.tcp_port == 0) return AnnounceError::kBadTlv;
  std::vector<std::uint8_t> d(kMagic.begin(), kMagic.end());
  d.push_back(kAnnounceVersion);
  d.push_back(kAnnounceType);
  const auto* name = reinterpret_cast<const std::uint8_t*>(a.device_name.data());
  append_tlv(d, tag(AnnounceTag::kDeviceName), std::span(name, a.device_name.size()));
  append_tlv(d, tag(AnnounceTag::kDeviceId), a.device_id);
  append_tlv(d, tag(AnnounceTag::kStaticPublicKey), a.static_key);
  std::array<std::uint8_t, 2> port{};
  store_be<std::uint16_t>(port, a.tcp_port);
  append_tlv(d, tag(AnnounceTag::kTcpPort), port);
  if (d.size() > kMaxDatagramSize) return AnnounceError::kTooLarge;
  out = std::move(d);
  return AnnounceError::kOk;
}

AnnounceError decode_announcement(std::span<const std::uint8_t> datagram, Announcement& out) {
  if (datagram.size() > kMaxDatagramSize) return AnnounceError::kTooLarge;
  if (datagram.size() < kMagic.size() + 2 ||
      !std::equal(kMagic.begin(), kMagic.end(), datagram.begin()) ||
      datagram[4] != kAnnounceVersion || datagram[5] != kAnnounceType) {
    return AnnounceError::kBadHeader;
  }

  Announcement a;
  bool have_name = false;
  bool have_id = false;
  bool have_key = false;
  bool have_port = false;
  const TlvError err =
      parse_tlv(datagram.subspan(6), [&](std::uint8_t t, std::span<const std::uint8_t> v) {
        switch (static_cast<AnnounceTag>(t)) {
          case AnnounceTag::kDeviceName: {
            const std::string_view name(reinterpret_cast<const char*>(v.data()), v.size());
            if (!valid_name(name)) return TlvVisit::kBadValue;
            a.device_name.assign(name);
            have_name = true;
            return TlvVisit::kAccepted;
          }
          case AnnounceTag::kDeviceId:
            if (v.size() != a.device_id.size()) return TlvVisit::kBadValue;
            std::copy(v.begin(), v.end(), a.device_id.begin());
            have_id = true;
            return TlvVisit::kAccepted;
          case AnnounceTag::kStaticPublicKey:
            if (v.size() != a.static_key.size()) return TlvVisit::kBadValue;
            std::copy(v.begin(), v.end(), a.static_key.begin());
            have_key = true;
            return TlvVisit::kAccepted;
          case AnnounceTag::kTcpPort:
            if (v.size() != 2) return TlvVisit::kBadValue;
            a.tcp_port = load_be<std::uint16_t>(v.first<2>());
            if (a.tcp_port == 0) return TlvVisit::kBadValue;
            have_port = true;
            return TlvVisit::kAccepted;
        }
        return TlvVisit::kUnknown;
      });
  if (err != TlvError::kOk) return AnnounceError::kBadTlv;
  if (!have_name || !have_id || !have_key || !have_port) return AnnounceError::kMissing;
  if (a.device_id != identity::device_id_from_key(a.static_key)) return AnnounceError::kIdMismatch;
  out = std::move(a);
  return AnnounceError::kOk;
}

}  // namespace twolink::discovery
