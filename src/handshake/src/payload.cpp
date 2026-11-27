#include "twolink/handshake/payload.hpp"

#include <array>
#include <bitset>
#include <utility>

#include "twolink/core/byte_io.hpp"
#include "twolink/core/utf8.hpp"

namespace twolink::handshake {

std::string_view to_string(PayloadError error) noexcept {
  switch (error) {
    case PayloadError::kOk: return "ok";
    case PayloadError::kTruncated: return "truncated TLV";
    case PayloadError::kDuplicateTag: return "duplicate tag";
    case PayloadError::kUnknownCritical: return "unknown critical tag";
    case PayloadError::kMissingRequired: return "missing required tag";
    case PayloadError::kBadDeviceName: return "invalid DEVICE_NAME";
    case PayloadError::kBadRole: return "invalid ROLE";
    case PayloadError::kBadFeatures: return "invalid FEATURES";
  }
  return "unknown";
}

bool is_valid_device_name(std::string_view name) noexcept {
  return !name.empty() && name.size() <= kMaxDeviceNameSize && is_valid_utf8(name);
}

namespace {

void put_tlv(std::vector<std::uint8_t>& out, Tag tag, std::span<const std::uint8_t> value) {
  out.push_back(static_cast<std::uint8_t>(tag));
  out.push_back(static_cast<std::uint8_t>(value.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(value.size() & 0xFF));
  out.insert(out.end(), value.begin(), value.end());
}

}  // namespace

PayloadError encode_payload(const HandshakePayload& payload, std::vector<std::uint8_t>& out) {
  if (!is_valid_device_name(payload.device_name)) return PayloadError::kBadDeviceName;
  if (payload.role != ConnectionRole::kPrimary && payload.role != ConnectionRole::kBulk) {
    return PayloadError::kBadRole;
  }
  const auto* name = reinterpret_cast<const std::uint8_t*>(payload.device_name.data());
  put_tlv(out, Tag::kDeviceName, std::span(name, payload.device_name.size()));
  const std::uint8_t role = static_cast<std::uint8_t>(payload.role);
  put_tlv(out, Tag::kRole, std::span(&role, 1));
  if (payload.features) {
    std::array<std::uint8_t, 4> f{};
    store_be<std::uint32_t>(f, *payload.features);
    put_tlv(out, Tag::kFeatures, f);
  }
  return PayloadError::kOk;
}

PayloadError decode_payload(std::span<const std::uint8_t> input, HandshakePayload& out) {
  ByteReader r{input};
  std::bitset<256> seen;
  HandshakePayload result;
  bool have_name = false;
  bool have_role = false;

  while (r.remaining() > 0) {
    std::uint8_t tag = 0;
    std::uint16_t len = 0;
    std::span<const std::uint8_t> value;
    if (!r.read(tag) || !r.read(len) || !r.view_bytes(len, value)) return PayloadError::kTruncated;
    if (seen.test(tag)) return PayloadError::kDuplicateTag;
    seen.set(tag);

    switch (static_cast<Tag>(tag)) {
      case Tag::kDeviceName: {
        const std::string_view name(reinterpret_cast<const char*>(value.data()), value.size());
        if (!is_valid_device_name(name)) return PayloadError::kBadDeviceName;
        result.device_name.assign(name);
        have_name = true;
        break;
      }
      case Tag::kRole:
        if (value.size() != 1 || value[0] > 1) return PayloadError::kBadRole;
        result.role = static_cast<ConnectionRole>(value[0]);
        have_role = true;
        break;
      case Tag::kFeatures:
        if (value.size() != 4) return PayloadError::kBadFeatures;
        result.features = load_be<std::uint32_t>(value.first<4>());
        break;
      default:
        if ((tag & kCriticalTagBit) != 0) return PayloadError::kUnknownCritical;
        break;  // unknown optional tag: ignored
    }
  }
  if (!have_name || !have_role) return PayloadError::kMissingRequired;
  out = std::move(result);
  return PayloadError::kOk;
}

}  // namespace twolink::handshake
