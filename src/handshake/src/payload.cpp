#include "twolink/handshake/payload.hpp"

#include <array>
#include <utility>

#include "twolink/core/byte_io.hpp"
#include "twolink/core/tlv.hpp"
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

PayloadError encode_payload(const HandshakePayload& payload, std::vector<std::uint8_t>& out) {
  if (!is_valid_device_name(payload.device_name)) return PayloadError::kBadDeviceName;
  if (payload.role != ConnectionRole::kPrimary && payload.role != ConnectionRole::kBulk) {
    return PayloadError::kBadRole;
  }
  const auto* name = reinterpret_cast<const std::uint8_t*>(payload.device_name.data());
  append_tlv(out, static_cast<std::uint8_t>(Tag::kDeviceName),
             std::span(name, payload.device_name.size()));
  const std::uint8_t role = static_cast<std::uint8_t>(payload.role);
  append_tlv(out, static_cast<std::uint8_t>(Tag::kRole), std::span(&role, 1));
  if (payload.features) {
    std::array<std::uint8_t, 4> f{};
    store_be<std::uint32_t>(f, *payload.features);
    append_tlv(out, static_cast<std::uint8_t>(Tag::kFeatures), f);
  }
  return PayloadError::kOk;
}

PayloadError decode_payload(std::span<const std::uint8_t> input, HandshakePayload& out) {
  HandshakePayload result;
  bool have_name = false;
  bool have_role = false;
  PayloadError bad = PayloadError::kOk;  // which value was malformed

  const TlvError err = parse_tlv(input, [&](std::uint8_t tag, std::span<const std::uint8_t> value) {
    switch (static_cast<Tag>(tag)) {
      case Tag::kDeviceName: {
        const std::string_view name(reinterpret_cast<const char*>(value.data()), value.size());
        if (!is_valid_device_name(name)) {
          bad = PayloadError::kBadDeviceName;
          return TlvVisit::kBadValue;
        }
        result.device_name.assign(name);
        have_name = true;
        return TlvVisit::kAccepted;
      }
      case Tag::kRole:
        if (value.size() != 1 || value[0] > 1) {
          bad = PayloadError::kBadRole;
          return TlvVisit::kBadValue;
        }
        result.role = static_cast<ConnectionRole>(value[0]);
        have_role = true;
        return TlvVisit::kAccepted;
      case Tag::kFeatures:
        if (value.size() != 4) {
          bad = PayloadError::kBadFeatures;
          return TlvVisit::kBadValue;
        }
        result.features = load_be<std::uint32_t>(value.first<4>());
        return TlvVisit::kAccepted;
    }
    return TlvVisit::kUnknown;
  });

  switch (err) {
    case TlvError::kOk: break;
    case TlvError::kTruncated: return PayloadError::kTruncated;
    case TlvError::kDuplicateTag: return PayloadError::kDuplicateTag;
    case TlvError::kUnknownCritical: return PayloadError::kUnknownCritical;
    case TlvError::kBadValue: return bad;
  }
  if (!have_name || !have_role) return PayloadError::kMissingRequired;
  out = std::move(result);
  return PayloadError::kOk;
}

}  // namespace twolink::handshake
