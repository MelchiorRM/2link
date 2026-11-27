#pragma once

// Discovery announcements, spec v0.1.3 §8.1 (threat model D2, D3).
//
//   magic "2LNK" | version: u8 = 1 | type: u8 = 0x01 (ANNOUNCE) | TLV list
//
// Announcements are plaintext and unauthenticated: they help find devices and
// never establish trust.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "twolink/crypto/keys.hpp"
#include "twolink/identity/device_id.hpp"

namespace twolink::discovery {

// §9.
inline constexpr std::uint16_t kDiscoveryPort = 47820;
inline constexpr std::size_t kMaxDatagramSize = 512;
inline constexpr std::uint8_t kAnnounceVersion = 1;
inline constexpr std::uint8_t kAnnounceType = 0x01;

enum class AnnounceTag : std::uint8_t {
  kDeviceName = 0x01,
  kDeviceId = 0x10,
  kStaticPublicKey = 0x11,
  kTcpPort = 0x12,
};

struct Announcement {
  std::string device_name;  // UTF-8, 1..64 bytes
  identity::DeviceId device_id{};
  crypto::PublicKey static_key{};
  std::uint16_t tcp_port = 0;

  friend bool operator==(const Announcement&, const Announcement&) = default;
};

// The announcement for this device: device_id derived from the key.
[[nodiscard]] Announcement make_announcement(std::string device_name,
                                             const crypto::PublicKey& static_key,
                                             std::uint16_t tcp_port);

enum class AnnounceError : std::uint8_t {
  kOk,
  kTooLarge,     // over kMaxDatagramSize
  kBadHeader,    // magic, version or type
  kBadTlv,       // truncated, duplicate tag, unknown critical tag, malformed value
  kMissing,      // a required tag is absent
  kIdMismatch,   // DEVICE_ID != BLAKE2b-256(STATIC_PUBLIC_KEY)
};

[[nodiscard]] std::string_view to_string(AnnounceError error) noexcept;

// Fails (output untouched) on an invalid field.
[[nodiscard]] AnnounceError encode_announcement(const Announcement& a,
                                                std::vector<std::uint8_t>& out);

// Every rule of §8.1; out is only written on success.
[[nodiscard]] AnnounceError decode_announcement(std::span<const std::uint8_t> datagram,
                                                Announcement& out);

}  // namespace twolink::discovery
