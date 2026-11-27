#pragma once

// Trust store: the peers this device has paired with, spec v0.1.3 §4.7
// (threat model L2, H4, H5).
//
// Each record pins a peer's static key. The file is owner-only (like the
// keystore) and authenticated with a MAC whose key is the keystore secret
// "trust-store", so an edited file (for example, an attacker key added to it)
// is refused rather than trusted.
//
// File format (big-endian):
//   magic "2LNKTRS1" (8) | count: u32
//   count x { device_id (32) | static_key (32) | first_paired_at: u64 (Unix
//             seconds, UTC, two's complement) | trust: u8 | name_len: u8 | name }
//   mac: BLAKE2b-256 keyed with the trust-store secret, over everything before it
//
// The MAC is checked before anything is parsed. Parsing is then strict:
// device_id must match the key, no duplicates, valid names, nothing trailing.
//
// Every change is written to disk before it takes effect in memory, so a
// failed save never leaves the two out of step.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "twolink/crypto/keys.hpp"
#include "twolink/identity/device_id.hpp"
#include "twolink/identity/keystore.hpp"

namespace twolink::identity {

inline constexpr std::string_view kTrustStoreSecretName = "trust-store";
inline constexpr std::size_t kMaxTrustedPeers = 1024;
inline constexpr std::size_t kMaxPeerNameSize = 64;

enum class Trust : std::uint8_t { kVerified = 1 };

struct PeerRecord {
  DeviceId device_id{};
  std::string name;  // from DEVICE_NAME, UTF-8, 1..64 bytes
  crypto::PublicKey static_key{};
  std::int64_t first_paired_at = 0;  // Unix seconds, UTC
  Trust trust = Trust::kVerified;

  friend bool operator==(const PeerRecord&, const PeerRecord&) = default;
};

// A verified record for a peer just paired with. device_id is derived from the
// key, never taken from anywhere else (§4.1).
[[nodiscard]] PeerRecord make_peer_record(const crypto::PublicKey& static_key, std::string name,
                                          std::chrono::system_clock::time_point paired_at);

enum class TrustStoreStatus : std::uint8_t {
  kOk,
  kCorrupt,              // MAC mismatch, bad format, or invalid record
  kInsecurePermissions,  // file or directory accessible to others (POSIX)
  kKeyUnavailable,       // the trust-store secret is missing or unreadable
  kInvalidRecord,        // add(): bad name, device_id not matching the key
  kFull,                 // add(): kMaxTrustedPeers reached
  kIoError,
};

[[nodiscard]] std::string_view to_string(TrustStoreStatus status) noexcept;

namespace detail {
// Exposed for tests: the file encoding and its strict decoder.
[[nodiscard]] std::vector<std::uint8_t> encode_trust_file(std::span<const PeerRecord> peers,
                                                          const SecretKey& mac_key);
[[nodiscard]] TrustStoreStatus decode_trust_file(std::span<const std::uint8_t> file,
                                                 const SecretKey& mac_key,
                                                 std::vector<PeerRecord>& out);
}  // namespace detail

class TrustStore {
 public:
  // Opens (or starts) the trust store at `file`, with its MAC key from the
  // keystore:
  //   - key and file present: the file must verify, or kCorrupt;
  //   - no file: an empty store (the file is written on the first change);
  //   - no key and no file: a new key is generated and stored;
  //   - no key but a file: kKeyUnavailable (it cannot be verified).
  [[nodiscard]] static TrustStoreStatus open(Keystore& keystore, std::filesystem::path file,
                                             std::optional<TrustStore>& out);

  TrustStore(TrustStore&&) noexcept = default;
  TrustStore& operator=(TrustStore&&) noexcept = default;
  ~TrustStore() = default;

  [[nodiscard]] const std::vector<PeerRecord>& peers() const noexcept { return peers_; }
  [[nodiscard]] const PeerRecord* find(const DeviceId& id) const noexcept;
  // IK responder lookup (§4.8).
  [[nodiscard]] const PeerRecord* find_by_key(const crypto::PublicKey& key) const noexcept;
  // Records with this name: a new device announcing a trusted peer's name may
  // be an identity change (§4.8, IDENTITY_CHANGED).
  [[nodiscard]] std::vector<const PeerRecord*> find_by_name(std::string_view name) const;

  // Adds a record, or replaces the one with the same device_id; saved first.
  [[nodiscard]] TrustStoreStatus add(PeerRecord record);
  // Removes a record (for example the old key after an explicit re-pair).
  // kOk also when no such record exists.
  [[nodiscard]] TrustStoreStatus remove(const DeviceId& id);

  [[nodiscard]] const std::filesystem::path& file() const noexcept { return file_; }

 private:
  TrustStore(std::filesystem::path file, SecretKey mac_key, std::vector<PeerRecord> peers) noexcept
      : file_(std::move(file)), mac_key_(std::move(mac_key)), peers_(std::move(peers)) {}

  [[nodiscard]] TrustStoreStatus save(std::span<const PeerRecord> peers) const;

  std::filesystem::path file_;
  SecretKey mac_key_;
  std::vector<PeerRecord> peers_;
};

}  // namespace twolink::identity
