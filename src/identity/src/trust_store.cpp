#include "twolink/identity/trust_store.hpp"

#include <algorithm>
#include <array>
#include <set>

#include <sodium.h>

#include "private_file.hpp"
#include "twolink/core/byte_io.hpp"
#include "twolink/core/utf8.hpp"

namespace twolink::identity {

namespace {

constexpr std::array<std::uint8_t, 8> kMagic{'2', 'L', 'N', 'K', 'T', 'R', 'S', '1'};
constexpr std::size_t kMacSize = 32;
constexpr std::size_t kMaxRecordSize = 32 + 32 + 8 + 1 + 1 + kMaxPeerNameSize;
constexpr std::size_t kMaxFileSize = kMagic.size() + 4 + kMaxTrustedPeers * kMaxRecordSize + kMacSize;

bool valid_name(std::string_view name) noexcept {
  return !name.empty() && name.size() <= kMaxPeerNameSize && is_valid_utf8(name);
}

bool valid_record(const PeerRecord& r) noexcept {
  return valid_name(r.name) && r.trust == Trust::kVerified &&
         r.device_id == device_id_from_key(r.static_key);
}

std::array<std::uint8_t, kMacSize> mac(std::span<const std::uint8_t> data, const SecretKey& key) {
  std::array<std::uint8_t, kMacSize> out{};
  crypto_generichash(out.data(), out.size(), data.data(), data.size(), key.bytes().data(),
                     key.bytes().size());
  return out;
}

template <typename T>
void put(std::vector<std::uint8_t>& out, T value) {
  std::array<std::uint8_t, sizeof(T)> b{};
  store_be<T>(b, value);
  out.insert(out.end(), b.begin(), b.end());
}

}  // namespace

PeerRecord make_peer_record(const crypto::PublicKey& static_key, std::string name,
                            std::chrono::system_clock::time_point paired_at) {
  PeerRecord r;
  r.device_id = device_id_from_key(static_key);
  r.name = std::move(name);
  r.static_key = static_key;
  r.first_paired_at =
      std::chrono::duration_cast<std::chrono::seconds>(paired_at.time_since_epoch()).count();
  r.trust = Trust::kVerified;
  return r;
}

std::string_view to_string(TrustStoreStatus status) noexcept {
  switch (status) {
    case TrustStoreStatus::kOk: return "ok";
    case TrustStoreStatus::kCorrupt: return "corrupt or tampered";
    case TrustStoreStatus::kInsecurePermissions: return "insecure permissions";
    case TrustStoreStatus::kKeyUnavailable: return "integrity key unavailable";
    case TrustStoreStatus::kInvalidRecord: return "invalid record";
    case TrustStoreStatus::kFull: return "trust store full";
    case TrustStoreStatus::kIoError: return "I/O error";
  }
  return "unknown";
}

// --- file format ----------------------------------------------------------------

std::vector<std::uint8_t> detail::encode_trust_file(std::span<const PeerRecord> peers,
                                                    const SecretKey& mac_key) {
  std::vector<std::uint8_t> out(kMagic.begin(), kMagic.end());
  put(out, static_cast<std::uint32_t>(peers.size()));
  for (const PeerRecord& r : peers) {
    out.insert(out.end(), r.device_id.begin(), r.device_id.end());
    out.insert(out.end(), r.static_key.begin(), r.static_key.end());
    put(out, static_cast<std::uint64_t>(r.first_paired_at));
    out.push_back(static_cast<std::uint8_t>(r.trust));
    out.push_back(static_cast<std::uint8_t>(r.name.size()));
    out.insert(out.end(), r.name.begin(), r.name.end());
  }
  const auto tag = mac(out, mac_key);
  out.insert(out.end(), tag.begin(), tag.end());
  return out;
}

TrustStoreStatus detail::decode_trust_file(std::span<const std::uint8_t> file,
                                           const SecretKey& mac_key,
                                           std::vector<PeerRecord>& out) {
  if (file.size() < kMagic.size() + 4 + kMacSize || file.size() > kMaxFileSize) {
    return TrustStoreStatus::kCorrupt;
  }
  // Authenticate before parsing anything.
  const auto body = file.first(file.size() - kMacSize);
  const auto expected = mac(body, mac_key);
  if (sodium_memcmp(expected.data(), file.data() + body.size(), kMacSize) != 0) {
    return TrustStoreStatus::kCorrupt;
  }

  ByteReader r{body};
  std::array<std::uint8_t, 8> magic{};
  std::uint32_t count = 0;
  if (!r.read_bytes(magic) || magic != kMagic || !r.read(count) || count > kMaxTrustedPeers) {
    return TrustStoreStatus::kCorrupt;
  }
  std::vector<PeerRecord> peers;
  peers.reserve(count);
  std::set<DeviceId> ids;
  for (std::uint32_t i = 0; i < count; ++i) {
    PeerRecord rec;
    std::uint64_t paired_at = 0;
    std::uint8_t trust = 0;
    std::uint8_t name_len = 0;
    std::span<const std::uint8_t> name;
    if (!r.read_bytes(rec.device_id) || !r.read_bytes(rec.static_key) || !r.read(paired_at) ||
        !r.read(trust) || !r.read(name_len) || !r.view_bytes(name_len, name)) {
      return TrustStoreStatus::kCorrupt;
    }
    if (trust != static_cast<std::uint8_t>(Trust::kVerified)) return TrustStoreStatus::kCorrupt;
    rec.first_paired_at = static_cast<std::int64_t>(paired_at);
    rec.trust = Trust::kVerified;
    rec.name.assign(reinterpret_cast<const char*>(name.data()), name.size());
    // device_id is unique and derived from the key, so keys are unique too.
    if (!valid_record(rec) || !ids.insert(rec.device_id).second) {
      return TrustStoreStatus::kCorrupt;
    }
    peers.push_back(std::move(rec));
  }
  if (r.remaining() != 0) return TrustStoreStatus::kCorrupt;
  out = std::move(peers);
  return TrustStoreStatus::kOk;
}

// --- TrustStore -----------------------------------------------------------------

TrustStoreStatus TrustStore::open(Keystore& keystore, std::filesystem::path file,
                                  std::optional<TrustStore>& out) {
  std::vector<std::uint8_t> bytes;
  const detail::FileStatus fs = detail::read_private_file(file, kMaxFileSize, bytes);
  switch (fs) {
    case detail::FileStatus::kOk:
    case detail::FileStatus::kNotFound: break;
    case detail::FileStatus::kInsecure: return TrustStoreStatus::kInsecurePermissions;
    case detail::FileStatus::kTooLarge: return TrustStoreStatus::kCorrupt;
    case detail::FileStatus::kIoError: return TrustStoreStatus::kIoError;
  }
  const bool have_file = fs == detail::FileStatus::kOk;

  std::optional<SecretKey> key;
  switch (keystore.load(kTrustStoreSecretName, key)) {
    case KeystoreStatus::kOk: break;
    case KeystoreStatus::kNotFound: {
      if (have_file) return TrustStoreStatus::kKeyUnavailable;  // cannot verify it
      SecretKey fresh = SecretKey::random();
      const KeystoreStatus s = keystore.store(kTrustStoreSecretName, fresh);
      if (s == KeystoreStatus::kAlreadyExists) {  // another process won the race
        if (keystore.load(kTrustStoreSecretName, key) != KeystoreStatus::kOk) {
          return TrustStoreStatus::kKeyUnavailable;
        }
      } else if (s != KeystoreStatus::kOk) {
        return TrustStoreStatus::kKeyUnavailable;
      } else {
        key = std::move(fresh);
      }
      break;
    }
    default: return TrustStoreStatus::kKeyUnavailable;
  }

  std::vector<PeerRecord> peers;
  if (have_file) {
    if (const TrustStoreStatus s = detail::decode_trust_file(bytes, *key, peers);
        s != TrustStoreStatus::kOk) {
      return s;
    }
  }
  out.emplace(TrustStore(std::move(file), std::move(*key), std::move(peers)));
  return TrustStoreStatus::kOk;
}

const PeerRecord* TrustStore::find(const DeviceId& id) const noexcept {
  const auto it = std::find_if(peers_.begin(), peers_.end(),
                               [&](const PeerRecord& r) { return r.device_id == id; });
  return it == peers_.end() ? nullptr : &*it;
}

const PeerRecord* TrustStore::find_by_key(const crypto::PublicKey& key) const noexcept {
  const auto it = std::find_if(peers_.begin(), peers_.end(),
                               [&](const PeerRecord& r) { return r.static_key == key; });
  return it == peers_.end() ? nullptr : &*it;
}

std::vector<const PeerRecord*> TrustStore::find_by_name(std::string_view name) const {
  std::vector<const PeerRecord*> found;
  for (const PeerRecord& r : peers_) {
    if (r.name == name) found.push_back(&r);
  }
  return found;
}

TrustStoreStatus TrustStore::save(std::span<const PeerRecord> peers) const {
  const std::vector<std::uint8_t> bytes = detail::encode_trust_file(peers, mac_key_);
  switch (detail::replace_private_file(file_, bytes)) {
    case detail::FileStatus::kOk: return TrustStoreStatus::kOk;
    case detail::FileStatus::kInsecure: return TrustStoreStatus::kInsecurePermissions;
    default: return TrustStoreStatus::kIoError;
  }
}

TrustStoreStatus TrustStore::add(PeerRecord record) {
  if (!valid_record(record)) return TrustStoreStatus::kInvalidRecord;
  std::vector<PeerRecord> next = peers_;
  const auto it = std::find_if(next.begin(), next.end(), [&](const PeerRecord& r) {
    return r.device_id == record.device_id;
  });
  if (it != next.end()) {
    *it = std::move(record);
  } else {
    if (next.size() >= kMaxTrustedPeers) return TrustStoreStatus::kFull;
    next.push_back(std::move(record));
  }
  if (const TrustStoreStatus s = save(next); s != TrustStoreStatus::kOk) return s;
  peers_ = std::move(next);
  return TrustStoreStatus::kOk;
}

TrustStoreStatus TrustStore::remove(const DeviceId& id) {
  std::vector<PeerRecord> next = peers_;
  std::erase_if(next, [&](const PeerRecord& r) { return r.device_id == id; });
  if (next.size() == peers_.size()) return TrustStoreStatus::kOk;
  if (const TrustStoreStatus s = save(next); s != TrustStoreStatus::kOk) return s;
  peers_ = std::move(next);
  return TrustStoreStatus::kOk;
}

}  // namespace twolink::identity
