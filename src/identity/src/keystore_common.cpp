// Keystore parts shared by every platform.

#include <algorithm>
#include <array>
#include <cstdlib>

#include <sodium.h>

#include "private_file.hpp"
#include "twolink/identity/keystore.hpp"

namespace twolink::identity {

// --- SecretKey -------------------------------------------------------------------

SecretKey SecretKey::from_bytes(std::span<const std::uint8_t, kSecretSize> bytes) noexcept {
  SecretKey key;
  std::copy(bytes.begin(), bytes.end(), key.bytes_.begin());
  return key;
}

SecretKey SecretKey::random() noexcept {
  SecretKey key;
  randombytes_buf(key.bytes_.data(), key.bytes_.size());
  return key;
}

SecretKey::SecretKey(SecretKey&& other) noexcept : bytes_(other.bytes_) {
  sodium_memzero(other.bytes_.data(), other.bytes_.size());
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept {
  if (this != &other) {
    bytes_ = other.bytes_;
    sodium_memzero(other.bytes_.data(), other.bytes_.size());
  }
  return *this;
}

SecretKey::~SecretKey() { sodium_memzero(bytes_.data(), bytes_.size()); }

// --- names and status ------------------------------------------------------------

std::string_view to_string(KeystoreStatus status) noexcept {
  switch (status) {
    case KeystoreStatus::kOk: return "ok";
    case KeystoreStatus::kNotFound: return "not found";
    case KeystoreStatus::kAlreadyExists: return "already exists";
    case KeystoreStatus::kCorrupt: return "corrupt";
    case KeystoreStatus::kInsecurePermissions: return "insecure permissions";
    case KeystoreStatus::kInvalidName: return "invalid name";
    case KeystoreStatus::kIoError: return "I/O error";
  }
  return "unknown";
}

std::string detail::random_suffix() {
  std::array<std::uint8_t, 8> r{};
  randombytes_buf(r.data(), r.size());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string s;
  for (const std::uint8_t b : r) {
    s += kHex[b >> 4];
    s += kHex[b & 0x0F];
  }
  return s;
}

bool is_valid_secret_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 32) return false;
  return std::all_of(name.begin(), name.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
  });
}

// --- MemoryKeystore --------------------------------------------------------------

KeystoreStatus MemoryKeystore::load(std::string_view name, std::optional<SecretKey>& out) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  const auto it = secrets_.find(name);
  if (it == secrets_.end()) return KeystoreStatus::kNotFound;
  out = SecretKey::from_bytes(it->second.bytes());
  return KeystoreStatus::kOk;
}

KeystoreStatus MemoryKeystore::store(std::string_view name, const SecretKey& secret) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  if (secrets_.find(name) != secrets_.end()) return KeystoreStatus::kAlreadyExists;
  secrets_.emplace(std::string(name), SecretKey::from_bytes(secret.bytes()));
  return KeystoreStatus::kOk;
}

// --- FileKeystore: platform-neutral parts -----------------------------------------

std::filesystem::path FileKeystore::path_for(std::string_view name) const {
  return dir_ / (std::string(name) + ".key");
}

namespace {

std::optional<std::string> env(const char* name) {
#ifdef _WIN32
  char* value = nullptr;
  std::size_t len = 0;
  if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) return std::nullopt;
  std::string out(value);
  std::free(value);
#else
  const char* value = std::getenv(name);  // NOLINT(concurrency-mt-unsafe): read at startup
  if (value == nullptr) return std::nullopt;
  std::string out(value);
#endif
  if (out.empty()) return std::nullopt;
  return out;
}

}  // namespace

std::optional<std::filesystem::path> default_data_dir() {
#ifdef _WIN32
  if (auto local = env("LOCALAPPDATA")) return std::filesystem::path(*local) / "2link";
  return std::nullopt;
#else
  if (auto xdg = env("XDG_DATA_HOME")) {
    const std::filesystem::path p(*xdg);
    if (p.is_absolute()) return p / "2link";  // XDG: relative values are ignored
  }
  if (auto home = env("HOME")) return std::filesystem::path(*home) / ".local" / "share" / "2link";
  return std::nullopt;
#endif
}

}  // namespace twolink::identity
