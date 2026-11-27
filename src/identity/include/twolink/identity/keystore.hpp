#pragma once

// Local storage for 32-byte secrets: the device's static private key
// ("identity") and, later, the trust-store integrity key (threat model L1, L2).
//
// Backends:
//   MemoryKeystore - tests only.
//   FileKeystore   - one file per secret in a per-user directory.
//     Linux/POSIX: the secret is stored in a file readable only by its owner
//       (0600, in a 0700 directory), like ~/.ssh keys. Loading refuses files
//       that are not regular files, not owned by the user, or readable by group
//       or others. A Secret Service (libsecret) backend may follow.
//     Windows: the secret is encrypted with DPAPI for the current user.
//
// Secrets are never overwritten: storing a name that exists fails, because
// replacing the identity key would silently change the device's identity.

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace twolink::identity {

inline constexpr std::size_t kSecretSize = 32;

// A 32-byte secret. Move-only; wiped on destruction and when moved from.
class SecretKey {
 public:
  [[nodiscard]] static SecretKey from_bytes(std::span<const std::uint8_t, kSecretSize> bytes) noexcept;
  [[nodiscard]] static SecretKey random() noexcept;  // requires crypto::initialize()

  SecretKey(const SecretKey&) = delete;
  SecretKey& operator=(const SecretKey&) = delete;
  SecretKey(SecretKey&& other) noexcept;
  SecretKey& operator=(SecretKey&& other) noexcept;
  ~SecretKey();

  [[nodiscard]] std::span<const std::uint8_t, kSecretSize> bytes() const noexcept { return bytes_; }

 private:
  SecretKey() = default;
  std::array<std::uint8_t, kSecretSize> bytes_{};
};

enum class KeystoreStatus : std::uint8_t {
  kOk,
  kNotFound,             // no secret with this name
  kAlreadyExists,        // store() refuses to overwrite
  kCorrupt,              // wrong size, bad magic or checksum, or decryption failed
  kInsecurePermissions,  // file or directory accessible to other users (POSIX)
  kInvalidName,          // name is not 1..32 of [a-z0-9-]
  kIoError,
};

[[nodiscard]] std::string_view to_string(KeystoreStatus status) noexcept;

// Names are 1..32 characters of [a-z0-9-], so they are safe as file names.
[[nodiscard]] bool is_valid_secret_name(std::string_view name) noexcept;

class Keystore {
 public:
  virtual ~Keystore() = default;
  [[nodiscard]] virtual KeystoreStatus load(std::string_view name, std::optional<SecretKey>& out) = 0;
  [[nodiscard]] virtual KeystoreStatus store(std::string_view name, const SecretKey& secret) = 0;
};

class MemoryKeystore final : public Keystore {
 public:
  [[nodiscard]] KeystoreStatus load(std::string_view name, std::optional<SecretKey>& out) override;
  [[nodiscard]] KeystoreStatus store(std::string_view name, const SecretKey& secret) override;

 private:
  std::map<std::string, SecretKey, std::less<>> secrets_;
};

class FileKeystore final : public Keystore {
 public:
  // dir is created on the first store() (POSIX: mode 0700).
  explicit FileKeystore(std::filesystem::path dir) : dir_(std::move(dir)) {}

  [[nodiscard]] KeystoreStatus load(std::string_view name, std::optional<SecretKey>& out) override;
  [[nodiscard]] KeystoreStatus store(std::string_view name, const SecretKey& secret) override;

  [[nodiscard]] std::filesystem::path path_for(std::string_view name) const;

 private:
  std::filesystem::path dir_;
};

// Per-user data directory for 2link:
//   Linux: $XDG_DATA_HOME/2link, else $HOME/.local/share/2link
//   Windows: %LOCALAPPDATA%\2link
// nullopt if the environment gives no usable location.
[[nodiscard]] std::optional<std::filesystem::path> default_data_dir();

}  // namespace twolink::identity
