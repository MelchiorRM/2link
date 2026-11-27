// FileKeystore on Linux/POSIX: owner-only files (threat model L1).

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>

#include <sodium.h>

#include "keystore_file_format.hpp"
#include "private_file.hpp"
#include "twolink/identity/keystore.hpp"

namespace twolink::identity {

namespace {

using detail::kChecksumSize;
using detail::kPosixFileSize;
using detail::kPosixMagic;

using FileBytes = std::array<std::uint8_t, kPosixFileSize>;

// Closes a file descriptor on scope exit.
class Fd {
 public:
  explicit Fd(int fd) noexcept : fd_(fd) {}
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  ~Fd() {
    if (fd_ >= 0) ::close(fd_);
  }
  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool ok() const noexcept { return fd_ >= 0; }
  [[nodiscard]] bool close() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return ::close(fd) == 0;
  }

 private:
  int fd_;
};

// Wipes a buffer on scope exit.
struct Wipe {
  std::span<std::uint8_t> bytes;
  ~Wipe() { sodium_memzero(bytes.data(), bytes.size()); }
};

void checksum(std::span<const std::uint8_t> data, std::span<std::uint8_t, kChecksumSize> out) {
  crypto_generichash(out.data(), out.size(), data.data(), data.size(), nullptr, 0);
}

bool write_all(int fd, std::span<const std::uint8_t> data) {
  while (!data.empty()) {
    const ssize_t n = ::write(fd, data.data(), data.size());
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return true;
}

bool read_all(int fd, std::span<std::uint8_t> data) {
  while (!data.empty()) {
    const ssize_t n = ::read(fd, data.data(), data.size());
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;  // file shorter than expected
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return true;
}

// Group or others have any access.
bool too_open(mode_t mode) { return (mode & (S_IRWXG | S_IRWXO)) != 0; }

KeystoreStatus ensure_dir(const std::filesystem::path& dir) {
  switch (detail::ensure_private_dir(dir)) {
    case detail::FileStatus::kOk: return KeystoreStatus::kOk;
    case detail::FileStatus::kInsecure: return KeystoreStatus::kInsecurePermissions;
    default: return KeystoreStatus::kIoError;
  }
}

void fsync_dir(const std::filesystem::path& dir) {
  const Fd fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (fd.ok()) static_cast<void>(::fsync(fd.get()));  // best effort
}

}  // namespace

KeystoreStatus FileKeystore::load(std::string_view name, std::optional<SecretKey>& out) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  const std::filesystem::path path = path_for(name);

  Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  if (!fd.ok()) {
    if (errno == ENOENT) return KeystoreStatus::kNotFound;
    if (errno == ELOOP) return KeystoreStatus::kInsecurePermissions;  // symlink
    return KeystoreStatus::kIoError;
  }
  struct stat st {};
  if (::fstat(fd.get(), &st) != 0) return KeystoreStatus::kIoError;
  if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || too_open(st.st_mode)) {
    return KeystoreStatus::kInsecurePermissions;
  }
  if (st.st_size != static_cast<off_t>(kPosixFileSize)) return KeystoreStatus::kCorrupt;

  FileBytes file{};
  const Wipe wipe_file{file};
  if (!read_all(fd.get(), file)) return KeystoreStatus::kIoError;

  std::array<std::uint8_t, kChecksumSize> expected{};
  checksum(std::span(file).first(8 + kSecretSize), expected);
  const bool magic_ok = std::equal(kPosixMagic.begin(), kPosixMagic.end(), file.begin());
  const bool sum_ok =
      sodium_memcmp(expected.data(), file.data() + 8 + kSecretSize, kChecksumSize) == 0;
  if (!magic_ok || !sum_ok) return KeystoreStatus::kCorrupt;

  out = SecretKey::from_bytes(std::span(file).subspan<8, kSecretSize>());
  return KeystoreStatus::kOk;
}

KeystoreStatus FileKeystore::store(std::string_view name, const SecretKey& secret) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  if (const KeystoreStatus s = ensure_dir(dir_); s != KeystoreStatus::kOk) return s;

  const std::filesystem::path path = path_for(name);
  struct stat st {};
  if (::lstat(path.c_str(), &st) == 0) return KeystoreStatus::kAlreadyExists;

  FileBytes file{};
  const Wipe wipe_file{file};
  std::copy(kPosixMagic.begin(), kPosixMagic.end(), file.begin());
  std::copy(secret.bytes().begin(), secret.bytes().end(), file.begin() + 8);
  checksum(std::span(file).first(8 + kSecretSize),
           std::span(file).subspan<8 + kSecretSize, kChecksumSize>());

  // Write a private temporary file, then link it into place: link() never
  // replaces an existing file, so a concurrent store cannot be overwritten.
  const std::filesystem::path tmp = dir_ / ("." + std::string(name) + ".tmp-" + detail::random_suffix());
  Fd fd(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (!fd.ok()) return KeystoreStatus::kIoError;
  const bool written = write_all(fd.get(), file) && ::fsync(fd.get()) == 0;
  const bool closed = fd.close();
  if (!written || !closed) {
    ::unlink(tmp.c_str());
    return KeystoreStatus::kIoError;
  }
  const int link_result = ::link(tmp.c_str(), path.c_str());
  const int link_errno = errno;
  ::unlink(tmp.c_str());
  if (link_result != 0) {
    return link_errno == EEXIST ? KeystoreStatus::kAlreadyExists : KeystoreStatus::kIoError;
  }
  fsync_dir(dir_);
  return KeystoreStatus::kOk;
}

}  // namespace twolink::identity
