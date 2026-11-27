#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <system_error>

#include "private_file.hpp"

namespace twolink::identity::detail {

namespace {

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
    if (n == 0) return false;
    data = data.subspan(static_cast<std::size_t>(n));
  }
  return true;
}

}  // namespace

FileStatus ensure_private_dir(const std::filesystem::path& dir) {
  std::error_code ec;
  if (dir.has_parent_path()) std::filesystem::create_directories(dir.parent_path(), ec);
  if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return FileStatus::kIoError;
  struct stat st {};
  if (::lstat(dir.c_str(), &st) != 0) return FileStatus::kIoError;
  if (!S_ISDIR(st.st_mode) || st.st_uid != ::geteuid()) return FileStatus::kInsecure;
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) return FileStatus::kInsecure;
  return FileStatus::kOk;
}

FileStatus read_private_file(const std::filesystem::path& path, std::size_t max_size,
                             std::vector<std::uint8_t>& out) {
  Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  if (!fd.ok()) {
    if (errno == ENOENT) return FileStatus::kNotFound;
    if (errno == ELOOP) return FileStatus::kInsecure;  // symlink
    return FileStatus::kIoError;
  }
  struct stat st {};
  if (::fstat(fd.get(), &st) != 0) return FileStatus::kIoError;
  if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() ||
      (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return FileStatus::kInsecure;
  }
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > max_size) {
    return FileStatus::kTooLarge;
  }
  std::vector<std::uint8_t> data(static_cast<std::size_t>(st.st_size));
  if (!read_all(fd.get(), data)) return FileStatus::kIoError;
  out = std::move(data);
  return FileStatus::kOk;
}

FileStatus replace_private_file(const std::filesystem::path& path,
                                std::span<const std::uint8_t> data) {
  const std::filesystem::path dir = path.parent_path();
  if (const FileStatus s = ensure_private_dir(dir); s != FileStatus::kOk) return s;

  const std::filesystem::path tmp =
      dir / ("." + path.filename().string() + ".tmp-" + random_suffix());
  Fd fd(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (!fd.ok()) return FileStatus::kIoError;
  const bool written = write_all(fd.get(), data) && ::fsync(fd.get()) == 0;
  const bool closed = fd.close();
  if (!written || !closed || ::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return FileStatus::kIoError;
  }
  const Fd dfd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (dfd.ok()) static_cast<void>(::fsync(dfd.get()));  // best effort
  return FileStatus::kOk;
}

}  // namespace twolink::identity::detail
