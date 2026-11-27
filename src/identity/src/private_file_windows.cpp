#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <fstream>
#include <system_error>

#include "private_file.hpp"

namespace twolink::identity::detail {

FileStatus ensure_private_dir(const std::filesystem::path& dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) return FileStatus::kIoError;
  return std::filesystem::is_directory(std::filesystem::symlink_status(dir, ec))
             ? FileStatus::kOk
             : FileStatus::kInsecure;
}

FileStatus read_private_file(const std::filesystem::path& path, std::size_t max_size,
                             std::vector<std::uint8_t>& out) {
  std::error_code ec;
  const auto status = std::filesystem::symlink_status(path, ec);
  if (ec || status.type() == std::filesystem::file_type::not_found) {
    return ec && ec != std::errc::no_such_file_or_directory ? FileStatus::kIoError
                                                             : FileStatus::kNotFound;
  }
  if (status.type() != std::filesystem::file_type::regular) return FileStatus::kInsecure;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return FileStatus::kIoError;
  if (size > max_size) return FileStatus::kTooLarge;

  std::ifstream in(path, std::ios::binary);
  if (!in) return FileStatus::kIoError;
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  if (!in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
    return FileStatus::kIoError;
  }
  out = std::move(data);
  return FileStatus::kOk;
}

FileStatus replace_private_file(const std::filesystem::path& path,
                                std::span<const std::uint8_t> data) {
  const std::filesystem::path dir = path.parent_path();
  if (const FileStatus s = ensure_private_dir(dir); s != FileStatus::kOk) return s;
  const std::filesystem::path tmp =
      dir / ("." + path.filename().string() + ".tmp-" + random_suffix());
  std::error_code ec;
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    f.flush();
    if (!f) {
      f.close();
      std::filesystem::remove(tmp, ec);
      return FileStatus::kIoError;
    }
  }
  if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::filesystem::remove(tmp, ec);
    return FileStatus::kIoError;
  }
  return FileStatus::kOk;
}

}  // namespace twolink::identity::detail
