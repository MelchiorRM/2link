#pragma once

// Private per-user files (threat model L1, L2), shared by the keystore and the
// trust store.
//
// POSIX: files are 0600 inside a 0700 directory owned by the user. Reading
// refuses symlinks, non-regular files, files owned by someone else and files
// group or others can access. Writing refuses a directory others can write to.
// Windows: files live under %LOCALAPPDATA%, which only the user can access;
// reading refuses anything that is not a regular file.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace twolink::identity::detail {

enum class FileStatus : std::uint8_t { kOk, kNotFound, kInsecure, kTooLarge, kIoError };

// POSIX: creates dir (0700) if needed and checks that it is a directory owned
// by the user that nobody else can write to. Windows: creates it.
[[nodiscard]] FileStatus ensure_private_dir(const std::filesystem::path& dir);

// Reads a whole private file of at most max_size bytes.
[[nodiscard]] FileStatus read_private_file(const std::filesystem::path& path, std::size_t max_size,
                                           std::vector<std::uint8_t>& out);

// Writes data to path, replacing any existing file atomically: a crash leaves
// either the old or the new content, never a mix.
[[nodiscard]] FileStatus replace_private_file(const std::filesystem::path& path,
                                              std::span<const std::uint8_t> data);

// 16 hex characters from the CSPRNG, for temporary file names.
[[nodiscard]] std::string random_suffix();

}  // namespace twolink::identity::detail
