// FileKeystore on Windows: secrets encrypted with DPAPI for the current user
// (threat model L1).

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// windows.h first.
#include <dpapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <sodium.h>

#include "keystore_file_format.hpp"
#include "private_file.hpp"
#include "twolink/identity/keystore.hpp"

namespace twolink::identity {

namespace {

using detail::kDpapiMagic;
using detail::kMaxDpapiFileSize;

// Frees a DPAPI output blob (after wiping it) on scope exit.
struct BlobGuard {
  DATA_BLOB blob{0, nullptr};
  BlobGuard() = default;
  BlobGuard(const BlobGuard&) = delete;
  BlobGuard& operator=(const BlobGuard&) = delete;
  ~BlobGuard() {
    if (blob.pbData != nullptr) {
      SecureZeroMemory(blob.pbData, blob.cbData);
      LocalFree(blob.pbData);
    }
  }
};

}  // namespace

KeystoreStatus FileKeystore::load(std::string_view name, std::optional<SecretKey>& out) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  const std::filesystem::path path = path_for(name);

  std::error_code ec;
  const auto status = std::filesystem::symlink_status(path, ec);
  if (ec || status.type() == std::filesystem::file_type::not_found) {
    return ec && ec != std::errc::no_such_file_or_directory ? KeystoreStatus::kIoError
                                                             : KeystoreStatus::kNotFound;
  }
  if (status.type() != std::filesystem::file_type::regular) {
    return KeystoreStatus::kInsecurePermissions;
  }
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return KeystoreStatus::kIoError;
  if (size <= kDpapiMagic.size() || size > kMaxDpapiFileSize) return KeystoreStatus::kCorrupt;

  std::ifstream in(path, std::ios::binary);
  if (!in) return KeystoreStatus::kIoError;
  std::vector<std::uint8_t> file(static_cast<std::size_t>(size));
  if (!in.read(reinterpret_cast<char*>(file.data()), static_cast<std::streamsize>(file.size()))) {
    return KeystoreStatus::kIoError;
  }
  if (!std::equal(kDpapiMagic.begin(), kDpapiMagic.end(), file.begin())) {
    return KeystoreStatus::kCorrupt;
  }

  DATA_BLOB encrypted{static_cast<DWORD>(file.size() - kDpapiMagic.size()),
                      file.data() + kDpapiMagic.size()};
  BlobGuard plain;
  if (!CryptUnprotectData(&encrypted, nullptr, nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &plain.blob)) {
    return KeystoreStatus::kCorrupt;  // tampered, or another user's / machine's blob
  }
  if (plain.blob.cbData != kSecretSize) return KeystoreStatus::kCorrupt;
  out = SecretKey::from_bytes(std::span<const std::uint8_t, kSecretSize>(plain.blob.pbData, kSecretSize));
  return KeystoreStatus::kOk;
}

KeystoreStatus FileKeystore::store(std::string_view name, const SecretKey& secret) {
  if (!is_valid_secret_name(name)) return KeystoreStatus::kInvalidName;
  std::error_code ec;
  std::filesystem::create_directories(dir_, ec);
  if (ec) return KeystoreStatus::kIoError;

  const std::filesystem::path path = path_for(name);
  if (std::filesystem::exists(std::filesystem::symlink_status(path, ec))) {
    return KeystoreStatus::kAlreadyExists;
  }

  // DPAPI only reads the input; the cast drops const for its C signature.
  DATA_BLOB plain{static_cast<DWORD>(kSecretSize), const_cast<BYTE*>(secret.bytes().data())};
  BlobGuard encrypted;
  if (!CryptProtectData(&plain, L"2link secret", nullptr, nullptr, nullptr,
                        CRYPTPROTECT_UI_FORBIDDEN, &encrypted.blob)) {
    return KeystoreStatus::kIoError;
  }

  // Write a temporary file, then move it into place without replacing: a
  // concurrent store cannot be overwritten.
  const std::filesystem::path tmp = dir_ / ("." + std::string(name) + ".tmp-" + detail::random_suffix());
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(kDpapiMagic.data()),
            static_cast<std::streamsize>(kDpapiMagic.size()));
    f.write(reinterpret_cast<const char*>(encrypted.blob.pbData),
            static_cast<std::streamsize>(encrypted.blob.cbData));
    f.flush();
    if (!f) {
      f.close();
      std::filesystem::remove(tmp, ec);
      return KeystoreStatus::kIoError;
    }
  }
  if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH)) {
    const DWORD err = GetLastError();
    std::filesystem::remove(tmp, ec);
    return err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS ? KeystoreStatus::kAlreadyExists
                                                                     : KeystoreStatus::kIoError;
  }
  return KeystoreStatus::kOk;
}

}  // namespace twolink::identity
