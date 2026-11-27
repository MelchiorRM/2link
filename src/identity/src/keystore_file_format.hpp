#pragma once

// On-disk format of a FileKeystore secret on POSIX (72 bytes):
//   magic "2LNKSEC1" (8) | secret (32) | BLAKE2b-256(magic || secret) (32)
// The checksum detects damage; confidentiality comes from file permissions.
// On Windows the file is: magic "2LNKDPA1" (8) | DPAPI blob.

#include <array>
#include <cstddef>
#include <cstdint>

namespace twolink::identity::detail {

inline constexpr std::array<std::uint8_t, 8> kPosixMagic{'2', 'L', 'N', 'K', 'S', 'E', 'C', '1'};
inline constexpr std::array<std::uint8_t, 8> kDpapiMagic{'2', 'L', 'N', 'K', 'D', 'P', 'A', '1'};
inline constexpr std::size_t kChecksumSize = 32;
inline constexpr std::size_t kPosixFileSize = 8 + 32 + kChecksumSize;
inline constexpr std::size_t kMaxDpapiFileSize = 4096;

}  // namespace twolink::identity::detail
