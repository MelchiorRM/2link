#pragma once

#include <cstdint>
#include <string_view>

namespace twolink {

// Wire protocol version carried in every frame header (spec v0.1).
inline constexpr std::uint8_t kProtocolVersion = 1;

std::string_view library_version() noexcept;

}  // namespace twolink
