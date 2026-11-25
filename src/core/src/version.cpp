#include "twolink/core/version.hpp"

namespace twolink {

std::string_view library_version() noexcept { return TWOLINK_VERSION_STRING; }

}  // namespace twolink
