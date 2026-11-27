// Fuzz target for the discovery announcement decoder (threat model D3).
//
// Invariants checked:
//  1. No crash, leak or UB (run under ASan/UBSan).
//  2. Anything accepted is at most 512 bytes, has DEVICE_ID == BLAKE2b(key),
//     and re-encodes to a datagram that decodes to the same announcement.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "twolink/crypto/keys.hpp"
#include "twolink/discovery/announcement.hpp"

namespace {

void check(bool condition) {
  if (!condition) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace twolink::discovery;
  static const bool initialized = twolink::crypto::initialize();
  check(initialized);
  Announcement a;
  if (decode_announcement(std::span(data, size), a) != AnnounceError::kOk) return 0;
  check(size <= kMaxDatagramSize);
  check(a.device_id == twolink::identity::device_id_from_key(a.static_key));
  std::vector<std::uint8_t> encoded;
  check(encode_announcement(a, encoded) == AnnounceError::kOk);
  Announcement back;
  check(decode_announcement(encoded, back) == AnnounceError::kOk && back == a);
  return 0;
}
