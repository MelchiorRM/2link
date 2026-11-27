// Fuzz target for the handshake TLV decoder (threat model H7).
//
// Invariants checked:
//  1. No crash, leak or UB (run under ASan/UBSan).
//  2. Anything accepted has a valid DEVICE_NAME and re-encodes to a list that
//     decodes to the same payload.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "twolink/handshake/payload.hpp"

namespace {

void check(bool condition) {
  if (!condition) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace twolink::handshake;
  HandshakePayload p;
  if (decode_payload(std::span(data, size), p) != PayloadError::kOk) return 0;
  check(is_valid_device_name(p.device_name));
  std::vector<std::uint8_t> encoded;
  check(encode_payload(p, encoded) == PayloadError::kOk);
  HandshakePayload back;
  check(decode_payload(encoded, back) == PayloadError::kOk && back == p);
  return 0;
}
