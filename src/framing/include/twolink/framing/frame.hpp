#pragma once

#include <cstddef>
#include <cstdint>

namespace twolink::framing {

// Strict upper bound on a single frame (header + ciphertext + tag).
// Final value is fixed by protocol spec v0.1.
inline constexpr std::size_t kMaxFrameSize = 1u << 20;  // 1 MiB

// Placeholder: frame header layout, encoder and incremental parser are
// Phase 0 deliverables (see task.md).
std::size_t max_frame_size() noexcept;

}  // namespace twolink::framing
