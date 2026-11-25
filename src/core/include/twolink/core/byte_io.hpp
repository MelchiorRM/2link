#pragma once

// Big-endian (network order) integer encoding with bounds checking.
// Spec v0.1 §1: all multi-byte integers on the wire are unsigned big-endian.

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace twolink {

// Fixed-size store/load: the span extent guarantees the size at compile time.
template <std::unsigned_integral T>
constexpr void store_be(std::span<std::uint8_t, sizeof(T)> out, T value) noexcept {
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    out[sizeof(T) - 1 - i] = static_cast<std::uint8_t>(value & 0xFFu);
    if constexpr (sizeof(T) > 1) value = static_cast<T>(value >> 8);
  }
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr T load_be(std::span<const std::uint8_t, sizeof(T)> in) noexcept {
  T value = 0;
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    value = static_cast<T>((value << 8) | in[i]);
  }
  return value;
}

// Sequential reader over untrusted input. A failed read consumes nothing.
class ByteReader {
 public:
  explicit constexpr ByteReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

  template <std::unsigned_integral T>
  [[nodiscard]] constexpr bool read(T& out) noexcept {
    if (remaining() < sizeof(T)) return false;
    out = load_be<T>(data_.subspan(pos_).template first<sizeof(T)>());
    pos_ += sizeof(T);
    return true;
  }

  // Copies exactly out.size() bytes.
  [[nodiscard]] constexpr bool read_bytes(std::span<std::uint8_t> out) noexcept {
    if (remaining() < out.size()) return false;
    std::copy_n(data_.data() + pos_, out.size(), out.data());
    pos_ += out.size();
    return true;
  }

  // Returns a view of the next n bytes without copying.
  [[nodiscard]] constexpr bool view_bytes(std::size_t n,
                                          std::span<const std::uint8_t>& out) noexcept {
    if (remaining() < n) return false;
    out = data_.subspan(pos_, n);
    pos_ += n;
    return true;
  }

  [[nodiscard]] constexpr std::size_t remaining() const noexcept { return data_.size() - pos_; }
  [[nodiscard]] constexpr std::size_t position() const noexcept { return pos_; }

 private:
  std::span<const std::uint8_t> data_;
  std::size_t pos_ = 0;
};

// Sequential writer into a caller-owned buffer. A failed write writes nothing.
class ByteWriter {
 public:
  explicit constexpr ByteWriter(std::span<std::uint8_t> buffer) noexcept : buf_(buffer) {}

  template <std::unsigned_integral T>
  [[nodiscard]] constexpr bool write(T value) noexcept {
    if (remaining() < sizeof(T)) return false;
    store_be<T>(buf_.subspan(pos_).template first<sizeof(T)>(), value);
    pos_ += sizeof(T);
    return true;
  }

  [[nodiscard]] constexpr bool write_bytes(std::span<const std::uint8_t> data) noexcept {
    if (remaining() < data.size()) return false;
    std::copy_n(data.data(), data.size(), buf_.data() + pos_);
    pos_ += data.size();
    return true;
  }

  [[nodiscard]] constexpr std::size_t remaining() const noexcept { return buf_.size() - pos_; }
  [[nodiscard]] constexpr std::size_t position() const noexcept { return pos_; }

 private:
  std::span<std::uint8_t> buf_;
  std::size_t pos_ = 0;
};

}  // namespace twolink
