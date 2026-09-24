// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/result.hpp"

namespace trxreg {

/// A 32-byte SHA-256 digest, used as the stable identity of canonical content.
struct Digest {
  std::array<std::uint8_t, 32> bytes{};

  [[nodiscard]] static Digest zero() noexcept { return Digest{}; }
  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] static Result<Digest> from_hex(std::string_view text);

  friend bool operator==(const Digest& lhs, const Digest& rhs) noexcept = default;
  friend auto operator<=>(const Digest& lhs, const Digest& rhs) noexcept = default;
};

/// Streaming SHA-256 (FIPS 180-4).
class Sha256 {
 public:
  Sha256();

  void update(const void* data, std::size_t length);
  void update(std::string_view text);
  void update(const std::vector<std::byte>& data);

  /// Finalize the digest. The object must not be reused afterwards without a reset.
  [[nodiscard]] Digest finish();

 private:
  void compress(const std::uint8_t* block);

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_{0};
  std::size_t buffer_used_{0};
};

[[nodiscard]] Digest sha256(const void* data, std::size_t length);
[[nodiscard]] Digest sha256(std::string_view text);
[[nodiscard]] Digest sha256(const std::vector<std::byte>& data);

/// CRC-32C (Castagnoli) used for framing and snapshot integrity. The seed is
/// required on the raw-pointer overload so that a string literal can only match
/// the std::string_view overload below; seeding composes, so
/// crc32c(b, crc32c(a)) continues the checksum over a and b.
[[nodiscard]] std::uint32_t crc32c(const void* data, std::size_t length, std::uint32_t seed) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view text, std::uint32_t seed = 0) noexcept;
[[nodiscard]] std::uint32_t crc32c(const std::vector<std::byte>& data, std::uint32_t seed = 0) noexcept;

/// FNV-1a 64-bit hash used only for in-memory indexing, never for identity.
[[nodiscard]] std::uint64_t fnv1a64(std::string_view text) noexcept;

}  // namespace trxreg
