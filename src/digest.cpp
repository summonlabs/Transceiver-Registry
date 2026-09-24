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

#include "trxreg/digest.hpp"

#include <array>
#include <cstring>

namespace trxreg {
namespace {

constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t value, std::uint32_t bits) noexcept {
  return (value >> bits) | (value << (32u - bits));
}

constexpr std::array<std::uint32_t, 256> make_crc32c_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t i = 0; i < 256u; ++i) {
    std::uint32_t crc = i;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1u) != 0u ? (crc >> 1u) ^ 0x82f63b78u : (crc >> 1u);
    }
    table[i] = crc;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32cTable = make_crc32c_table();

}  // namespace

Sha256::Sha256() {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::compress(const std::uint8_t* block) {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24u) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16u) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8u) |
           (static_cast<std::uint32_t>(block[i * 4 + 3]));
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7u) ^ rotr(w[i - 15], 18u) ^ (w[i - 15] >> 3u);
    const std::uint32_t s1 = rotr(w[i - 2], 17u) ^ rotr(w[i - 2], 19u) ^ (w[i - 2] >> 10u);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t length) {
  if (length == 0) {
    return;
  }
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_bytes_ += static_cast<std::uint64_t>(length);

  if (buffer_used_ > 0) {
    const std::size_t want = 64 - buffer_used_;
    const std::size_t take = length < want ? length : want;
    std::memcpy(buffer_.data() + buffer_used_, bytes, take);
    buffer_used_ += take;
    bytes += take;
    length -= take;
    if (buffer_used_ == 64) {
      compress(buffer_.data());
      buffer_used_ = 0;
    }
  }

  while (length >= 64) {
    compress(bytes);
    bytes += 64;
    length -= 64;
  }

  if (length > 0) {
    std::memcpy(buffer_.data(), bytes, length);
    buffer_used_ = length;
  }
}

void Sha256::update(std::string_view text) { update(text.data(), text.size()); }

void Sha256::update(const std::vector<std::byte>& data) { update(data.data(), data.size()); }

Digest Sha256::finish() {
  const std::uint64_t bit_length = total_bytes_ * 8u;
  const std::uint8_t pad = 0x80u;
  update(&pad, 1);

  const std::uint8_t zero = 0x00u;
  while (buffer_used_ != 56) {
    update(&zero, 1);
  }

  std::uint8_t length_bytes[8];
  for (std::size_t i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (56u - 8u * i)) & 0xffu);
  }
  update(length_bytes, 8);

  Digest digest;
  for (std::size_t i = 0; i < 8; ++i) {
    digest.bytes[i * 4 + 0] = static_cast<std::uint8_t>((state_[i] >> 24u) & 0xffu);
    digest.bytes[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16u) & 0xffu);
    digest.bytes[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8u) & 0xffu);
    digest.bytes[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xffu);
  }
  return digest;
}

Digest sha256(const void* data, std::size_t length) {
  Sha256 hasher;
  hasher.update(data, length);
  return hasher.finish();
}

Digest sha256(std::string_view text) { return sha256(text.data(), text.size()); }

Digest sha256(const std::vector<std::byte>& data) { return sha256(data.data(), data.size()); }

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest::to_hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[(bytes[i] >> 4u) & 0x0fu];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0fu];
  }
  return out;
}

Result<Digest> Digest::from_hex(std::string_view text) {
  if (text.size() != 64) {
    return make_error(StatusCode::InvalidArgument, "digest hex text must be exactly 64 characters");
  }
  Digest digest;
  auto nibble = [](char ch, std::uint8_t& out) -> bool {
    if (ch >= '0' && ch <= '9') {
      out = static_cast<std::uint8_t>(ch - '0');
      return true;
    }
    if (ch >= 'a' && ch <= 'f') {
      out = static_cast<std::uint8_t>(ch - 'a' + 10);
      return true;
    }
    if (ch >= 'A' && ch <= 'F') {
      out = static_cast<std::uint8_t>(ch - 'A' + 10);
      return true;
    }
    return false;
  };
  for (std::size_t i = 0; i < 32; ++i) {
    std::uint8_t hi = 0;
    std::uint8_t lo = 0;
    if (!nibble(text[i * 2], hi) || !nibble(text[i * 2 + 1], lo)) {
      return make_error(StatusCode::InvalidArgument, "digest hex text contains a non-hex character");
    }
    digest.bytes[i] = static_cast<std::uint8_t>((hi << 4u) | lo);
  }
  return digest;
}

std::uint32_t crc32c(const void* data, std::size_t length, std::uint32_t seed) noexcept {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = ~seed;
  for (std::size_t i = 0; i < length; ++i) {
    crc = kCrc32cTable[(crc ^ bytes[i]) & 0xffu] ^ (crc >> 8u);
  }
  return ~crc;
}

std::uint32_t crc32c(std::string_view text, std::uint32_t seed) noexcept {
  return crc32c(text.data(), text.size(), seed);
}

std::uint32_t crc32c(const std::vector<std::byte>& data, std::uint32_t seed) noexcept {
  return crc32c(data.data(), data.size(), seed);
}

std::uint64_t fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = 0xcbf29ce484222325ull;
  for (const char ch : text) {
    hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(ch));
    hash *= 0x100000001b3ull;
  }
  return hash;
}

}  // namespace trxreg
