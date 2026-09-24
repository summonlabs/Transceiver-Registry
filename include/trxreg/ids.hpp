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

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "trxreg/result.hpp"

namespace trxreg {

/// A strongly typed identifier: two ids with different tags never compare.
template <class Tag, class Rep>
class StrongId {
 public:
  using rep_type = Rep;

  constexpr StrongId() noexcept = default;
  constexpr explicit StrongId(Rep value) noexcept : value_(value) {}

  [[nodiscard]] constexpr Rep value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool valid() const noexcept { return value_ != Rep{0}; }

  friend constexpr bool operator==(StrongId lhs, StrongId rhs) noexcept = default;
  friend constexpr auto operator<=>(StrongId lhs, StrongId rhs) noexcept = default;

 private:
  Rep value_{};
};

struct SourceIdTag;
struct SourceEpochTag;
struct ModuleUidTag;
struct IncarnationIdTag;
struct RuleIdTag;
struct GenerationTag;
struct SequenceTag;
struct ClockDomainTag;

/// Registry-local identity of an evidence source (a publisher process, a probe
/// agent, a configuration importer, ...).
using SourceId = StrongId<SourceIdTag, std::uint32_t>;
/// Incarnation counter for a source. Re-registering a source name produces a new
/// epoch; authority tokens minted under an older epoch are refused.
using SourceEpoch = StrongId<SourceEpochTag, std::uint32_t>;
/// Registry-local identity of a module record.
using ModuleUid = StrongId<ModuleUidTag, std::uint64_t>;
/// Incarnation counter for a module record. A physical replacement bumps it.
using IncarnationId = StrongId<IncarnationIdTag, std::uint32_t>;
using RuleId = StrongId<RuleIdTag, std::uint32_t>;
/// Monotonic registry generation. Every committed mutation advances it by one.
using Generation = StrongId<GenerationTag, std::uint64_t>;
/// Monotonic evidence sequence within a registry lifetime.
using Sequence = StrongId<SequenceTag, std::uint64_t>;
/// Identity of a clock domain (one process incarnation of one clock).
using ClockDomainId = StrongId<ClockDomainTag, std::uint64_t>;

inline constexpr std::uint64_t kMaxKeyBytes = 128;

/// Validate a caller-supplied textual key (slot, port, module key, source name).
Status validate_key_text(std::string_view text, std::string_view what, std::uint64_t max_bytes = kMaxKeyBytes);

/// A validated textual key with a distinct type per domain.
template <class Tag>
class TextKey {
 public:
  TextKey() = default;

  static Result<TextKey> parse(std::string_view text, std::string_view what) {
    TRXREG_TRY(validate_key_text(text, what));
    TextKey key;
    key.value_.assign(text);
    return key;
  }

  [[nodiscard]] const std::string& str() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

  friend bool operator==(const TextKey& lhs, const TextKey& rhs) noexcept = default;
  friend auto operator<=>(const TextKey& lhs, const TextKey& rhs) noexcept = default;

 private:
  std::string value_;
};

struct SlotKeyTag;
struct PortKeyTag;
struct ModuleKeyTag;

/// Physical slot / bay / cage identity, for example `chassis0/bay2`.
using SlotKey = TextKey<SlotKeyTag>;
/// Host port identity, for example `switch0/ethernet1/1`.
using PortKey = TextKey<PortKeyTag>;
/// Caller-chosen stable key for a physical module position or serial identity.
using ModuleKey = TextKey<ModuleKeyTag>;

}  // namespace trxreg
