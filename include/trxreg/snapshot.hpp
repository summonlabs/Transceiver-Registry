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

#include <cstdint>
#include <string>

#include "trxreg/canonical.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/result.hpp"

namespace trxreg {

class Registry;

struct SaveOptions {
  /// Flush file contents to stable storage before the snapshot is renamed into
  /// place. Disabling this trades durability for speed in tests only.
  bool fsync{true};
  /// Persist per-claim and per-declaration superseded history.
  bool include_history{true};
};

struct LoadOptions {
  /// Recover the longest valid prefix of a torn or partially written snapshot
  /// instead of rejecting the file outright. Recovery never invents state: the
  /// dropped bytes are reported and every recovered dynamic sample is
  /// re-validated against the current clock.
  bool allow_tail_recovery{true};
  /// Reject a snapshot whose format version differs from the supported one.
  bool require_supported_version{true};
  CanonicalLimits limits{CanonicalLimits::snapshot()};
};

/// What a load actually applied, including anything that had to be discarded.
struct LoadReport {
  std::uint16_t format_version{0};
  Generation generation{};
  std::uint32_t registry_incarnation{0};
  std::uint64_t modules{0};
  std::uint64_t incarnations{0};
  std::uint64_t sources{0};
  std::uint64_t ports{0};
  std::uint64_t rules{0};
  std::uint64_t thresholds{0};
  std::uint64_t claims{0};
  std::uint64_t declarations{0};
  std::uint64_t samples{0};
  std::uint64_t fenced_incarnations{0};
  /// Evidence that could not be current after this load: samples beyond their
  /// freshness bound, samples from another clock domain, and hysteresis latches
  /// whose evidence base no longer holds.
  std::uint64_t evidence_invalidated_on_load{0};
  bool tail_recovered{false};
  std::uint64_t dropped_tail_bytes{0};
  std::string recovery_note;
  Digest content_digest{};
  WallNs loaded_at_wall_ns{0};

  friend bool operator==(const LoadReport& lhs, const LoadReport& rhs) noexcept = default;
};

/// Persist the registry to a file. The write is atomic: content is written to a
/// temporary file in the same directory, flushed, and renamed over the target,
/// so a crash never leaves a partially overwritten snapshot behind.
Status save_snapshot(const Registry& registry, const std::string& path, const SaveOptions& options = {});

/// Load a snapshot into an empty registry.
Result<LoadReport> load_snapshot(Registry& registry, const std::string& path, const LoadOptions& options = {});

/// Validate a snapshot file without mutating any registry.
Result<LoadReport> inspect_snapshot(const std::string& path, const LoadOptions& options = {});

}  // namespace trxreg
