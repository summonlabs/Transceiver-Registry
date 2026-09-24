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

// Internal domain logic shared by the registry and the persistence layer:
// consensus building over multi-source evidence, threshold selection, and
// health classification helpers. Kept out of the public headers so that tests
// can build independent reference models instead of calling the same code.

#include <compare>
#include <cstdint>
#include <string>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg::detail {

/// Build consensus records for every (field, subkey) present in `claims`.
/// Claims flagged `live == false` are reported as superseded and never decide
/// the outcome. Results are ordered by (field, subkey).
std::vector<FieldConsensus> build_identity_consensus(std::vector<IdentityClaim> claims);

/// Build consensus records for every (key, subkey) present in `declarations`.
std::vector<CapabilityConsensus> build_capability_consensus(std::vector<CapabilityDeclaration> declarations);

/// Value equality for consensus comparison: canonical sets compare structurally.
bool capability_values_equal(const CapabilityValue& lhs, const CapabilityValue& rhs) noexcept;

/// Select the effective threshold for a metric series. Module-wide thresholds
/// (lane == kModuleLane) and lane-specific thresholds are both considered; a
/// lane-specific threshold wins. Returns nullptr when no live threshold applies.
const HealthThreshold* select_threshold(const std::vector<HealthThreshold>& thresholds, HealthMetric metric,
                                        std::uint16_t lane) noexcept;

/// Health metric a telemetry capability declares, if any.
bool telemetry_capability_metric(CapabilityKey key, HealthMetric& metric) noexcept;

/// Validate a published threshold for internal consistency (hysteresis ordering).
Status validate_threshold(const HealthThreshold& threshold);

/// Validate a published rule.
Status validate_rule(const CompatRule& rule);

/// The canonical series key of a health metric (metric and lane).
struct SeriesKey {
  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};

  friend bool operator==(const SeriesKey& lhs, const SeriesKey& rhs) noexcept = default;
  friend auto operator<=>(const SeriesKey& lhs, const SeriesKey& rhs) noexcept = default;
};

/// Classification of a series from evidence and policy, without hysteresis.
struct SeriesClassification {
  MetricState state{MetricState::Unknown};
  /// Why the classification came out the way it did, used to build the report's
  /// issue list without re-deriving the reason.
  HealthIssueKind reason_kind{HealthIssueKind::Missing};
  bool has_value{false};
  double value{0.0};
  bool has_age{false};
  WallNs age_ns{0};
  std::int64_t fresh{0};
  std::int64_t stale{0};
  std::int64_t fenced{0};
  std::uint32_t sources{0};
  std::string reason;
};

/// Classify the newest live sample of each source for one series. Freshness is
/// always evaluated against `now_wall_ns`; a sample that is beyond its
/// freshness bound is Stale no matter when it was ingested.
SeriesClassification classify_series(const std::vector<HealthSample>& samples, const HealthThreshold* threshold,
                                     ModuleUid uid, IncarnationId incarnation, WallNs now_wall_ns,
                                     std::int64_t max_future_skew_ns);

}  // namespace trxreg::detail
