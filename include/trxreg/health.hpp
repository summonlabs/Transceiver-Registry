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
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// Lane index meaning "the module as a whole".
inline constexpr std::uint16_t kModuleLane = 0xFFFF;

/// Direction in which a metric moves away from nominal.
enum class ThresholdDirection : std::uint8_t {
  /// Values above the thresholds are worse (temperature, bias current, ...).
  Above = 0,
  /// Values below the thresholds are worse (receive power, supply voltage, ...).
  Below,
};

/// A caller-supplied measurement, before the registry attaches authority and
/// ordering. Presence is explicit: a missing measurement is never a zero.
struct HealthSampleInput {
  friend bool operator==(const HealthSampleInput& lhs, const HealthSampleInput& rhs) noexcept = default;

  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};
  SamplePresence presence{SamplePresence::Present};
  double value{0.0};
  WallNs observed_at_wall_ns{0};
  std::uint64_t observed_at_monotonic_ns{0};
  ClockDomainId clock_domain{};
  Provenance provenance{};
};

/// A stored measurement with full provenance and fencing information.
struct HealthSample {
  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};
  SamplePresence presence{SamplePresence::Present};
  double value{0.0};
  WallNs observed_at_wall_ns{0};
  std::uint64_t observed_at_monotonic_ns{0};
  ClockDomainId clock_domain{};
  Provenance provenance{};
  SourceId source{};
  SourceEpoch source_epoch{};
  ModuleUid module{};
  IncarnationId incarnation{};
  Generation generation{};
  Sequence sequence{};
  /// False when the sample belongs to a fenced incarnation or a retired epoch.
  bool live{true};

  friend bool operator==(const HealthSample& lhs, const HealthSample& rhs) noexcept = default;
};

/// Published classification policy for one metric series.
///
/// Thresholds are only meaningful where the data model justifies them, so a
/// metric without a published threshold is reported as `Unclassified` rather
/// than being compared against a built-in default. Hysteresis is expressed as
/// distinct enter/exit thresholds plus the number of consecutive samples
/// required to escalate and to recover.
struct HealthThreshold {
  HealthMetric metric{HealthMetric::Unknown};
  /// `kModuleLane` applies the threshold to every lane of the metric.
  std::uint16_t lane{kModuleLane};
  ThresholdDirection direction{ThresholdDirection::Above};
  bool has_degraded{false};
  double degraded_enter{0.0};
  double degraded_exit{0.0};
  bool has_critical{false};
  double critical_enter{0.0};
  double critical_exit{0.0};
  /// Consecutive qualifying samples required before escalating a state.
  std::uint32_t escalate_after{1};
  /// Consecutive qualifying samples required before recovering a state.
  std::uint32_t recover_after{1};
  /// Maximum age of a sample that may still describe the present.
  WallNs max_age_ns{0};
  /// Maximum spread between simultaneous sources before the series is
  /// considered conflicting. Zero means any difference conflicts.
  double disagreement_tolerance{0.0};
  Provenance provenance{};
  SourceId source{};
  SourceEpoch source_epoch{};
  Generation generation{};
  Sequence sequence{};
  bool live{true};

  [[nodiscard]] bool threshold_for(HealthMetric metric_in, std::uint16_t lane_in) const noexcept;

  friend bool operator==(const HealthThreshold& lhs, const HealthThreshold& rhs) noexcept = default;
};

/// Hysteresis latch for one metric series. Persisted, and re-validated against
/// the clock at load time so a historical state never becomes current.
struct HealthLatch {
  MetricState state{MetricState::Unknown};
  std::uint32_t consecutive{0};
  WallNs last_sample_wall_ns{0};
  Sequence last_sample_sequence{};
  Generation last_transition_generation{};
  WallNs last_transition_wall_ns{0};

  friend bool operator==(const HealthLatch& lhs, const HealthLatch& rhs) noexcept = default;
};

/// Why a metric could not be classified.
enum class HealthIssueKind : std::uint8_t {
  Missing = 0,
  Stale,
  Fenced,
  SourceConflict,
  NoThreshold,
  NotAvailable,
  ReadError,
  NotSupported,
  FutureTimestamp,
  OutOfRange,
  SupersededThreshold,
};

std::string_view to_string(HealthIssueKind kind) noexcept;
bool health_issue_kind_from_string(std::string_view text, HealthIssueKind& out) noexcept;

struct HealthIssue {
  HealthIssueKind kind{HealthIssueKind::Missing};
  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};
  std::string detail;

  friend bool operator==(const HealthIssue& lhs, const HealthIssue& rhs) noexcept = default;
};

/// Classification of one metric series.
struct MetricHealth {
  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};
  MetricState state{MetricState::Unknown};
  bool has_value{false};
  double value{0.0};
  bool has_age{false};
  WallNs age_ns{0};
  std::int64_t sample_count{0};
  std::int64_t fresh_count{0};
  std::int64_t stale_count{0};
  std::int64_t fenced_count{0};
  std::uint32_t source_count{0};
  std::string reason;

  friend bool operator==(const MetricHealth& lhs, const MetricHealth& rhs) noexcept = default;
};

/// Evidence-gated health answer for one module incarnation.
struct HealthReport {
  ModuleUid uid{};
  IncarnationId incarnation{};
  Generation generation{};
  HealthOutcome outcome{HealthOutcome::Unknown};
  MetricState worst{MetricState::Unknown};
  std::vector<MetricHealth> metrics;
  std::vector<HealthIssue> issues;
  WallNs evaluated_at_wall_ns{0};
  ClockDomainId clock_domain{};
  Digest digest{};

  /// True only when every considered metric is fresh, classified `Ok`, and
  /// established by evidence belonging to the current incarnation.
  [[nodiscard]] bool healthy() const noexcept;
};

/// Classification thresholds for a single value under a threshold policy.
MetricState classify_value(const HealthThreshold& threshold, double value) noexcept;

/// Apply hysteresis to one fresh sample.
///
/// The value (not a pre-computed classification) is required because the exit
/// thresholds of the *current* state decide whether a sample is a recovery
/// candidate at all: a value that falls back between the exit and the entry
/// bound holds the state and resets the consecutive counter instead of starting
/// a recovery.
HealthLatch advance_latch(const HealthThreshold& threshold, const HealthLatch& previous, double value,
                          WallNs sample_wall_ns, Sequence sample_sequence, Generation generation) noexcept;

}  // namespace trxreg
