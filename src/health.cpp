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

#include "trxreg/health.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <utility>
#include <vector>

#include "domain.hpp"

namespace trxreg {
namespace {

bool is_hysteresis_state(MetricState state) noexcept {
  return state == MetricState::Ok || state == MetricState::Degraded || state == MetricState::Critical;
}

/// Severity rank used to decide whether a zone change is an escalation.
int zone_rank(MetricState state) noexcept {
  switch (state) {
    case MetricState::Critical:
      return 2;
    case MetricState::Degraded:
      return 1;
    default:
      return 0;
  }
}

}  // namespace

bool HealthThreshold::threshold_for(HealthMetric metric_in, std::uint16_t lane_in) const noexcept {
  if (metric != metric_in) {
    return false;
  }
  return lane == kModuleLane || lane == lane_in;
}

MetricState classify_value(const HealthThreshold& threshold, double value) noexcept {
  // Entry thresholds only: this is the raw zone of a value with no hysteresis.
  if (threshold.direction == ThresholdDirection::Above) {
    if (threshold.has_critical && value >= threshold.critical_enter) {
      return MetricState::Critical;
    }
    if (threshold.has_degraded && value >= threshold.degraded_enter) {
      return MetricState::Degraded;
    }
    return MetricState::Ok;
  }
  if (threshold.has_critical && value <= threshold.critical_enter) {
    return MetricState::Critical;
  }
  if (threshold.has_degraded && value <= threshold.degraded_enter) {
    return MetricState::Degraded;
  }
  return MetricState::Ok;
}

HealthLatch advance_latch(const HealthThreshold& threshold, const HealthLatch& previous, double value,
                          WallNs sample_wall_ns, Sequence sample_sequence, Generation generation) noexcept {
  HealthLatch latch = previous;
  MetricState zone = MetricState::Ok;
  if (threshold.direction == ThresholdDirection::Above) {
    const double critical_boundary = latch.state == MetricState::Critical ? threshold.critical_exit
                                                                         : threshold.critical_enter;
    const double degraded_boundary = latch.state == MetricState::Degraded ? threshold.degraded_exit
                                                                         : threshold.degraded_enter;
    if (threshold.has_critical && value >= critical_boundary) {
      zone = MetricState::Critical;
    } else if (threshold.has_degraded && value >= degraded_boundary) {
      zone = MetricState::Degraded;
    }
  } else {
    const double critical_boundary = latch.state == MetricState::Critical ? threshold.critical_exit
                                                                         : threshold.critical_enter;
    const double degraded_boundary = latch.state == MetricState::Degraded ? threshold.degraded_exit
                                                                         : threshold.degraded_enter;
    if (threshold.has_critical && value <= critical_boundary) {
      zone = MetricState::Critical;
    } else if (threshold.has_degraded && value <= degraded_boundary) {
      zone = MetricState::Degraded;
    }
  }

  if (!is_hysteresis_state(latch.state)) {
    // No usable previous classification: the first fresh sample establishes it.
    latch.state = zone;
    latch.consecutive = 0;
    latch.last_transition_generation = generation;
    latch.last_transition_wall_ns = sample_wall_ns;
  } else if (zone == latch.state) {
    latch.consecutive = 0;
  } else if (zone_rank(zone) > zone_rank(latch.state)) {
    ++latch.consecutive;
    if (latch.consecutive >= threshold.escalate_after) {
      latch.state = zone;
      latch.consecutive = 0;
      latch.last_transition_generation = generation;
      latch.last_transition_wall_ns = sample_wall_ns;
    }
  } else {
    ++latch.consecutive;
    if (latch.consecutive >= threshold.recover_after) {
      latch.state = zone;
      latch.consecutive = 0;
      latch.last_transition_generation = generation;
      latch.last_transition_wall_ns = sample_wall_ns;
    }
  }

  latch.last_sample_wall_ns = sample_wall_ns;
  latch.last_sample_sequence = sample_sequence;
  return latch;
}

namespace detail {

bool telemetry_capability_metric(CapabilityKey key, HealthMetric& metric) noexcept {
  switch (key) {
    case CapabilityKey::TemperatureTelemetry:
      metric = HealthMetric::TemperatureCelsius;
      return true;
    case CapabilityKey::VoltageTelemetry:
      metric = HealthMetric::SupplyVoltageVolts;
      return true;
    case CapabilityKey::TxPowerTelemetry:
      metric = HealthMetric::TxPowerDbm;
      return true;
    case CapabilityKey::RxPowerTelemetry:
      metric = HealthMetric::RxPowerDbm;
      return true;
    case CapabilityKey::BiasCurrentTelemetry:
      metric = HealthMetric::TxBiasCurrentMilliamps;
      return true;
    case CapabilityKey::LaneSkewTelemetry:
      metric = HealthMetric::LaneSkewPicoseconds;
      return true;
    default:
      return false;
  }
}

const HealthThreshold* select_threshold(const std::vector<HealthThreshold>& thresholds, HealthMetric metric,
                                        std::uint16_t lane) noexcept {
  const HealthThreshold* module_wide = nullptr;
  const HealthThreshold* lane_specific = nullptr;
  for (const HealthThreshold& threshold : thresholds) {
    if (!threshold.live || threshold.metric != metric) {
      continue;
    }
    if (threshold.lane == lane) {
      lane_specific = &threshold;
    } else if (threshold.lane == kModuleLane) {
      module_wide = &threshold;
    }
  }
  return lane_specific != nullptr ? lane_specific : module_wide;
}

Status validate_threshold(const HealthThreshold& threshold) {
  if (threshold.metric == HealthMetric::Unknown || threshold.metric == HealthMetric::Unsupported) {
    return Status(StatusCode::InvalidArgument, "threshold must name a modelled metric");
  }
  double min_value = 0.0;
  double max_value = 0.0;
  if (!metric_plausible_range(threshold.metric, min_value, max_value)) {
    return Status(StatusCode::InvalidArgument, "threshold metric has no plausible range");
  }
  if (threshold.lane != kModuleLane && threshold.lane > 255) {
    return Status(StatusCode::InvalidArgument, "threshold lane index is out of range");
  }
  if (!threshold.has_degraded && !threshold.has_critical) {
    return Status(StatusCode::InvalidArgument, "threshold must define at least one band");
  }
  if (threshold.escalate_after == 0 || threshold.recover_after == 0) {
    return Status(StatusCode::InvalidArgument, "threshold hysteresis counts must be at least one");
  }
  if (threshold.max_age_ns <= 0) {
    return Status(StatusCode::InvalidArgument, "threshold freshness bound must be positive");
  }
  if (threshold.disagreement_tolerance < 0.0 || !std::isfinite(threshold.disagreement_tolerance)) {
    return Status(StatusCode::InvalidArgument, "threshold disagreement tolerance must be finite and non-negative");
  }
  const bool above = threshold.direction == ThresholdDirection::Above;
  const auto ordered = [above](double exit_value, double enter_value) {
    return above ? exit_value <= enter_value : exit_value >= enter_value;
  };
  if (threshold.has_degraded) {
    if (!std::isfinite(threshold.degraded_enter) || !std::isfinite(threshold.degraded_exit)) {
      return Status(StatusCode::InvalidArgument, "threshold bounds must be finite");
    }
    if (!ordered(threshold.degraded_exit, threshold.degraded_enter)) {
      return Status(StatusCode::InvalidArgument,
                    "hysteresis exit bound must be less severe than the entry bound");
    }
  }
  if (threshold.has_critical) {
    if (!std::isfinite(threshold.critical_enter) || !std::isfinite(threshold.critical_exit)) {
      return Status(StatusCode::InvalidArgument, "threshold bounds must be finite");
    }
    if (!ordered(threshold.critical_exit, threshold.critical_enter)) {
      return Status(StatusCode::InvalidArgument,
                    "hysteresis exit bound must be less severe than the entry bound");
    }
  }
  if (threshold.has_degraded && threshold.has_critical) {
    const bool consistent =
        above ? threshold.degraded_enter <= threshold.critical_enter : threshold.degraded_enter >= threshold.critical_enter;
    if (!consistent) {
      return Status(StatusCode::InvalidArgument, "degraded band must be less severe than the critical band");
    }
  }
  return ok_status();
}

SeriesClassification classify_series(const std::vector<HealthSample>& samples, const HealthThreshold* threshold,
                                     ModuleUid uid, IncarnationId incarnation, WallNs now_wall_ns,
                                     std::int64_t max_future_skew_ns) {
  SeriesClassification result;

  // Newest live sample per source, plus counters over every sample of the series.
  std::map<std::uint32_t, const HealthSample*> newest_by_source;
  for (const HealthSample& sample : samples) {
    if (sample.module != uid) {
      continue;
    }
    if (sample.incarnation != incarnation || !sample.live) {
      ++result.fenced;
      continue;
    }
    const auto existing = newest_by_source.find(sample.source.value());
    if (existing == newest_by_source.end() || existing->second->observed_at_wall_ns <= sample.observed_at_wall_ns) {
      newest_by_source[sample.source.value()] = &sample;
    }
  }
  result.sources = static_cast<std::uint32_t>(newest_by_source.size());

  if (newest_by_source.empty()) {
    result.state = result.fenced > 0 ? MetricState::Fenced : MetricState::Unknown;
    result.reason_kind = result.fenced > 0 ? HealthIssueKind::Fenced : HealthIssueKind::Missing;
    result.reason = result.fenced > 0 ? "every sample belongs to a fenced incarnation"
                                      : "no sample has been ingested for this metric";
    return result;
  }

  // Without a published threshold the runtime refuses to classify: the value is
  // reported as observed but the state stays Unclassified, never Ok.
  if (threshold == nullptr) {
    const HealthSample* newest_present = nullptr;
    for (const auto& entry : newest_by_source) {
      const HealthSample& sample = *entry.second;
      if (sample.presence != SamplePresence::Present) {
        continue;
      }
      if (newest_present == nullptr || newest_present->observed_at_wall_ns <= sample.observed_at_wall_ns) {
        newest_present = &sample;
      }
    }
    if (newest_present == nullptr) {
      result.state = MetricState::Unknown;
      result.reason_kind = HealthIssueKind::NotAvailable;
      result.reason = "no usable measurement is available and no threshold is published";
      return result;
    }
    result.state = MetricState::Unclassified;
    result.has_value = true;
    result.value = newest_present->value;
    result.has_age = true;
    result.age_ns = now_wall_ns > newest_present->observed_at_wall_ns ? now_wall_ns - newest_present->observed_at_wall_ns : 0;
    result.reason_kind = HealthIssueKind::NoThreshold;
    result.reason = "no threshold is published for this metric";
    return result;
  }

  const WallNs max_age_ns = threshold->max_age_ns;
  std::vector<double> fresh_values;
  const HealthSample* newest_fresh = nullptr;
  WallNs newest_fresh_age = 0;
  std::size_t aged_out_sources = 0;
  std::size_t presence_unusable_sources = 0;
  std::size_t future_sources = 0;
  std::string unusable_reason;
  HealthIssueKind unusable_kind = HealthIssueKind::Missing;

  for (const auto& entry : newest_by_source) {
    const HealthSample& sample = *entry.second;
    if (sample.presence != SamplePresence::Present) {
      ++presence_unusable_sources;
      if (unusable_reason.empty()) {
        switch (sample.presence) {
          case SamplePresence::NotAvailable:
            unusable_reason = "the module reports the metric as not available";
            unusable_kind = HealthIssueKind::NotAvailable;
            break;
          case SamplePresence::ReadError:
            unusable_reason = "the last read of the metric failed";
            unusable_kind = HealthIssueKind::ReadError;
            break;
          case SamplePresence::NotSupported:
            unusable_reason = "the metric is not supported by this module";
            unusable_kind = HealthIssueKind::NotSupported;
            break;
          case SamplePresence::Present:
            break;
        }
      }
      continue;
    }
    if (sample.observed_at_wall_ns > now_wall_ns + max_future_skew_ns) {
      ++future_sources;
      ++aged_out_sources;
      if (unusable_reason.empty()) {
        unusable_reason = "the observation timestamp is in the future";
        unusable_kind = HealthIssueKind::FutureTimestamp;
      }
      continue;
    }
    const WallNs age = now_wall_ns > sample.observed_at_wall_ns ? now_wall_ns - sample.observed_at_wall_ns : 0;
    if (age > max_age_ns) {
      ++aged_out_sources;
      if (unusable_reason.empty()) {
        unusable_reason = "the newest sample is older than the freshness bound";
        unusable_kind = HealthIssueKind::Stale;
      }
      continue;
    }
    ++result.fresh;
    fresh_values.push_back(sample.value);
    if (newest_fresh == nullptr || newest_fresh->observed_at_wall_ns <= sample.observed_at_wall_ns) {
      newest_fresh = &sample;
      newest_fresh_age = age;
    }
  }
  result.stale = static_cast<std::int64_t>(aged_out_sources + presence_unusable_sources);

  if (fresh_values.empty()) {
    if (aged_out_sources > 0) {
      // Evidence exists but no longer describes the present.
      result.state = MetricState::Stale;
      result.reason_kind = future_sources > 0 ? HealthIssueKind::FutureTimestamp : HealthIssueKind::Stale;
      result.reason = unusable_reason.empty() ? "the newest sample is older than the freshness bound" : unusable_reason;
    } else {
      // No measurement exists at all: absent telemetry is never a value.
      result.state = MetricState::Unknown;
      result.reason_kind = unusable_kind;
      result.reason = unusable_reason.empty() ? "no usable measurement is available" : unusable_reason;
    }
    return result;
  }

  double lowest = fresh_values.front();
  double highest = fresh_values.front();
  for (const double value : fresh_values) {
    lowest = std::min(lowest, value);
    highest = std::max(highest, value);
  }
  if (fresh_values.size() > 1 && (highest - lowest) > threshold->disagreement_tolerance) {
    result.state = MetricState::Conflicting;
    result.has_value = true;
    result.value = newest_fresh->value;
    result.has_age = true;
    result.age_ns = newest_fresh_age;
    result.reason_kind = HealthIssueKind::SourceConflict;
    result.reason = "live sources disagree beyond the published tolerance";
    return result;
  }

  result.has_value = true;
  result.value = newest_fresh->value;
  result.has_age = true;
  result.age_ns = newest_fresh_age;
  result.state = classify_value(*threshold, result.value);
  result.reason = "classified against the published threshold";
  return result;
}

}  // namespace detail

bool HealthReport::healthy() const noexcept {
  if (outcome != HealthOutcome::Fresh) {
    return false;
  }
  return worst == MetricState::Ok;
}

}  // namespace trxreg
