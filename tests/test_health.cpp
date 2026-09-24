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

#include "registry_support.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

namespace {

using namespace trxreg;
using namespace trxreg::test;

/// Artifacts live in the working directory the test runner chooses. The
/// directory is created once and reused; nothing is written into the source tree.
/// Artifacts live under the OS temporary directory so a test run can never
/// leave files inside the source tree.
std::string snapshot_path(const char* name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "trxreg-tests";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return (directory / name).string();
}

const MetricHealth* find_metric(const HealthReport& report, HealthMetric metric) {
  for (const MetricHealth& row : report.metrics) {
    if (row.metric == metric) {
      return &row;
    }
  }
  return nullptr;
}

bool has_issue(const HealthReport& report, HealthIssueKind kind) {
  for (const HealthIssue& issue : report.issues) {
    if (issue.kind == kind) {
      return true;
    }
  }
  return false;
}

}  // namespace

// Absence of telemetry is not health and is certainly not a zero measurement.
TRXREG_TEST(health_missing_telemetry_is_not_healthy) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay1");
  publish_threshold(registry, source.authority(), temperature_threshold());

  const Result<HealthReport> report = registry.health(module);
  REQUIRE_OK(report);
  CHECK(report.value().outcome == HealthOutcome::Unknown);
  CHECK(report.value().worst == MetricState::Unknown);
  CHECK(!report.value().healthy());
  REQUIRE(!report.value().metrics.empty());
  const MetricHealth* temperature = find_metric(report.value(), HealthMetric::TemperatureCelsius);
  REQUIRE(temperature != nullptr);
  CHECK(temperature->state == MetricState::Unknown);
  CHECK(!temperature->has_value);
  CHECK_EQ(temperature->sample_count, std::int64_t{0});
  CHECK(has_issue(report.value(), HealthIssueKind::Missing));

  // A module that declares telemetry it never delivers is still unknown.
  publish_capability(registry, source.authority(), module, CapabilityKey::VoltageTelemetry,
                     CapabilityValue::boolean(true));
  const Result<HealthReport> declared = registry.health(module);
  REQUIRE_OK(declared);
  CHECK(!declared.value().healthy());
  const MetricHealth* voltage = find_metric(declared.value(), HealthMetric::SupplyVoltageVolts);
  REQUIRE(voltage != nullptr);
  CHECK(voltage->state == MetricState::Unknown);
  CHECK(!voltage->has_value);
}

// "Not available" and "read failed" are evidence of absence, never a zero.
TRXREG_TEST(health_absent_measurements_are_not_zero) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay2");
  publish_threshold(registry, source.authority(), temperature_threshold());

  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 0.0, clock->wall_now_ns(),
         kModuleLane, SamplePresence::NotAvailable);
  const Result<HealthReport> absent = registry.health(module);
  REQUIRE_OK(absent);
  const MetricHealth* temperature = find_metric(absent.value(), HealthMetric::TemperatureCelsius);
  REQUIRE(temperature != nullptr);
  CHECK(temperature->state == MetricState::Unknown);
  CHECK(!temperature->has_value);
  CHECK(!absent.value().healthy());

  clock->advance_ns(1'000'000'000LL);
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 0.0, clock->wall_now_ns(),
         kModuleLane, SamplePresence::ReadError);
  const Result<HealthReport> failed = registry.health(module);
  REQUIRE_OK(failed);
  const MetricHealth* after = find_metric(failed.value(), HealthMetric::TemperatureCelsius);
  REQUIRE(after != nullptr);
  CHECK(after->state == MetricState::Unknown);
  CHECK(!after->has_value);
  CHECK(!failed.value().healthy());
}

TRXREG_TEST(health_freshness_expires_without_restart) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay3");
  publish_threshold(registry, source.authority(), temperature_threshold(60'000'000'000LL));

  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 42.0, clock->wall_now_ns());
  const Result<HealthReport> fresh = registry.health(module);
  REQUIRE_OK(fresh);
  CHECK(fresh.value().outcome == HealthOutcome::Fresh);
  CHECK(fresh.value().worst == MetricState::Ok);
  CHECK(fresh.value().healthy());

  clock->advance_ns(59'000'000'000LL);
  const Result<HealthReport> almost = registry.health(module);
  REQUIRE_OK(almost);
  CHECK(almost.value().healthy());

  clock->advance_ns(2'000'000'000LL);
  const Result<HealthReport> stale = registry.health(module);
  REQUIRE_OK(stale);
  CHECK(stale.value().outcome == HealthOutcome::Stale);
  CHECK(stale.value().worst == MetricState::Stale);
  CHECK(!stale.value().healthy());
  CHECK(has_issue(stale.value(), HealthIssueKind::Stale));
}

// A restart must not resurrect a measurement as current: freshness is evaluated
// against the wall clock at query time, not against the moment of ingestion.
TRXREG_TEST(health_freshness_across_restart) {
  const std::string path = snapshot_path("health-restart.trxr");
  const auto first_clock = make_test_clock(kBaseWallNs, ClockDomainId{11});
  {
    Registry registry({}, first_clock);
    const SourceHandle source = register_source(registry, "probe-agent");
    const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay4");
    publish_threshold(registry, source.authority(), temperature_threshold(60'000'000'000LL));
    ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 44.0, first_clock->wall_now_ns());
    const Result<HealthReport> before = registry.health(module);
    REQUIRE_OK(before);
    CHECK(before.value().healthy());
    REQUIRE_OK(registry.save(path));
  }

  // Restart with a new clock domain ten seconds later: the evidence is still
  // inside its freshness window, so it still describes the present.
  const auto second_clock = make_test_clock(kBaseWallNs + 10'000'000'000LL, ClockDomainId{12});
  {
    Registry registry({}, second_clock);
    const Result<LoadReport> loaded = registry.load(path);
    REQUIRE_OK(loaded);
    CHECK_EQ(loaded.value().evidence_invalidated_on_load, std::uint64_t{0});
    const Result<ModuleHandle> module = [&]() -> Result<ModuleHandle> {
      const Result<IdentityView> view = registry.identity_by_key("chassis0/bay4");
      if (!view.ok()) {
        return view.error();
      }
      ModuleHandle handle;
      handle.uid = view.value().uid;
      handle.incarnation = view.value().incarnation;
      handle.generation = view.value().generation;
      handle.key = view.value().key;
      return handle;
    }();
    REQUIRE_OK(module);
    const Result<HealthReport> after_restart = registry.health(module.value());
    REQUIRE_OK(after_restart);
    CHECK(after_restart.value().outcome == HealthOutcome::Fresh);
    CHECK(after_restart.value().healthy());
  }

  // Restart again, past the freshness window: the same evidence is now stale.
  const auto third_clock = make_test_clock(kBaseWallNs + 61'000'000'000LL, ClockDomainId{13});
  Registry registry({}, third_clock);
  const Result<LoadReport> loaded = registry.load(path);
  REQUIRE_OK(loaded);
  CHECK(loaded.value().evidence_invalidated_on_load >= 1);
  const Result<IdentityView> view = registry.identity_by_key("chassis0/bay4");
  REQUIRE_OK(view);
  ModuleHandle handle;
  handle.uid = view.value().uid;
  handle.incarnation = view.value().incarnation;
  handle.generation = view.value().generation;
  handle.key = view.value().key;
  const Result<HealthReport> after = registry.health(handle);
  REQUIRE_OK(after);
  CHECK(after.value().outcome == HealthOutcome::Stale);
  CHECK(!after.value().healthy());
  const Result<HealthLatch> latch = registry.latch(handle, HealthMetric::TemperatureCelsius, kModuleLane);
  REQUIRE_OK(latch);
  CHECK(latch.value().state == MetricState::Unknown);
}

// Evidence that was already historical at ingestion never becomes current, and
// a restart does not change that.
TRXREG_TEST(health_historical_sample_never_becomes_current) {
  const std::string path = snapshot_path("health-historical.trxr");
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{21});
  {
    Registry registry({}, clock);
    const SourceHandle source = register_source(registry, "probe-agent");
    const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay5");
    publish_threshold(registry, source.authority(), temperature_threshold(60'000'000'000LL));
    ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 45.0,
           kBaseWallNs - 3'600'000'000'000LL);
    const Result<HealthReport> report = registry.health(module);
    REQUIRE_OK(report);
    CHECK(report.value().outcome == HealthOutcome::Stale);
    CHECK(!report.value().healthy());
    REQUIRE_OK(registry.save(path));
  }

  const auto restarted = make_test_clock(kBaseWallNs + 1'000'000'000LL, ClockDomainId{22});
  Registry registry({}, restarted);
  REQUIRE_OK(registry.load(path));
  const Result<IdentityView> view = registry.identity_by_key("chassis0/bay5");
  REQUIRE_OK(view);
  ModuleHandle handle;
  handle.uid = view.value().uid;
  handle.incarnation = view.value().incarnation;
  handle.generation = view.value().generation;
  handle.key = view.value().key;
  const Result<HealthReport> report = registry.health(handle);
  REQUIRE_OK(report);
  CHECK(report.value().outcome == HealthOutcome::Stale);
  CHECK(!report.value().healthy());
}

// Two live sources that disagree beyond the published tolerance produce a
// conflict, not a silent average and not health.
TRXREG_TEST(health_conflicting_sources_are_reported) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle first = register_source(registry, "probe-agent-a");
  const SourceHandle second = register_source(registry, "probe-agent-b");
  const ModuleHandle module = register_module(registry, first.authority(), "chassis0/bay6");
  publish_threshold(registry, first.authority(), temperature_threshold(60'000'000'000LL));

  ingest(registry, first.authority(), module, HealthMetric::TemperatureCelsius, 40.0, clock->wall_now_ns());
  ingest(registry, second.authority(), module, HealthMetric::TemperatureCelsius, 55.0, clock->wall_now_ns());

  const Result<HealthReport> report = registry.health(module);
  REQUIRE_OK(report);
  CHECK(report.value().outcome == HealthOutcome::Conflicting);
  CHECK(!report.value().healthy());
  CHECK(has_issue(report.value(), HealthIssueKind::SourceConflict));

  // Agreement inside the tolerance is not a conflict.
  clock->advance_ns(1'000'000'000LL);
  ingest(registry, second.authority(), module, HealthMetric::TemperatureCelsius, 40.5, clock->wall_now_ns());
  const Result<HealthReport> agreeing = registry.health(module);
  REQUIRE_OK(agreeing);
  CHECK(agreeing.value().outcome == HealthOutcome::Fresh);
  CHECK(agreeing.value().worst == MetricState::Ok);
}

// Hysteresis: escalation and recovery both require sustained evidence.
TRXREG_TEST(health_hysteresis_requires_sustained_evidence) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay7");

  HealthThreshold threshold = temperature_threshold(3'600'000'000'000LL);
  threshold.escalate_after = 3;
  threshold.recover_after = 2;
  publish_threshold(registry, source.authority(), threshold);

  const auto ingest_at = [&](double value, std::int64_t offset_ns) {
    clock->advance_ns(offset_ns);
    ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, value, clock->wall_now_ns());
  };
  const auto state = [&]() -> MetricState {
    const Result<HealthReport> report = registry.health(module);
    if (!report.ok()) {
      return MetricState::Unknown;
    }
    const MetricHealth* row = find_metric(report.value(), HealthMetric::TemperatureCelsius);
    return row != nullptr ? row->state : MetricState::Unknown;
  };

  ingest_at(40.0, 0);
  CHECK(state() == MetricState::Ok);
  ingest_at(72.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Ok);
  ingest_at(73.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Ok);
  ingest_at(74.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Degraded);
  // A value above the entry bound escalates further, still requiring the count.
  ingest_at(85.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Degraded);
  ingest_at(86.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Degraded);
  ingest_at(87.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Critical);
  // Recovery needs two consecutive samples below the exit bound.
  ingest_at(50.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Critical);
  ingest_at(49.0, 1'000'000'000LL);
  CHECK(state() == MetricState::Ok);
}

TRXREG_TEST(health_rejects_implausible_and_inconsistent_input) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay8");

  HealthThreshold inconsistent = temperature_threshold();
  inconsistent.degraded_exit = 90.0;  // exit more severe than entry
  REQUIRE_FAILS(registry.publish_threshold(source.authority(), inconsistent, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  HealthThreshold no_bands = temperature_threshold();
  no_bands.has_degraded = false;
  no_bands.has_critical = false;
  REQUIRE_FAILS(registry.publish_threshold(source.authority(), no_bands, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  HealthThreshold no_window = temperature_threshold();
  no_window.max_age_ns = 0;
  REQUIRE_FAILS(registry.publish_threshold(source.authority(), no_window, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  publish_threshold(registry, source.authority(), temperature_threshold());

  HealthSampleInput out_of_range;
  out_of_range.metric = HealthMetric::TemperatureCelsius;
  out_of_range.value = 5000.0;
  out_of_range.provenance = synthetic_provenance();
  REQUIRE_FAILS(registry.ingest_health(source.authority(), module, out_of_range, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  HealthSampleInput not_a_number;
  not_a_number.metric = HealthMetric::TemperatureCelsius;
  not_a_number.value = std::numeric_limits<double>::quiet_NaN();
  not_a_number.provenance = synthetic_provenance();
  REQUIRE_FAILS(registry.ingest_health(source.authority(), module, not_a_number, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  HealthSampleInput from_the_future;
  from_the_future.metric = HealthMetric::TemperatureCelsius;
  from_the_future.value = 40.0;
  from_the_future.observed_at_wall_ns = clock->wall_now_ns() + 600'000'000'000LL;
  from_the_future.provenance = synthetic_provenance();
  REQUIRE_FAILS(registry.ingest_health(source.authority(), module, from_the_future, MutationPolicy::AutoRetry),
                StatusCode::ClockSkew);

  HealthSampleInput no_provenance;
  no_provenance.metric = HealthMetric::TemperatureCelsius;
  no_provenance.value = 40.0;
  REQUIRE_FAILS(registry.ingest_health(source.authority(), module, no_provenance, MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);

  // Replaying an older observation of the same series, in the same clock
  // domain, is refused rather than accepted out of order.
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 41.0, clock->wall_now_ns(),
         kModuleLane, SamplePresence::Present, 1'000'000ull);
  HealthSampleInput replay;
  replay.metric = HealthMetric::TemperatureCelsius;
  replay.value = 41.0;
  replay.observed_at_wall_ns = clock->wall_now_ns();
  replay.observed_at_monotonic_ns = 1'000'000ull;
  replay.clock_domain = clock->domain();
  replay.provenance = synthetic_provenance();
  REQUIRE_FAILS(registry.ingest_health(source.authority(), module, replay, MutationPolicy::AutoRetry),
                StatusCode::Refused);
}

// Telemetry recorded for one physical module must not describe its replacement.
TRXREG_TEST(health_evidence_is_fenced_by_replacement) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle original = register_module(registry, source.authority(), "chassis0/bay9", RegisterIntent::EnsureCurrent,
                                                "Acme Optics", "AO-400G-SR8", "SN-OLD");
  publish_threshold(registry, source.authority(), temperature_threshold(3'600'000'000'000LL));
  ingest(registry, source.authority(), original, HealthMetric::TemperatureCelsius, 95.0, clock->wall_now_ns());
  const Result<HealthReport> before = registry.health(original);
  REQUIRE_OK(before);
  CHECK(before.value().worst == MetricState::Critical);

  const ModuleHandle replacement = register_module(registry, source.authority(), "chassis0/bay9",
                                                   RegisterIntent::NewIncarnation, "Other Vendor", "OV-100G-LR4",
                                                   "SN-NEW");
  const Result<HealthReport> after = registry.health(replacement);
  REQUIRE_OK(after);
  CHECK(after.value().outcome == HealthOutcome::Fenced);
  CHECK(after.value().worst == MetricState::Fenced);
  CHECK(!after.value().healthy());

  const Result<EvidenceSummary> summary = registry.evidence_summary(replacement);
  REQUIRE_OK(summary);
  CHECK_EQ(summary.value().fenced_samples, std::uint64_t{1});
  CHECK_EQ(summary.value().live_samples, std::uint64_t{0});

  SampleQuery query;
  query.include_superseded = false;
  const Result<std::vector<HealthSample>> samples = registry.samples(replacement, query);
  REQUIRE_OK(samples);
  CHECK(samples.value().empty());
}
