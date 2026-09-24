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

// Internal registry state. Not installed: nothing here is part of the public
// API contract.
//
// Concurrency model: Impl holds one mutex and one immutable state snapshot. A
// mutation copies the state, applies the change, and publishes the copy. Readers
// only hold the mutex while copying the shared pointer, so a callback can never
// run under the lock and a reader can never observe a torn state. Because the
// whole mutation happens under the lock, the fence check and the commit are
// atomic: exactly one of several racing publishers presenting the same expected
// generation commits.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/snapshot.hpp"

namespace trxreg {

/// Latched classification of one metric series.
struct HealthLatchRecord {
  HealthMetric metric{HealthMetric::Unknown};
  std::uint16_t lane{kModuleLane};
  HealthLatch latch{};

  friend bool operator==(const HealthLatchRecord& lhs, const HealthLatchRecord& rhs) noexcept = default;
};

struct ThresholdRecord {
  HealthThreshold threshold{};
  Generation generation{};
  Sequence sequence{};
  bool live{true};
};

struct ModuleRecord {
  ModuleKey key{};
  ModuleUid uid{};
  IncarnationId incarnation{1};
  LifecycleState state{LifecycleState::Discovered};
  Generation state_generation{};
  Sequence state_sequence{};
  WallNs state_wall_ns{0};
  Generation created_generation{};
  Sequence created_sequence{};
  WallNs created_wall_ns{0};
  /// Generation at which the previous incarnation of this key was replaced.
  Generation fenced_generation{};
  std::uint32_t incarnation_count{1};
  std::vector<IdentityClaim> claims;
  std::vector<CapabilityDeclaration> declarations;
  std::vector<HealthSample> samples;
  std::vector<LifecycleEvent> lifecycle;
  std::vector<HealthLatchRecord> latches;

  /// Per-series count of samples; kept in sync so that trimming is O(1) per
  /// series instead of a scan.
  std::map<std::pair<std::uint8_t, std::uint16_t>, std::uint32_t> series_counts;

  friend bool operator==(const ModuleRecord& lhs, const ModuleRecord& rhs) noexcept = default;
};

struct PortRecord {
  PortKey key{};
  Generation first_generation{};
  Sequence sequence{};
  WallNs first_wall_ns{0};
  std::vector<CapabilityDeclaration> declarations;
};

struct SourceRecord {
  SourceId id{};
  std::string name;
  SourceEpoch epoch{};
  SourceDescriptor descriptor{};
  Generation generation{};
  Sequence sequence{};
  WallNs registered_wall_ns{0};
};

struct State {
  Generation generation{};
  std::uint32_t registry_incarnation{1};
  std::uint64_t next_module_uid{1};
  std::uint64_t next_rule_id{1};
  std::uint64_t next_source_id{1};
  std::uint64_t next_sequence{1};
  std::map<std::uint32_t, SourceRecord> sources;
  std::map<std::string, std::uint32_t> source_id_by_name;
  std::map<std::uint64_t, ModuleRecord> modules;
  std::map<std::string, std::uint64_t> module_uid_by_key;
  std::map<std::string, PortRecord> ports;
  std::map<std::string, AttachmentRecord> attachments;
  std::vector<ThresholdRecord> thresholds;
  std::map<std::uint32_t, CompatRuleRecord> rules;
  std::uint64_t mutations{0};
  std::uint64_t dropped_samples{0};
  std::uint64_t conflicts_observed{0};

  friend bool operator==(const State& lhs, const State& rhs) noexcept = default;
};

using StatePtr = std::shared_ptr<const State>;

/// Resolve the live source epoch for a source id; returns false when the source
/// is unknown.
bool source_is_live(const State& state, SourceId source, SourceEpoch epoch);

/// True when the module record currently holds this incarnation.
bool incarnation_is_current(const ModuleRecord& record, IncarnationId incarnation);

/// Copy the claims of one incarnation and mark live/superseded flags.
std::vector<IdentityClaim> live_claims(const State& state, const ModuleRecord& record, IncarnationId incarnation);

/// Copy the capability declarations of one incarnation and mark live flags.
std::vector<CapabilityDeclaration> live_declarations(const State& state, const ModuleRecord& record,
                                                     IncarnationId incarnation);

/// Copy the capability declarations of a port and mark live flags.
std::vector<CapabilityDeclaration> live_port_declarations(const State& state, const PortRecord& record);

/// Copy the samples of one incarnation and mark live flags.
std::vector<HealthSample> live_samples(const State& state, const ModuleRecord& record, IncarnationId incarnation);

std::uint64_t next_sequence(State& state);

/// Canonical digest of the entire state (used by stats and by tests that prove
/// insertion-order independence).
Digest compute_state_digest(const State& state);

/// Health thresholds (policy) that are currently live.
std::vector<HealthThreshold> live_thresholds(const State& state);

/// Evidence-gated health report for one module incarnation.
HealthReport build_health_report(const State& state, const ModuleRecord& record, const RegistryConfig& config,
                                 const ClockPtr& clock);

/// Persistence entry point used by autosave; defined in snapshot.cpp.
Status save_snapshot_impl(const RegistryImpl& impl, const std::string& path, const SaveOptions& options);

struct RegistryAccess {
  static RegistryImpl& impl(Registry& registry);
  static const RegistryImpl& impl(const Registry& registry);
};

struct RegistryImpl {
  RegistryConfig config{};
  ClockPtr clock{};
  mutable std::mutex mutex{};
  StatePtr state{};

  mutable std::mutex autosave_mutex{};
  std::string autosave_path{};
  SaveOptions autosave_options{};
  bool autosave_enabled{false};
  Generation autosave_generation{};
  std::atomic<std::uint64_t> refusals{0};
  std::atomic<std::uint64_t> queries{0};

  RegistryImpl(RegistryConfig config_in, ClockPtr clock_in);

  [[nodiscard]] StatePtr current() const;
  [[nodiscard]] Generation generation() const;

  /// Run one mutation under the lock. `body` receives a mutable copy of the
  /// state, the generation the change will be published under, and a fresh
  /// sequence number. The copy is published only when the body returns Ok.
  template <class Body>
  Status mutate(bool require_generation, Generation expected, Body&& body);

  void maybe_autosave();
};

template <class Body>
Status RegistryImpl::mutate(bool require_generation, Generation expected, Body&& body) {
  {
    std::unique_lock<std::mutex> lock(mutex);
    if (require_generation && expected.valid() && expected != state->generation) {
      refusals.fetch_add(1, std::memory_order_relaxed);
      return Status(StatusCode::StaleGeneration,
                    "the registry moved on: expected generation " + std::to_string(expected.value()) +
                        " but the current generation is " + std::to_string(state->generation.value()));
    }
    auto next = std::make_shared<State>(*state);
    const Generation next_generation{next->generation.value() + 1};
    const Sequence sequence{next_sequence(*next)};
    const Status status = body(*next, next_generation, sequence);
    if (!status.ok()) {
      refusals.fetch_add(1, std::memory_order_relaxed);
      return status;
    }
    next->generation = next_generation;
    next->mutations += 1;
    state = std::move(next);
  }
  maybe_autosave();
  return ok_status();
}

}  // namespace trxreg
