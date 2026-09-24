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

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace {

using namespace trxreg;
using namespace trxreg::test;

std::filesystem::path property_artifact(const std::string& name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "trxreg-tests";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / name;
}

}  // namespace

// Randomized state machine over the public API.
//
// Every step is a legal operation drawn from a seeded generator; after each
// step the registry's invariants are re-checked. A failing seed is printed, so
// the exact sequence that broke an invariant can be reproduced.
TRXREG_TEST(property_random_operation_sequences_hold_invariants) {
  constexpr std::uint64_t kSeed = 0x7a11c0deull;
  note("property state-machine seed=" + std::to_string(kSeed));
  Random random(kSeed);

  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const SourceHandle second = register_source(registry, "probe-agent-2");
  publish_threshold(registry, source.authority(), temperature_threshold(600'000'000'000LL));

  std::vector<ModuleHandle> modules;
  Generation last_generation = registry.generation();
  std::uint64_t committed = 0;
  // Setup committed three mutations (two sources and the threshold); only the
  // steps below are counted against this baseline.
  const std::uint64_t baseline_mutations = registry.stats().mutations;

  for (int step = 0; step < 400; ++step) {
    const std::uint64_t roll = random.below(10);
    bool mutated = false;
    if (roll == 0 || modules.empty()) {
      ModuleRegistration registration;
      const Result<ModuleKey> key = ModuleKey::parse("chassis0/bay" + std::to_string(random.below(6)), "module key");
      REQUIRE_OK(key);
      registration.key = key.value();
      registration.provenance = synthetic_provenance("property-generator");
      registration.policy = MutationPolicy::AutoRetry;
      if (random.boolean()) {
        registration.intent = RegisterIntent::NewIncarnation;
      }
      registration.identity.push_back(
          IdentityFieldValue{IdentityField::SerialNumber, {}, "SN-" + std::to_string(random.below(1000))});
      const Result<ModuleHandle> handle = registry.register_module(registration, source.authority());
      REQUIRE_OK(handle);
      modules.push_back(handle.value());
      mutated = true;
    } else if (roll == 1) {
      const ModuleHandle module = modules[random.below(modules.size())];
      IdentityFieldValue value;
      value.field = IdentityField::VendorSpecific;
      value.subkey = "tag";
      value.value = "v" + std::to_string(random.below(50));
      const Status status = registry.update_identity(source.authority(), module, value,
                                                     synthetic_provenance("property-generator"),
                                                     MutationPolicy::AutoRetry);
      // A handle whose incarnation was replaced is fenced; that is the only
      // refusal this step may produce.
      CHECK(status.ok() || status.code() == StatusCode::Fenced ||
            status.code() == StatusCode::CapacityExceeded);
      mutated = status.ok();
    } else if (roll == 2) {
      const ModuleHandle module = modules[random.below(modules.size())];
      const CapabilityKey keys[] = {CapabilityKey::MediaClass, CapabilityKey::SpeedClasses, CapabilityKey::LaneCount,
                                    CapabilityKey::TemperatureTelemetry};
      const CapabilityKey key = keys[random.below(4)];
      CapabilityValue value = CapabilityValue::count(8);
      if (key == CapabilityKey::MediaClass) {
        value = CapabilityValue::of(MediaClass::MultimodeFiber);
      } else if (key == CapabilityKey::SpeedClasses) {
        value = CapabilityValue::of_speed_classes({SpeedClass::Gb400});
      } else if (key == CapabilityKey::TemperatureTelemetry) {
        value = CapabilityValue::boolean(true);
      }
      const Status status = registry.publish_capability(source.authority(), module, key, {}, std::move(value),
                                                        synthetic_provenance("property-generator"),
                                                        MutationPolicy::AutoRetry);
      if (!status.ok()) {
        // Fencing after a replacement is the expected classified refusal.
        CHECK(status.code() == StatusCode::Fenced);
      }
      mutated = status.ok();
    } else if (roll == 3) {
      const ModuleHandle module = modules[random.below(modules.size())];
      HealthSampleInput sample;
      sample.metric = HealthMetric::TemperatureCelsius;
      sample.presence = SamplePresence::Present;
      sample.value = random.real(0.0, 110.0);
      sample.observed_at_wall_ns = clock->wall_now_ns();
      sample.provenance = synthetic_provenance("property-generator");
      const Status status = registry.ingest_health(source.authority(), module, sample, MutationPolicy::AutoRetry);
      if (!status.ok()) {
        CHECK(status.code() == StatusCode::Fenced || status.code() == StatusCode::Refused ||
              status.code() == StatusCode::InvalidArgument);
      }
      mutated = status.ok();
    } else if (roll == 4) {
      const ModuleHandle module = modules[random.below(modules.size())];
      const Result<SlotKey> slot = SlotKey::parse("chassis0/slot" + std::to_string(random.below(4)), "slot key");
      REQUIRE_OK(slot);
      const Result<AttachmentRecord> attachment =
          registry.attach(source.authority(), module, slot.value(), 0, MutationPolicy::AutoRetry);
      // A fenced incarnation cannot be attached, and a module whose lifecycle
      // forbids attachment is refused: both are classified outcomes.
      CHECK(attachment.ok() || attachment.error().code == StatusCode::Fenced ||
            attachment.error().code == StatusCode::InvalidTransition);
      mutated = attachment.ok();
    } else if (roll == 5) {
      const Result<SlotKey> slot = SlotKey::parse("chassis0/slot" + std::to_string(random.below(4)), "slot key");
      REQUIRE_OK(slot);
      const Status status = registry.detach(source.authority(), slot.value(), MutationPolicy::AutoRetry);
      CHECK(status.ok() || status.code() == StatusCode::NotFound);
      mutated = status.ok();
    } else if (roll == 6) {
      const ModuleHandle module = modules[random.below(modules.size())];
      const LifecycleState targets[] = {LifecycleState::Active, LifecycleState::Degraded,
                                        LifecycleState::Quarantined, LifecycleState::Retired,
                                        LifecycleState::Removed};
      const LifecycleState target = targets[random.below(5)];
      const Result<LifecycleEvent> transition = registry.transition(source.authority(), module, target,
                                                                  "property step", MutationPolicy::AutoRetry);
      // Either the transition is legal, or it is refused as illegal; nothing else.
      CHECK(transition.ok() || transition.error().code == StatusCode::InvalidTransition ||
            transition.error().code == StatusCode::Fenced);
      mutated = transition.ok();
    } else if (roll == 7) {
      const ModuleHandle module = modules[random.below(modules.size())];
      const Result<LifecycleEvent> event = registry.reconcile_lifecycle(source.authority(), module,
                                                                       MutationPolicy::AutoRetry);
      CHECK(event.ok() || event.error().code == StatusCode::Fenced);
      mutated = event.ok();
    } else if (roll == 8) {
      const ModuleHandle module = modules[random.below(modules.size())];
      // A second source may disagree; the registry must keep both claims.
      IdentityFieldValue value;
      value.field = IdentityField::SerialNumber;
      value.value = "SN-OTHER-" + std::to_string(random.below(1000));
      const Status status = registry.update_identity(second.authority(), module, value,
                                                     synthetic_provenance("property-generator-2"),
                                                     MutationPolicy::AutoRetry);
      CHECK(status.ok() || status.code() == StatusCode::Fenced);
      mutated = status.ok();
    } else {
      clock->advance_ns(static_cast<std::int64_t>(random.range(0, 1'000'000'000)));
    }

    const Generation current = registry.generation();
    CHECK(current.value() >= last_generation.value());
    if (mutated) {
      CHECK_EQ(current.value(), last_generation.value() + 1);
      ++committed;
      last_generation = current;
    } else {
      CHECK_EQ(current.value(), last_generation.value());
    }

    // Invariant: every module the registry reports can be queried, and the
    // digest of its identity is stable while nothing mutates.
    const std::vector<ModuleHandle> reported = registry.modules();
    for (const ModuleHandle& handle : reported) {
      const Result<IdentityView> view = registry.identity(handle);
      CHECK(view.ok());
      if (view.ok()) {
        CHECK_EQ(view.value().uid, handle.uid);
        CHECK_EQ(view.value().incarnation, handle.incarnation);
        CHECK_EQ(view.value().generation, current);
      }
    }
    const Digest digest = registry.state_digest();
    CHECK_EQ(registry.state_digest().to_hex(), digest.to_hex());
  }

  CHECK_EQ(registry.stats().mutations, baseline_mutations + committed);
  CHECK(registry.stats().modules >= 1);

  // A save/load cycle at the end of the random sequence preserves every module's
  // identity digest, which is the content-addressed part of the state.
  const std::filesystem::path path = property_artifact("property-final.trxr");
  std::vector<std::string> digests_before;
  for (const ModuleHandle& handle : registry.modules()) {
    const Result<IdentityView> view = registry.identity(handle);
    REQUIRE_OK(view);
    digests_before.push_back(view.value().digest.to_hex());
  }
  REQUIRE_OK(registry.save(path.string()));

  Registry reloaded({}, make_test_clock());
  const Result<LoadReport> report = reloaded.load(path.string());
  REQUIRE_OK(report);
  CHECK_EQ(report.value().modules, std::uint64_t{registry.modules().size()});
  std::vector<std::string> digests_after;
  for (const ModuleHandle& handle : reloaded.modules()) {
    const Result<IdentityView> view = reloaded.identity(handle);
    REQUIRE_OK(view);
    digests_after.push_back(view.value().digest.to_hex());
  }
  std::sort(digests_before.begin(), digests_before.end());
  std::sort(digests_after.begin(), digests_after.end());
  CHECK(digests_before == digests_after);
}

// The consensus over independent sources does not depend on the order in which
// their claims arrived.
TRXREG_TEST(property_consensus_is_order_independent) {
  constexpr std::uint64_t kSeed = 0x0d3e7ull;
  note("property order-independence seed=" + std::to_string(kSeed));
  Random random(kSeed);

  for (int trial = 0; trial < 40; ++trial) {
    const std::uint64_t seed = random.next();
    Random case_random(seed);

    const int source_count = static_cast<int>(case_random.range(2, 5));
    std::vector<std::string> values;
    for (int i = 0; i < source_count; ++i) {
      // Sources agree or disagree deterministically per trial.
      values.push_back("value-" + std::to_string(case_random.below(case_random.boolean() ? 2 : source_count)));
    }

    const auto build = [&](bool reversed) {
      Registry registry;
      std::vector<SourceHandle> sources;
      for (int i = 0; i < source_count; ++i) {
        sources.push_back(register_source(registry, "source-" + std::to_string(i)));
      }
      const ModuleHandle module = register_module(registry, sources.front().authority(), "chassis0/order");
      std::vector<int> order;
      for (int i = 0; i < source_count; ++i) {
        order.push_back(i);
      }
      if (reversed) {
        std::reverse(order.begin(), order.end());
      }
      for (const int index : order) {
        const Status status = registry.update_identity(
            sources[static_cast<std::size_t>(index)].authority(), module,
            IdentityFieldValue{IdentityField::VendorSpecific, "order", values[static_cast<std::size_t>(index)]},
            synthetic_provenance("source-" + std::to_string(index)), MutationPolicy::AutoRetry);
        TRXREG_FIXTURE_STATUS(status);
      }
      const IdentityView view = TRXREG_FIXTURE(registry.identity(module));
      return std::make_pair(view.find(IdentityField::VendorSpecific, "order")->outcome,
                            view.find(IdentityField::VendorSpecific, "order")->has_value);
    };

    const auto forward = build(false);
    const auto backward = build(true);
    if (forward.first != backward.first || forward.second != backward.second) {
      report_failure(__FILE__, __LINE__, "case seed=" + std::to_string(seed) + " forward outcome " +
                                            std::to_string(static_cast<int>(forward.first)) + " backward " +
                                            std::to_string(static_cast<int>(backward.first)));
    }
    // The observed outcome must be one of the modelled consensus outcomes and
    // must never claim a value while reporting a conflict.
    CHECK(forward.first != ConsensusOutcome::Unknown);
    if (forward.first == ConsensusOutcome::Conflicting) {
      CHECK(!forward.second);
    }
  }
}

// Independently built registries that receive the same logical operations
// produce byte-identical canonical state.
TRXREG_TEST(property_identical_operations_produce_identical_state) {
  constexpr std::uint64_t kSeed = 0x5a3e5a7eull;
  note("property determinism seed=" + std::to_string(kSeed));
  Random random(kSeed);

  for (int trial = 0; trial < 20; ++trial) {
    const std::uint64_t seed = random.next();
    Random case_random(seed);

    const auto build = [&](std::uint64_t local_seed) {
      Random local(local_seed);
      Registry registry({}, make_test_clock(kBaseWallNs, ClockDomainId{77}));
      const SourceHandle source = register_source(registry, "determinism-agent");
      const int module_count = static_cast<int>(local.range(1, 4));
      for (int m = 0; m < module_count; ++m) {
        const ModuleHandle module =
            register_module(registry, source.authority(), "chassis0/det" + std::to_string(m));
        publish_capability(registry, source.authority(), module, CapabilityKey::LaneCount,
                           CapabilityValue::count(local.range(1, 16)));
        ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius,
               local.real(20.0, 30.0), kBaseWallNs);
      }
      return registry.state_digest().to_hex();
    };

    const std::string first = build(seed);
    const std::string second = build(seed);
    if (first != second) {
      report_failure(__FILE__, __LINE__, "case seed=" + std::to_string(seed) + " produced different state digests");
    }
  }
}
