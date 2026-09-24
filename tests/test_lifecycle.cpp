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

namespace {

using namespace trxreg;
using namespace trxreg::test;

}  // namespace

TRXREG_TEST(lifecycle_registration_starts_registered) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay1");
  const Result<LifecycleState> state = registry.lifecycle_state(module);
  REQUIRE_OK(state);
  CHECK(state.value() == LifecycleState::Registered);

  // Registered cannot jump straight to Active: the module must be attached.
  REQUIRE_FAILS(registry.transition(source.authority(), module, LifecycleState::Active, "skip", MutationPolicy::AutoRetry),
                StatusCode::InvalidTransition);

  const Result<std::vector<LifecycleEvent>> history = registry.lifecycle_history(module);
  REQUIRE_OK(history);
  REQUIRE(history.value().size() >= 2);
  CHECK(history.value().front().from == LifecycleState::Discovered);
  CHECK(history.value().front().to == LifecycleState::Discovered);
  CHECK(history.value().back().to == LifecycleState::Registered);
  for (const LifecycleEvent& event : history.value()) {
    CHECK_EQ(event.incarnation, module.incarnation);
  }
}

TRXREG_TEST(lifecycle_attach_detach_and_terminal_states) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay2");
  const Result<SlotKey> slot = SlotKey::parse("chassis0/slot2", "slot key");
  REQUIRE_OK(slot);

  const Result<AttachmentRecord> attached = registry.attach(source.authority(), module, slot.value(), 0,
                                                           MutationPolicy::AutoRetry);
  REQUIRE_OK(attached);
  CHECK_EQ(attached.value().uid, module.uid);
  CHECK(attached.value().live);

  const Result<LifecycleState> after_attach = registry.lifecycle_state(module);
  REQUIRE_OK(after_attach);
  CHECK(after_attach.value() == LifecycleState::Attached);

  // Re-attaching the same incarnation is idempotent rather than an error.
  const Result<AttachmentRecord> again = registry.attach(source.authority(), module, slot.value(), 0,
                                                        MutationPolicy::AutoRetry);
  REQUIRE_OK(again);
  CHECK(again.value().live);

  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Active, "link up",
                                 MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Degraded, "fec corrected",
                                 MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Active, "recovered",
                                 MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Quarantined, "operator action",
                                 MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Attached, "quarantine lifted",
                                 MutationPolicy::AutoRetry));

  // Detaching a physically attached module moves it to Removed.
  REQUIRE_OK(registry.detach(source.authority(), slot.value(), MutationPolicy::AutoRetry));
  const Result<LifecycleState> removed = registry.lifecycle_state(module);
  REQUIRE_OK(removed);
  CHECK(removed.value() == LifecycleState::Removed);
  REQUIRE_FAILS(registry.attachment_of_slot(slot.value()), StatusCode::NotFound);
  REQUIRE_FAILS(registry.detach(source.authority(), slot.value(), MutationPolicy::AutoRetry), StatusCode::NotFound);

  REQUIRE_OK(registry.transition(source.authority(), module, LifecycleState::Retired, "end of life",
                                 MutationPolicy::AutoRetry));
  CHECK(lifecycle_state_is_terminal(LifecycleState::Retired));
  REQUIRE_FAILS(registry.transition(source.authority(), module, LifecycleState::Registered, "resurrect",
                                    MutationPolicy::AutoRetry),
                StatusCode::InvalidTransition);
}

TRXREG_TEST(lifecycle_replacement_records_replaced_event) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle original = register_module(registry, source.authority(), "chassis0/bay3", RegisterIntent::EnsureCurrent,
                                                "Acme Optics", "AO-400G-SR8", "SN-OLD");
  const Result<SlotKey> slot = SlotKey::parse("chassis0/slot3", "slot key");
  REQUIRE_OK(slot);
  REQUIRE_OK(registry.attach(source.authority(), original, slot.value(), 0, MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.transition(source.authority(), original, LifecycleState::Active, "link up",
                                 MutationPolicy::AutoRetry));

  const ModuleHandle replacement = register_module(registry, source.authority(), "chassis0/bay3",
                                                   RegisterIntent::NewIncarnation, "Other Vendor", "OV-100G-LR4",
                                                   "SN-NEW");

  const Result<std::vector<LifecycleEvent>> old_history = registry.lifecycle_history(original);
  REQUIRE_OK(old_history);
  bool saw_replaced = false;
  for (const LifecycleEvent& event : old_history.value()) {
    if (event.to == LifecycleState::Replaced) {
      saw_replaced = true;
      CHECK(event.from == LifecycleState::Active);
    }
  }
  CHECK(saw_replaced);

  // The replacement inherits the slot, and the previous attachment is fenced.
  const Result<AttachmentRecord> slot_state = registry.attachment_of_slot(slot.value());
  REQUIRE_FAILS(slot_state, StatusCode::NotFound);
  REQUIRE_OK(registry.attach(source.authority(), replacement, slot.value(), 0, MutationPolicy::AutoRetry));
  const Result<AttachmentRecord> rebound = registry.attachment_of_slot(slot.value());
  REQUIRE_OK(rebound);
  CHECK_EQ(rebound.value().incarnation, replacement.incarnation);
  CHECK_EQ(rebound.value().uid, replacement.uid);
}

TRXREG_TEST(lifecycle_reconcile_uses_health_evidence) {
  const auto clock = make_test_clock();
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay4");
  const Result<SlotKey> slot = SlotKey::parse("chassis0/slot4", "slot key");
  REQUIRE_OK(slot);
  REQUIRE_OK(registry.attach(source.authority(), module, slot.value(), 0, MutationPolicy::AutoRetry));

  // Without any evidence the registry refuses to invent a lifecycle change.
  const Result<LifecycleEvent> before_evidence = registry.reconcile_lifecycle(source.authority(), module,
                                                                             MutationPolicy::AutoRetry);
  REQUIRE_OK(before_evidence);
  CHECK(before_evidence.value().from == before_evidence.value().to);
  CHECK(before_evidence.value().reason == "no transition required");

  publish_threshold(registry, source.authority(), temperature_threshold());

  // Fresh, nominal evidence moves an attached module to Active.
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 40.0, clock->wall_now_ns());
  const Result<HealthReport> report = registry.health(module);
  REQUIRE_OK(report);
  CHECK(report.value().outcome == HealthOutcome::Fresh);
  CHECK(report.value().worst == MetricState::Ok);
  CHECK(report.value().healthy());
  const Result<LifecycleEvent> activated = registry.reconcile_lifecycle(source.authority(), module,
                                                                       MutationPolicy::AutoRetry);
  REQUIRE_OK(activated);
  CHECK(activated.value().from == LifecycleState::Attached);
  CHECK(activated.value().to == LifecycleState::Active);

  // A critical measurement degrades it.
  clock->advance_ns(1'000'000'000LL);
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 85.0, clock->wall_now_ns());
  const Result<LifecycleEvent> degraded = registry.reconcile_lifecycle(source.authority(), module,
                                                                      MutationPolicy::AutoRetry);
  REQUIRE_OK(degraded);
  CHECK(degraded.value().to == LifecycleState::Degraded);

  // Stale evidence cannot restore it: the measurement ages out of its window.
  clock->advance_ns(120'000'000'000LL);
  const Result<LifecycleEvent> stale = registry.reconcile_lifecycle(source.authority(), module,
                                                                   MutationPolicy::AutoRetry);
  REQUIRE_OK(stale);
  CHECK(stale.value().to == LifecycleState::Degraded);

  // Fresh nominal evidence does restore it.
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 41.0, clock->wall_now_ns());
  const Result<LifecycleEvent> recovered = registry.reconcile_lifecycle(source.authority(), module,
                                                                       MutationPolicy::AutoRetry);
  REQUIRE_OK(recovered);
  CHECK(recovered.value().to == LifecycleState::Active);
}
