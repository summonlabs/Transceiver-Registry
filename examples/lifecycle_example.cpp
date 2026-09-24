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

// Lifecycle walkthrough of the Transceiver Registry.
//
// One module is driven through the whole evidence-backed life of a physical
// part: registration, capability publication, attachment to a slot, a published
// health threshold, telemetry ingestion, a health-driven lifecycle
// reconciliation, and finally a physical replacement that fences the previous
// incarnation while keeping its history inspectable.
//
// The run is deterministic: every timestamp comes from a ManualClock, so the
// freshness windows printed below are explicit values rather than wall-clock
// accidents. Nothing here talks to hardware - the runtime never does - and every
// record carries SYNTHETIC provenance so synthetic evidence can never be
// mistaken for a real device.

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/health.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/lifecycle.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/taxonomy.hpp"

namespace {

using namespace trxreg;

/// 2026-01-01T00:00:00Z. A fixed origin keeps the printed timeline reproducible.
constexpr WallNs kStartWallNs = 1'767'225'600'000'000'000LL;
constexpr ClockDomainId kClockDomain{7};

/// Freshness bound published for the temperature series: 60 seconds.
constexpr WallNs kTemperatureMaxAgeNs = 60'000'000'000LL;
constexpr WallNs kSecondNs = 1'000'000'000LL;

void print(std::string_view text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
}

std::string quoted(std::string_view text) { return "'" + std::string(text) + "'"; }

std::string number(double value) {
  char buffer[48];
  const int written = std::snprintf(buffer, sizeof(buffer), "%.3f", value);
  return written > 0 ? std::string(buffer, static_cast<std::size_t>(written)) : std::string("nan");
}

/// Every failure path prints the classified status and exits 1: a silently
/// wrong example is worse than a failing one.
int fail(std::string_view step, const Error& error) {
  std::string text = "lifecycle_example: ";
  text += step;
  text += " failed: ";
  text += error.message;
  text += " [";
  text += to_string(error.code);
  text += "]";
  text += '\n';
  std::fwrite(text.data(), 1, text.size(), stderr);
  return 1;
}

/// The runtime publishes readable names for the taxonomy enums; HealthIssueKind
/// is a report detail without a name table, so the example names it locally.
std::string_view issue_kind_name(HealthIssueKind kind) {
  switch (kind) {
    case HealthIssueKind::Missing:
      return "missing";
    case HealthIssueKind::Stale:
      return "stale";
    case HealthIssueKind::Fenced:
      return "fenced";
    case HealthIssueKind::SourceConflict:
      return "source_conflict";
    case HealthIssueKind::NoThreshold:
      return "no_threshold";
    case HealthIssueKind::NotAvailable:
      return "not_available";
    case HealthIssueKind::ReadError:
      return "read_error";
    case HealthIssueKind::NotSupported:
      return "not_supported";
    case HealthIssueKind::FutureTimestamp:
      return "future_timestamp";
    case HealthIssueKind::OutOfRange:
      return "out_of_range";
    case HealthIssueKind::SupersededThreshold:
      return "superseded_threshold";
  }
  return "unknown";
}

Provenance synthetic(std::string origin, std::string method) {
  Provenance provenance;
  provenance.kind = EvidenceKind::Synthetic;
  provenance.origin = std::move(origin);
  provenance.method = std::move(method);
  return provenance;
}

IdentityFieldValue identity_value(IdentityField field, std::string value) {
  IdentityFieldValue out;
  out.field = field;
  out.value = std::move(value);
  return out;
}

/// Publish one capability for a module. Every mutation here uses AutoRetry: the
/// handles minted earlier carry earlier generations, and an independent publisher
/// must not have to re-read the registry between two publications.
Status publish(Registry& registry, const AuthorityToken& authority, const ModuleHandle& module, CapabilityKey key,
               CapabilityValue value) {
  return registry.publish_capability(authority, module, key, std::string{}, std::move(value),
                                     synthetic("probe-agent", "declared"), MutationPolicy::AutoRetry);
}

Status ingest(Registry& registry, const AuthorityToken& authority, const ModuleHandle& module, HealthMetric metric,
              double value, WallNs observed_at_wall_ns) {
  HealthSampleInput sample;
  sample.metric = metric;
  sample.lane = kModuleLane;
  sample.presence = SamplePresence::Present;
  sample.value = value;
  sample.observed_at_wall_ns = observed_at_wall_ns;
  sample.provenance = synthetic("ddm-poll", "read");
  return registry.ingest_health(authority, module, sample, MutationPolicy::AutoRetry);
}

void print_metric(const MetricHealth& metric) {
  std::string text = "      metric ";
  text += to_string(metric.metric);
  text += " lane=";
  text += metric.lane == kModuleLane ? std::string("module") : std::to_string(metric.lane);
  text += " state=";
  text += to_string(metric.state);
  if (metric.has_value) {
    text += " value=";
    text += number(metric.value);
  }
  text += " age_ns=";
  text += std::to_string(metric.age_ns);
  text += " samples=";
  text += std::to_string(metric.sample_count);
  text += " fresh=";
  text += std::to_string(metric.fresh_count);
  text += " stale=";
  text += std::to_string(metric.stale_count);
  text += " fenced=";
  text += std::to_string(metric.fenced_count);
  text += " sources=";
  text += std::to_string(metric.source_count);
  if (!metric.reason.empty()) {
    text += " reason=";
    text += quoted(metric.reason);
  }
  print(text);
}

void print_report(const HealthReport& report) {
  print("      outcome=" + std::string(to_string(report.outcome)) + " worst=" + std::string(to_string(report.worst)) +
        " generation=" + std::to_string(report.generation.value()) +
        " evaluated_at_wall_ns=" + std::to_string(report.evaluated_at_wall_ns));
  for (const MetricHealth& metric : report.metrics) {
    print_metric(metric);
  }
  for (const HealthIssue& issue : report.issues) {
    print("      issue " + std::string(issue_kind_name(issue.kind)) + " " + std::string(to_string(issue.metric)) +
          " lane=" + (issue.lane == kModuleLane ? std::string("module") : std::to_string(issue.lane)) + ": " +
          issue.detail);
  }
  if (report.issues.empty()) {
    print("      issue none");
  }
}

void print_identity(const IdentityView& view) {
  print("      uid=" + std::to_string(view.uid.value()) + " incarnation=" + std::to_string(view.incarnation.value()) +
        " lifecycle=" + std::string(to_string(view.lifecycle)) +
        " conflicts=" + std::to_string(view.conflicting_fields) +
        " superseded_fields=" + std::to_string(view.superseded_fields) +
        " digest=" + view.digest.to_hex());
  for (const FieldConsensus& field : view.fields) {
    std::string text = "      field ";
    text += to_string(field.field);
    if (!field.subkey.empty()) {
      text += "[";
      text += field.subkey;
      text += "]";
    }
    text += " outcome=";
    text += to_string(field.outcome);
    text += " value=";
    text += quoted(field.value);
    text += " live_claims=";
    text += std::to_string(field.claims.size());
    text += " superseded_claims=";
    text += std::to_string(field.superseded_claims.size());
    print(text);
  }
}

int run() {
  const auto clock = std::make_shared<ManualClock>(kStartWallNs, kClockDomain);
  Registry registry{RegistryConfig{}, clock};

  print("Transceiver Registry - lifecycle example");
  print("clock: ManualClock domain=" + std::to_string(kClockDomain.value()) +
        " start_wall_ns=" + std::to_string(kStartWallNs) + " (2026-01-01T00:00:00Z)");

  // -- 1. the evidence source ----------------------------------------------
  SourceDescriptor source_descriptor;
  source_descriptor.name = "probe-agent-1";
  source_descriptor.description = "reads module EEPROM pages and DDM telemetry";
  source_descriptor.declared_kind = EvidenceKind::Synthetic;
  source_descriptor.instance_id = "probe-agent-1/run-1";

  const Result<SourceHandle> source_result = registry.register_source(source_descriptor);
  if (!source_result.ok()) {
    return fail("register_source", source_result.error());
  }
  const SourceHandle source = source_result.value();
  const AuthorityToken authority = source.authority();
  print("[1] source registered: name='probe-agent-1' id=" + std::to_string(source.id.value()) +
        " epoch=" + std::to_string(source.epoch.value()) +
        " generation=" + std::to_string(source.generation.value()));

  // -- 2. the module and its identity claims --------------------------------
  const Result<ModuleKey> module_key = ModuleKey::parse("chassis0/bay2/module0", "module key");
  if (!module_key.ok()) {
    return fail("ModuleKey::parse", module_key.error());
  }

  ModuleRegistration registration;
  registration.key = module_key.value();
  registration.intent = RegisterIntent::EnsureCurrent;
  registration.identity.push_back(identity_value(IdentityField::Vendor, "Acme Optics"));
  registration.identity.push_back(identity_value(IdentityField::PartNumber, "AO-400G-SR8"));
  registration.identity.push_back(identity_value(IdentityField::SerialNumber, "SN-0001"));
  registration.identity.push_back(identity_value(IdentityField::FirmwareVersion, "2.3.7"));
  registration.provenance = synthetic("eeprom-page0", "decoded");
  registration.policy = MutationPolicy::AutoRetry;

  const Result<ModuleHandle> module_result = registry.register_module(registration, authority);
  if (!module_result.ok()) {
    return fail("register_module", module_result.error());
  }
  const ModuleHandle module = module_result.value();
  print("[2] module registered: key='chassis0/bay2/module0' uid=" + std::to_string(module.uid.value()) +
        " incarnation=" + std::to_string(module.incarnation.value()) +
        " generation=" + std::to_string(module.generation.value()));

  const Result<IdentityView> identity_result = registry.identity(module);
  if (!identity_result.ok()) {
    return fail("identity", identity_result.error());
  }
  print_identity(identity_result.value());

  // -- 3. capabilities ------------------------------------------------------
  std::vector<std::pair<CapabilityKey, CapabilityValue>> capabilities;
  capabilities.emplace_back(CapabilityKey::ModuleFamily, CapabilityValue::of(ModuleFamily::OpticalTransceiver));
  capabilities.emplace_back(CapabilityKey::MediaClass, CapabilityValue::of(MediaClass::MultimodeFiber));
  capabilities.emplace_back(CapabilityKey::ConnectorClass, CapabilityValue::of(ConnectorClass::Mpo16));
  capabilities.emplace_back(CapabilityKey::LaneCount, CapabilityValue::count(8));
  capabilities.emplace_back(CapabilityKey::SpeedClasses,
                            CapabilityValue::of_speed_classes({SpeedClass::Gb400}));
  capabilities.emplace_back(CapabilityKey::FecModes,
                            CapabilityValue::of_fec_modes({FecClass::RsFec544, FecClass::None}));
  capabilities.emplace_back(CapabilityKey::DigitalDiagnosticMonitoring, CapabilityValue::boolean(true));
  capabilities.emplace_back(CapabilityKey::TemperatureTelemetry, CapabilityValue::boolean(true));
  capabilities.emplace_back(CapabilityKey::VoltageTelemetry, CapabilityValue::boolean(true));
  capabilities.emplace_back(CapabilityKey::RxPowerTelemetry, CapabilityValue::boolean(true));

  for (const auto& entry : capabilities) {
    const Status status = publish(registry, authority, module, entry.first, entry.second);
    if (!status.ok()) {
      return fail(std::string("publish_capability(") + std::string(to_string(entry.first)) + ")", status.error());
    }
  }
  print("[3] published " + std::to_string(capabilities.size()) + " capability declarations");

  const Result<CapabilityView> capability_result = registry.capabilities(module);
  if (!capability_result.ok()) {
    return fail("capabilities", capability_result.error());
  }
  for (const CapabilityConsensus& attribute : capability_result.value().attributes) {
    print("      " + std::string(to_string(attribute.key)) + " = " + attribute.value.describe(attribute.key) +
          " [" + std::string(to_string(attribute.outcome)) + "]");
  }

  // -- 4. attach the module to its slot -------------------------------------
  const Result<SlotKey> slot_key = SlotKey::parse("chassis0/bay2", "slot key");
  if (!slot_key.ok()) {
    return fail("SlotKey::parse", slot_key.error());
  }
  const Result<AttachmentRecord> attach_result =
      registry.attach(authority, module, slot_key.value(), 1, MutationPolicy::AutoRetry);
  if (!attach_result.ok()) {
    return fail("attach", attach_result.error());
  }
  print("[4] attached uid=" + std::to_string(attach_result.value().uid.value()) + "/incarnation=" +
        std::to_string(attach_result.value().incarnation.value()) + " to slot='chassis0/bay2' port_index=1");

  const Result<LifecycleEvent> active_result = registry.transition(authority, module, LifecycleState::Active,
                                                                  "module is attached and answering", MutationPolicy::AutoRetry);
  if (!active_result.ok()) {
    return fail("transition(Active)", active_result.error());
  }
  print("      lifecycle: " + std::string(to_string(active_result.value().from)) + " -> " +
        std::string(to_string(active_result.value().to)) + " (" + active_result.value().reason + ")");

  // -- 5. publish the health policy -----------------------------------------
  HealthThreshold threshold;
  threshold.metric = HealthMetric::TemperatureCelsius;
  threshold.lane = kModuleLane;
  threshold.direction = ThresholdDirection::Above;
  threshold.has_degraded = true;
  threshold.degraded_enter = 70.0;
  threshold.degraded_exit = 65.0;
  threshold.has_critical = true;
  threshold.critical_enter = 80.0;
  threshold.critical_exit = 75.0;
  threshold.escalate_after = 1;
  threshold.recover_after = 1;
  threshold.max_age_ns = kTemperatureMaxAgeNs;
  threshold.disagreement_tolerance = 1.0;
  threshold.provenance = synthetic("operator-policy", "declared");

  const Status threshold_status = registry.publish_threshold(authority, threshold, MutationPolicy::AutoRetry);
  if (!threshold_status.ok()) {
    return fail("publish_threshold", threshold_status.error());
  }
  print("[5] threshold published: temperature_celsius degraded_enter=70.000 critical_enter=80.000 max_age_ns=" +
        std::to_string(kTemperatureMaxAgeNs) + " (60 s)");

  // -- 6. fresh telemetry ----------------------------------------------------
  const WallNs first_sample_ns = clock->wall_now_ns();
  const Status first_status = ingest(registry, authority, module, HealthMetric::TemperatureCelsius, 62.5, first_sample_ns);
  if (!first_status.ok()) {
    return fail("ingest_health(temperature, 62.5)", first_status.error());
  }
  clock->advance_ns(kSecondNs);
  const WallNs second_sample_ns = clock->wall_now_ns();
  struct PlannedSample {
    HealthMetric metric;
    double value;
  };
  const PlannedSample planned[] = {
      {HealthMetric::TemperatureCelsius, 71.5},
      {HealthMetric::SupplyVoltageVolts, 3.31},
      {HealthMetric::RxPowerDbm, -2.4},
  };
  for (const PlannedSample& sample : planned) {
    const Status status = ingest(registry, authority, module, sample.metric, sample.value, second_sample_ns);
    if (!status.ok()) {
      return fail(std::string("ingest_health(") + std::string(to_string(sample.metric)) + ")", status.error());
    }
  }
  print("[6] ingested 4 fresh samples at wall_ns=" + std::to_string(first_sample_ns) + " and " +
        std::to_string(second_sample_ns));

  // -- 7. the health report -------------------------------------------------
  const Result<HealthReport> report_result = registry.health(module);
  if (!report_result.ok()) {
    return fail("health", report_result.error());
  }
  print("[7] health report:");
  print_report(report_result.value());

  // -- 8. reconcile the lifecycle against that report -----------------------
  const Result<LifecycleEvent> reconcile_result =
      registry.reconcile_lifecycle(authority, module, MutationPolicy::AutoRetry);
  if (!reconcile_result.ok()) {
    return fail("reconcile_lifecycle", reconcile_result.error());
  }
  print("[8] reconciled lifecycle: " + std::string(to_string(reconcile_result.value().from)) + " -> " +
        std::string(to_string(reconcile_result.value().to)) + " (" + reconcile_result.value().reason + ")");

  // -- 9. a physical replacement in the same slot ---------------------------
  ModuleRegistration replacement;
  replacement.key = module_key.value();
  replacement.intent = RegisterIntent::NewIncarnation;
  replacement.identity.push_back(identity_value(IdentityField::Vendor, "Acme Optics"));
  replacement.identity.push_back(identity_value(IdentityField::PartNumber, "AO-400G-SR8"));
  replacement.identity.push_back(identity_value(IdentityField::SerialNumber, "SN-0002"));
  replacement.identity.push_back(identity_value(IdentityField::FirmwareVersion, "2.4.1"));
  replacement.provenance = synthetic("eeprom-page0", "decoded");
  replacement.policy = MutationPolicy::AutoRetry;

  const Result<ModuleHandle> replacement_result = registry.register_module(replacement, authority);
  if (!replacement_result.ok()) {
    return fail("register_module(replacement)", replacement_result.error());
  }
  const ModuleHandle current = replacement_result.value();
  print("[9] replacement registered: uid=" + std::to_string(current.uid.value()) +
        " incarnation=" + std::to_string(current.incarnation.value()) +
        " generation=" + std::to_string(current.generation.value()));

  const Result<AttachmentRecord> reattach_result =
      registry.attach(authority, current, slot_key.value(), 1, MutationPolicy::AutoRetry);
  if (!reattach_result.ok()) {
    return fail("attach(replacement)", reattach_result.error());
  }
  const Result<AttachmentRecord> slot_view = registry.attachment_of_slot(slot_key.value());
  if (!slot_view.ok()) {
    return fail("attachment_of_slot", slot_view.error());
  }
  print("      slot 'chassis0/bay2' now holds uid=" + std::to_string(slot_view.value().uid.value()) +
        "/incarnation=" + std::to_string(slot_view.value().incarnation.value()) +
        " attached_at_wall_ns=" + std::to_string(slot_view.value().attached_at_wall_ns));

  // The superseded incarnation is fenced: it is not an error the caller caused,
  // and it is not an empty answer either - the runtime refuses to describe the
  // replacement with the old incarnation's evidence.
  const Result<IdentityView> fenced_result = registry.identity(module);
  if (fenced_result.ok()) {
    return fail("identity(old incarnation)",
                Error{StatusCode::Internal, "the superseded incarnation was still reported as current"});
  }
  print("      identity(old incarnation=" + std::to_string(module.incarnation.value()) +
        ") refused: " + std::string(to_string(fenced_result.error().code)) + " - " + fenced_result.error().message);

  ClaimQuery claim_query;
  claim_query.field = IdentityField::Unknown;
  claim_query.limit = 16;
  claim_query.include_superseded = true;
  const Result<std::vector<IdentityClaim>> claims_result = registry.claim_history(module, claim_query);
  if (!claims_result.ok()) {
    return fail("claim_history", claims_result.error());
  }
  print("      claim_history(old incarnation) still records " + std::to_string(claims_result.value().size()) +
        " claims:");
  for (const IdentityClaim& claim : claims_result.value()) {
    print("        " + std::string(to_string(claim.field)) + "=" + quoted(claim.value) + " incarnation=" +
          std::to_string(claim.incarnation.value()) + " generation=" + std::to_string(claim.generation.value()));
  }

  const Result<IdentityView> current_identity = registry.identity(current);
  if (!current_identity.ok()) {
    return fail("identity(replacement)", current_identity.error());
  }
  print("      identity(new incarnation=" + std::to_string(current.incarnation.value()) + "):");
  print_identity(current_identity.value());

  const Status current_capability_status = publish(registry, authority, current, CapabilityKey::MediaClass,
                                                   CapabilityValue::of(MediaClass::MultimodeFiber));
  if (!current_capability_status.ok()) {
    return fail("publish_capability(replacement)", current_capability_status.error());
  }
  const Result<CapabilityView> current_capabilities = registry.capabilities(current);
  if (!current_capabilities.ok()) {
    return fail("capabilities(replacement)", current_capabilities.error());
  }
  print("      the replacement declares " + std::to_string(current_capabilities.value().attributes.size()) +
        " attribute(s); the previous incarnation's " + std::to_string(capabilities.size()) +
        " declarations are not inherited");

  const Result<HealthReport> current_report = registry.health(current);
  if (!current_report.ok()) {
    return fail("health(replacement)", current_report.error());
  }
  print("      the replacement has no telemetry of its own; the previous incarnation's samples are fenced:");
  print_report(current_report.value());

  // -- 10. what the registry now holds --------------------------------------
  const RegistryStats stats = registry.stats();
  print("[10] registry stats:");
  print("      generation=" + std::to_string(stats.generation.value()) +
        " registry_incarnation=" + std::to_string(stats.registry_incarnation));
  print("      sources=" + std::to_string(stats.sources) + " modules=" + std::to_string(stats.modules) +
        " incarnations=" + std::to_string(stats.incarnations) +
        " fenced_incarnations=" + std::to_string(stats.fenced_incarnations));
  print("      ports=" + std::to_string(stats.ports) + " rules=" + std::to_string(stats.rules) +
        " thresholds=" + std::to_string(stats.thresholds) + " attachments=" + std::to_string(stats.attachments) +
        " live_attachments=" + std::to_string(stats.live_attachments));
  print("      claims=" + std::to_string(stats.claims) + " declarations=" + std::to_string(stats.declarations) +
        " samples=" + std::to_string(stats.samples) + " mutations=" + std::to_string(stats.mutations) +
        " refusals=" + std::to_string(stats.refusals) + " queries=" + std::to_string(stats.queries) +
        " conflicts_observed=" + std::to_string(stats.conflicts_observed));
  print("      state_digest=" + stats.state_digest.to_hex());
  print("state_digest=" + registry.state_digest().to_hex());
  print("lifecycle example completed");
  return 0;
}

}  // namespace

int main() { return run(); }
