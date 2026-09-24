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

// Downstream consumer of the installed Transceiver Registry package.
//
// The consumer is deliberately thin: it uses the public headers only, registers a
// module, publishes one capability and one telemetry sample, and then exercises
// the compatibility API in a way whose outcome is fixed by rules it publishes
// itself:
//
//   allow rule only                  -> COMPATIBLE
//   allow + higher-priority deny     -> INCOMPATIBLE
//   both retired                     -> UNKNOWN (no live rule, closure open)
//
// A decision is accepted only when it is one of the four modelled outcomes, and
// each step asserts the outcome its published knowledge implies. Any other value
// (including UNKNOWN where a rule should have decided) fails the run.

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/taxonomy.hpp"
#include "trxreg/version.hpp"

namespace {

using namespace trxreg;

/// A fixed origin keeps the printed timestamps reproducible.
constexpr WallNs kStartWallNs = 1'767'225'600'000'000'000LL;
constexpr ClockDomainId kClockDomain{101};

void print(std::string_view text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
}

int fail(std::string_view step, const Error& error) {
  std::string text = "trxreg_downstream: ";
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

std::string_view outcome_name(CompatOutcome outcome) {
  switch (outcome) {
    case CompatOutcome::Unknown:
      return "unknown";
    case CompatOutcome::Compatible:
      return "compatible";
    case CompatOutcome::Incompatible:
      return "incompatible";
    case CompatOutcome::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

std::string_view closure_name(KnowledgeClosure closure) {
  switch (closure) {
    case KnowledgeClosure::Open:
      return "open";
    case KnowledgeClosure::Partial:
      return "partial";
    case KnowledgeClosure::Closed:
      return "closed";
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

/// True only for the four outcomes the API models. Anything else means the
/// package is not usable, whatever the numeric value happens to be.
bool is_modelled_outcome(CompatOutcome outcome) {
  return outcome == CompatOutcome::Compatible || outcome == CompatOutcome::Incompatible ||
         outcome == CompatOutcome::Unknown || outcome == CompatOutcome::Unsupported;
}

int report_decision(std::string_view step, const CompatDecision& decision, CompatOutcome expected) {
  print("    " + std::string(step) + ": outcome=" + std::string(outcome_name(decision.outcome)) +
        " closure=" + std::string(closure_name(decision.closure)) +
        " considered_rules=" + std::to_string(decision.considered_rules) +
        " decision_digest=" + decision.decision_digest.to_hex());
  if (!is_modelled_outcome(decision.outcome)) {
    return fail(step, Error{StatusCode::Internal, "the decision is not one of the four modelled outcomes"});
  }
  if (decision.outcome != expected) {
    return fail(step, Error{StatusCode::Internal, std::string("expected ") + std::string(outcome_name(expected)) +
                                                        " but the registry answered " +
                                                        std::string(outcome_name(decision.outcome))});
  }
  return 0;
}

CompatRule make_rule(std::string name, CompatVerdict verdict, std::int32_t priority, Requirement requirement) {
  CompatRule rule;
  rule.name = std::move(name);
  rule.requirements.push_back(std::move(requirement));
  rule.verdict = verdict;
  rule.priority = priority;
  rule.rationale = "published by the downstream consumer";
  rule.provenance = synthetic("downstream-policy", "declared");
  return rule;
}

Requirement module_requirement(CapabilityKey key, RequirementOp op, CapabilityValue operand) {
  Requirement requirement;
  requirement.subject = RequirementSubject::Module;
  requirement.key = key;
  requirement.op = op;
  requirement.operand = std::move(operand);
  return requirement;
}

int run() {
  const auto clock = std::make_shared<ManualClock>(kStartWallNs, kClockDomain);
  Registry registry{RegistryConfig{}, clock};

  print("[1] TransceiverRegistry package: version=" + std::string(version_string()) +
        " snapshot_format=" + std::to_string(kSnapshotFormatVersion) +
        " wire_protocol=" + std::to_string(kWireProtocolVersion));

  SourceDescriptor descriptor;
  descriptor.name = "downstream-agent";
  descriptor.description = "downstream consumer of the installed package";
  descriptor.declared_kind = EvidenceKind::Synthetic;
  descriptor.instance_id = "downstream-agent/run-1";
  const Result<SourceHandle> source = registry.register_source(descriptor);
  if (!source.ok()) {
    return fail("register_source", source.error());
  }
  const AuthorityToken authority = source.value().authority();
  print("[2] source registered: id=" + std::to_string(source.value().id.value()) +
        " epoch=" + std::to_string(source.value().epoch.value()));

  const Result<ModuleKey> key = ModuleKey::parse("downstream0/cage1/module0", "module key");
  if (!key.ok()) {
    return fail("ModuleKey::parse", key.error());
  }
  ModuleRegistration registration;
  registration.key = key.value();
  registration.intent = RegisterIntent::EnsureCurrent;
  registration.provenance = synthetic("eeprom-page0", "decoded");
  registration.policy = MutationPolicy::AutoRetry;
  IdentityFieldValue vendor;
  vendor.field = IdentityField::Vendor;
  vendor.value = "Acme Optics";
  registration.identity.push_back(vendor);
  const Result<ModuleHandle> module = registry.register_module(registration, authority);
  if (!module.ok()) {
    return fail("register_module", module.error());
  }
  print("[3] module registered: uid=" + std::to_string(module.value().uid.value()) +
        " incarnation=" + std::to_string(module.value().incarnation.value()) +
        " key=" + module.value().key.str());

  const Status capability_status =
      registry.publish_capability(authority, module.value(), CapabilityKey::LaneCount, std::string{},
                                  CapabilityValue::count(8), synthetic("eeprom-page0", "decoded"),
                                  MutationPolicy::AutoRetry);
  if (!capability_status.ok()) {
    return fail("publish_capability", capability_status.error());
  }
  print("[4] capability published: lane_count=8");

  HealthSampleInput sample;
  sample.metric = HealthMetric::TemperatureCelsius;
  sample.lane = kModuleLane;
  sample.presence = SamplePresence::Present;
  sample.value = 58.5;
  sample.observed_at_wall_ns = clock->wall_now_ns();
  sample.provenance = synthetic("ddm-poll", "read");
  const Status sample_status = registry.ingest_health(authority, module.value(), sample, MutationPolicy::AutoRetry);
  if (!sample_status.ok()) {
    return fail("ingest_health", sample_status.error());
  }
  print("[5] sample ingested: temperature_celsius=58.500 at wall_ns=" + std::to_string(sample.observed_at_wall_ns));

  const Result<PortKey> port = PortKey::parse("switch0/ethernet9/1", "port key");
  if (!port.ok()) {
    return fail("PortKey::parse", port.error());
  }
  const auto query = [&registry, &port, &module]() {
    CompatQuery compat_query;
    compat_query.port = port.value();
    compat_query.uid = module.value().uid;
    compat_query.incarnation = module.value().incarnation;
    compat_query.require_latest_generation = true;
    compat_query.explain = true;
    return registry.query_compatibility(compat_query);
  };

  // -- an explicit allow rule decides the pair -------------------------------
  const Result<CompatRuleHandle> allow = registry.publish_rule(
      authority,
      make_rule("downstream-allow", CompatVerdict::Compatible, 10,
                module_requirement(CapabilityKey::LaneCount, RequirementOp::AtLeast, CapabilityValue::count(1))),
      MutationPolicy::AutoRetry);
  if (!allow.ok()) {
    return fail("publish_rule(allow)", allow.error());
  }
  const Result<CompatDecision> allow_decision = query();
  if (!allow_decision.ok()) {
    return fail("query_compatibility(allow)", allow_decision.error());
  }
  print("[6] allow rule id=" + std::to_string(allow.value().id.value()) + " published (priority 10)");
  const int allow_check = report_decision("query with the allow rule", allow_decision.value(), CompatOutcome::Compatible);
  if (allow_check != 0) {
    return allow_check;
  }

  // -- a deny rule with higher priority overrides it -------------------------
  const Result<CompatRuleHandle> deny = registry.publish_rule(
      authority,
      make_rule("downstream-deny", CompatVerdict::Incompatible, 100,
                module_requirement(CapabilityKey::LaneCount, RequirementOp::AtMost, CapabilityValue::count(8))),
      MutationPolicy::AutoRetry);
  if (!deny.ok()) {
    return fail("publish_rule(deny)", deny.error());
  }
  const Result<CompatDecision> deny_decision = query();
  if (!deny_decision.ok()) {
    return fail("query_compatibility(deny)", deny_decision.error());
  }
  print("[7] deny rule id=" + std::to_string(deny.value().id.value()) + " published (priority 100)");
  const int deny_check = report_decision("query with the deny rule", deny_decision.value(), CompatOutcome::Incompatible);
  if (deny_check != 0) {
    return deny_check;
  }

  // -- with no live rule the pair is an open question ------------------------
  for (const CompatRuleRecord& record : registry.rules()) {
    if (!record.live) {
      continue;
    }
    const Status retired = registry.retire_rule(authority, record.id, MutationPolicy::AutoRetry);
    if (!retired.ok()) {
      return fail("retire_rule", retired.error());
    }
  }
  const Result<CompatDecision> open_decision = query();
  if (!open_decision.ok()) {
    return fail("query_compatibility(no rules)", open_decision.error());
  }
  print("[8] both rules retired");
  const int open_check = report_decision("query without rules", open_decision.value(), CompatOutcome::Unknown);
  if (open_check != 0) {
    return open_check;
  }
  if (open_decision.value().closure != KnowledgeClosure::Open) {
    return fail("query_compatibility(no rules)",
                Error{StatusCode::Internal, "a pair with no live rule must report closure=open"});
  }

  print("downstream consumer completed");
  return 0;
}

}  // namespace

int main() { return run(); }
