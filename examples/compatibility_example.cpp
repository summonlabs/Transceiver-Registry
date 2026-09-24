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

// Compatibility walkthrough of the Transceiver Registry.
//
// A host port profile and a module are published, three rules with different
// verdicts are declared, and the resulting decision is printed through
// explain_decision() together with its input and decision digests.
//
// Three instructive cases follow, and all three answer UNKNOWN:
//   (a) two live sources disagree about a capability the deciding rule reads,
//   (b) no rule covers the pair at all,
//   (c) a rule reads an attribute nobody published.
// None of them may ever be mistaken for approval, which is what the closure
// field exists to express.

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/taxonomy.hpp"

namespace {

using namespace trxreg;

constexpr WallNs kStartWallNs = 1'767'225'600'000'000'000LL;
constexpr ClockDomainId kClockDomain{11};

void print(std::string_view text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
}

std::string quoted(std::string_view text) { return "'" + std::string(text) + "'"; }

int fail(std::string_view step, const Error& error) {
  std::string text = "compatibility_example: ";
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

// The decision vocabulary lives in compatibility.hpp, which publishes no name
// table for it, so the example renders those three enums itself.

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

std::string_view requirement_state_name(RequirementState state) {
  switch (state) {
    case RequirementState::Satisfied:
      return "satisfied";
    case RequirementState::Violated:
      return "violated";
    case RequirementState::Indeterminate:
      return "indeterminate";
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

Requirement module_requires(CapabilityKey key, RequirementOp op, CapabilityValue operand, std::string note = {}) {
  Requirement requirement;
  requirement.subject = RequirementSubject::Module;
  requirement.key = key;
  requirement.op = op;
  requirement.operand = std::move(operand);
  requirement.note = std::move(note);
  return requirement;
}

Requirement port_requires(CapabilityKey key, RequirementOp op, CapabilityValue operand, std::string note = {}) {
  Requirement requirement;
  requirement.subject = RequirementSubject::Port;
  requirement.key = key;
  requirement.op = op;
  requirement.operand = std::move(operand);
  requirement.note = std::move(note);
  return requirement;
}

CompatRule make_rule(std::string name, CompatVerdict verdict, std::int32_t priority, std::string rationale,
                     std::vector<Requirement> requirements) {
  CompatRule rule;
  rule.name = std::move(name);
  rule.requirements = std::move(requirements);
  rule.verdict = verdict;
  rule.priority = priority;
  rule.rationale = std::move(rationale);
  rule.provenance = synthetic("operator-policy", "declared");
  return rule;
}

Status publish_module_capability(Registry& registry, const AuthorityToken& authority, const ModuleHandle& module,
                                 CapabilityKey key, CapabilityValue value, const Provenance& provenance) {
  return registry.publish_capability(authority, module, key, std::string{}, std::move(value), provenance,
                                     MutationPolicy::AutoRetry);
}

Status publish_port_capability(Registry& registry, const AuthorityToken& authority, const PortKey& port,
                               CapabilityKey key, CapabilityValue value) {
  return registry.publish_port_capability(authority, port, key, std::string{}, std::move(value),
                                          synthetic("chassis-config", "declared"), MutationPolicy::AutoRetry);
}

void print_capabilities(const CapabilityView& view, std::string_view indent) {
  for (const CapabilityConsensus& attribute : view.attributes) {
    std::string text(indent);
    text += to_string(attribute.key);
    text += " = ";
    text += attribute.value.describe(attribute.key);
    text += " [";
    text += to_string(attribute.outcome);
    text += ", declarations=";
    text += std::to_string(attribute.declarations.size());
    text += "]";
    print(text);
  }
}

void print_explanation(const CompatDecision& decision) {
  const std::string explanation = explain_decision(decision);
  std::size_t start = 0;
  while (start < explanation.size()) {
    const std::size_t end = explanation.find('\n', start);
    const std::size_t length = end == std::string::npos ? explanation.size() - start : end - start;
    print("        " + explanation.substr(start, length));
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
}

void print_decision(const CompatDecision& decision) {
  print("      outcome=" + std::string(outcome_name(decision.outcome)) +
        " closure=" + std::string(closure_name(decision.closure)) +
        " considered_rules=" + std::to_string(decision.considered_rules) +
        " indeterminate_rules=" + std::to_string(decision.indeterminate_rules));
  print("      decision_digest=" + decision.decision_digest.to_hex());
  print("      inputs_digest=" + decision.inputs_digest.to_hex());
  print("      explain_decision():");
  print_explanation(decision);
  for (const RequirementEvaluation& evaluation : decision.violated_requirements) {
    print("      violated requirement " + std::string(to_string(evaluation.requirement.subject)) + "." +
          std::string(to_string(evaluation.requirement.key)) + " (" +
          std::string(requirement_state_name(evaluation.state)) + "): " + evaluation.detail);
  }
  // Unmet (indeterminate) requirements are already rendered by explain_decision().
}

Result<CompatDecision> query(Registry& registry, const PortKey& port, const ModuleHandle& module) {
  CompatQuery compat_query;
  compat_query.port = port;
  compat_query.uid = module.uid;
  compat_query.incarnation = module.incarnation;
  compat_query.require_latest_generation = true;
  compat_query.explain = true;
  return registry.query_compatibility(compat_query);
}

int run() {
  const auto clock = std::make_shared<ManualClock>(kStartWallNs, kClockDomain);
  Registry registry{RegistryConfig{}, clock};

  print("Transceiver Registry - compatibility example");
  print("clock: ManualClock domain=" + std::to_string(kClockDomain.value()) +
        " start_wall_ns=" + std::to_string(kStartWallNs));

  // -- sources ---------------------------------------------------------------
  SourceDescriptor chassis_source;
  chassis_source.name = "chassis-config";
  chassis_source.description = "declares host port profiles from operator configuration";
  chassis_source.declared_kind = EvidenceKind::Synthetic;
  chassis_source.instance_id = "chassis-config/run-1";
  const Result<SourceHandle> chassis_result = registry.register_source(chassis_source);
  if (!chassis_result.ok()) {
    return fail("register_source(chassis-config)", chassis_result.error());
  }
  const AuthorityToken chassis_authority = chassis_result.value().authority();
  print("[1] source 'chassis-config' id=" + std::to_string(chassis_result.value().id.value()) +
        " epoch=" + std::to_string(chassis_result.value().epoch.value()));

  SourceDescriptor probe_source;
  probe_source.name = "probe-agent-1";
  probe_source.description = "reads module EEPROM pages";
  probe_source.declared_kind = EvidenceKind::Synthetic;
  probe_source.instance_id = "probe-agent-1/run-1";
  const Result<SourceHandle> probe_result = registry.register_source(probe_source);
  if (!probe_result.ok()) {
    return fail("register_source(probe-agent-1)", probe_result.error());
  }
  const AuthorityToken probe_authority = probe_result.value().authority();
  print("[2] source 'probe-agent-1' id=" + std::to_string(probe_result.value().id.value()) +
        " epoch=" + std::to_string(probe_result.value().epoch.value()));

  // -- the host port profile -------------------------------------------------
  const Result<PortKey> port_result = PortKey::parse("switch0/ethernet1/1", "port key");
  if (!port_result.ok()) {
    return fail("PortKey::parse", port_result.error());
  }
  const PortKey port = port_result.value();

  struct Publication {
    CapabilityKey key;
    CapabilityValue value;
  };
  const std::vector<Publication> port_profile = {
      {CapabilityKey::MediaClass, CapabilityValue::of(MediaClass::MultimodeFiber)},
      {CapabilityKey::ConnectorClass, CapabilityValue::of(ConnectorClass::Mpo16)},
      {CapabilityKey::SpeedClasses, CapabilityValue::of_speed_classes({SpeedClass::Gb400})},
      {CapabilityKey::FecModes, CapabilityValue::of_fec_modes({FecClass::RsFec544, FecClass::None})},
      {CapabilityKey::MaxPowerMilliWatts, CapabilityValue::real(3500.0)},
  };
  for (const Publication& publication : port_profile) {
    const Status status =
        publish_port_capability(registry, chassis_authority, port, publication.key, publication.value);
    if (!status.ok()) {
      return fail(std::string("publish_port_capability(") + std::string(to_string(publication.key)) + ")",
                  status.error());
    }
  }
  print("[3] host port profile published for " + quoted(port.str()) + ":");
  const Result<CapabilityView> port_view = registry.port_capabilities(port);
  if (!port_view.ok()) {
    return fail("port_capabilities", port_view.error());
  }
  print_capabilities(port_view.value(), "      ");

  // -- the module ------------------------------------------------------------
  const Result<ModuleKey> module_key = ModuleKey::parse("chassis0/bay1/module0", "module key");
  if (!module_key.ok()) {
    return fail("ModuleKey::parse", module_key.error());
  }
  ModuleRegistration registration;
  registration.key = module_key.value();
  registration.intent = RegisterIntent::EnsureCurrent;
  registration.provenance = synthetic("eeprom-page0", "decoded");
  registration.policy = MutationPolicy::AutoRetry;
  IdentityFieldValue vendor;
  vendor.field = IdentityField::Vendor;
  vendor.value = "Acme Optics";
  IdentityFieldValue part;
  part.field = IdentityField::PartNumber;
  part.value = "AO-400G-SR8";
  registration.identity.push_back(vendor);
  registration.identity.push_back(part);
  const Result<ModuleHandle> module_result = registry.register_module(registration, probe_authority);
  if (!module_result.ok()) {
    return fail("register_module", module_result.error());
  }
  const ModuleHandle module = module_result.value();

  const std::vector<Publication> module_profile = {
      {CapabilityKey::ModuleFamily, CapabilityValue::of(ModuleFamily::OpticalTransceiver)},
      {CapabilityKey::MediaClass, CapabilityValue::of(MediaClass::MultimodeFiber)},
      {CapabilityKey::ConnectorClass, CapabilityValue::of(ConnectorClass::Mpo16)},
      {CapabilityKey::LaneCount, CapabilityValue::count(8)},
      {CapabilityKey::SpeedClasses, CapabilityValue::of_speed_classes({SpeedClass::Gb400})},
      {CapabilityKey::FecModes, CapabilityValue::of_fec_modes({FecClass::RsFec544})},
      {CapabilityKey::MaxPowerMilliWatts, CapabilityValue::real(3200.0)},
  };
  const Provenance eeprom_provenance = synthetic("eeprom-page0", "decoded");
  for (const Publication& publication : module_profile) {
    const Status status = publish_module_capability(registry, probe_authority, module, publication.key,
                                                    publication.value, eeprom_provenance);
    if (!status.ok()) {
      return fail(std::string("publish_capability(") + std::string(to_string(publication.key)) + ")", status.error());
    }
  }
  print("[4] module published: uid=" + std::to_string(module.uid.value()) +
        " incarnation=" + std::to_string(module.incarnation.value()) + " key=" + quoted(module.key.str()));
  const Result<CapabilityView> module_view = registry.capabilities(module);
  if (!module_view.ok()) {
    return fail("capabilities", module_view.error());
  }
  print_capabilities(module_view.value(), "      ");

  // -- three rules with three different verdicts -----------------------------
  const Result<CompatRuleHandle> allow_result = registry.publish_rule(
      chassis_authority,
      make_rule("mmf-400g-port-accepts-mmf-400g-module", CompatVerdict::Compatible, 100,
                "a 400G multimode module is supported in a 400G multimode port",
                {module_requires(CapabilityKey::MediaClass, RequirementOp::Equals,
                                 CapabilityValue::of(MediaClass::MultimodeFiber), "same medium"),
                 module_requires(CapabilityKey::SpeedClasses, RequirementOp::SubsetOf,
                                 CapabilityValue::of_speed_classes({SpeedClass::Gb400, SpeedClass::Gb200}),
                                 "the module must not exceed what the port can carry"),
                 module_requires(CapabilityKey::FecModes, RequirementOp::Overlaps,
                                 CapabilityValue::of_fec_modes({FecClass::RsFec544, FecClass::None}),
                                 "a common FEC mode must exist"),
                 port_requires(CapabilityKey::ConnectorClass, RequirementOp::Equals,
                               CapabilityValue::of(ConnectorClass::Mpo16), "the port must expose an MPO-16 cage")}),
      MutationPolicy::AutoRetry);
  if (!allow_result.ok()) {
    return fail("publish_rule(allow)", allow_result.error());
  }

  const Result<CompatRuleHandle> deny_result = registry.publish_rule(
      chassis_authority,
      make_rule("low-power-port-cannot-drive-400g", CompatVerdict::Incompatible, 200,
                "a cage that delivers at most 3 W cannot power a 400G module",
                {port_requires(CapabilityKey::MaxPowerMilliWatts, RequirementOp::AtMost,
                               CapabilityValue::real(3000.0), "power budget of the cage")}),
      MutationPolicy::AutoRetry);
  if (!deny_result.ok()) {
    return fail("publish_rule(deny)", deny_result.error());
  }

  const Result<CompatRuleHandle> unsupported_result = registry.publish_rule(
      chassis_authority,
      make_rule("loopback-module-not-supported", CompatVerdict::Unsupported, 300,
                "loopback plugs are not modelled as line-side optics here",
                {module_requires(CapabilityKey::ModuleFamily, RequirementOp::Equals,
                                 CapabilityValue::of(ModuleFamily::LoopbackModule), "inventory class")}),
      MutationPolicy::AutoRetry);
  if (!unsupported_result.ok()) {
    return fail("publish_rule(unsupported)", unsupported_result.error());
  }
  print("[5] rules published: allow id=" + std::to_string(allow_result.value().id.value()) +
        " deny id=" + std::to_string(deny_result.value().id.value()) +
        " unsupported id=" + std::to_string(unsupported_result.value().id.value()));

  // -- the decision ----------------------------------------------------------
  const Result<CompatDecision> decision_result = query(registry, port, module);
  if (!decision_result.ok()) {
    return fail("query_compatibility", decision_result.error());
  }
  print("[6] compatibility decision for port=" + quoted(port.str()) + " module=" +
        std::to_string(module.uid.value()) + "/" + std::to_string(module.incarnation.value()) + ":");
  print_decision(decision_result.value());
  if (decision_result.value().outcome != CompatOutcome::Compatible) {
    return fail("query_compatibility(deciding rules)",
                Error{StatusCode::Internal, "the allow rule should have decided this pair as compatible"});
  }

  // The same module in a cage that cannot power it: a matched deny always wins,
  // even though the allow rule matches there as well.
  const Result<PortKey> low_power_port_result = PortKey::parse("switch0/ethernet1/2", "port key");
  if (!low_power_port_result.ok()) {
    return fail("PortKey::parse(low power port)", low_power_port_result.error());
  }
  const PortKey low_power_port = low_power_port_result.value();
  for (const Publication& publication : port_profile) {
    CapabilityValue value = publication.value;
    if (publication.key == CapabilityKey::MaxPowerMilliWatts) {
      value = CapabilityValue::real(2500.0);
    }
    const Status status = publish_port_capability(registry, chassis_authority, low_power_port, publication.key, value);
    if (!status.ok()) {
      return fail("publish_port_capability(low power port)", status.error());
    }
  }
  const Result<CompatDecision> low_power_decision = query(registry, low_power_port, module);
  if (!low_power_decision.ok()) {
    return fail("query_compatibility(low power port)", low_power_decision.error());
  }
  print("[7] the same module in port 'switch0/ethernet1/2' with MaxPowerMilliWatts=2500:");
  print_decision(low_power_decision.value());
  if (low_power_decision.value().outcome != CompatOutcome::Incompatible) {
    return fail("query_compatibility(low power port)",
                Error{StatusCode::Internal, "the deny rule should have decided this pair as incompatible"});
  }

  // -- case (a): two live sources disagree about the deciding attribute -------
  const Status conflict_status =
      publish_module_capability(registry, chassis_authority, module, CapabilityKey::MediaClass,
                                CapabilityValue::of(MediaClass::SingleModeFiber),
                                synthetic("chassis-config", "declared"));
  if (!conflict_status.ok()) {
    return fail("publish_capability(conflicting media class)", conflict_status.error());
  }
  const Result<CapabilityView> conflicted_view = registry.capabilities(module);
  if (!conflicted_view.ok()) {
    return fail("capabilities(conflicted)", conflicted_view.error());
  }
  const CapabilityConsensus* media = conflicted_view.value().find(CapabilityKey::MediaClass);
  print("[8] case (a): 'probe-agent-1' and 'chassis-config' both declare MediaClass on uid=" +
        std::to_string(module.uid.value()));
  if (media != nullptr) {
    print("      consensus=" + std::string(to_string(media->outcome)) +
          " declarations=" + std::to_string(media->declarations.size()) +
          " conflicting_attributes=" + std::to_string(conflicted_view.value().conflicting_attributes));
    for (const CapabilityDeclaration& declaration : media->declarations) {
      print("        source=" + std::to_string(declaration.source.value()) +
            " epoch=" + std::to_string(declaration.source_epoch.value()) +
            " value=" + declaration.value.describe(CapabilityKey::MediaClass));
    }
  }
  const Result<CompatDecision> conflict_decision = query(registry, port, module);
  if (!conflict_decision.ok()) {
    return fail("query_compatibility(conflict)", conflict_decision.error());
  }
  print_decision(conflict_decision.value());
  if (conflict_decision.value().outcome != CompatOutcome::Unknown ||
      conflict_decision.value().outcome == CompatOutcome::Compatible) {
    return fail("query_compatibility(conflict)",
                Error{StatusCode::Internal, "a conflicting attribute must never produce compatible"});
  }

  // -- case (b): no rule covers the pair -------------------------------------
  for (const CompatRuleRecord& record : registry.rules()) {
    if (!record.live) {
      continue;
    }
    const Status status = registry.retire_rule(chassis_authority, record.id, MutationPolicy::AutoRetry);
    if (!status.ok()) {
      return fail("retire_rule", status.error());
    }
  }
  const Result<CompatDecision> open_decision = query(registry, port, module);
  if (!open_decision.ok()) {
    return fail("query_compatibility(no rules)", open_decision.error());
  }
  print("[9] case (b): every rule retired, so no rule covers this pair:");
  print_decision(open_decision.value());
  if (open_decision.value().closure != KnowledgeClosure::Open) {
    return fail("query_compatibility(no rules)",
                Error{StatusCode::Internal, "a pair with no live rule must report closure=open"});
  }

  // -- case (c): a rule reads an attribute nobody published -------------------
  const Result<CompatRuleHandle> guard_result = registry.publish_rule(
      chassis_authority,
      make_rule("operating-window-guard", CompatVerdict::Compatible, 50,
                "the operating temperature window must be known before this pair is approved",
                {module_requires(CapabilityKey::OperatingTemperatureMaxCelsius, RequirementOp::AtLeast,
                                 CapabilityValue::real(0.0), "no source published an operating window")}),
      MutationPolicy::AutoRetry);
  if (!guard_result.ok()) {
    return fail("publish_rule(operating window guard)", guard_result.error());
  }
  const Result<CompatDecision> partial_decision = query(registry, port, module);
  if (!partial_decision.ok()) {
    return fail("query_compatibility(unpublished attribute)", partial_decision.error());
  }
  print("[10] case (c): rule id=" + std::to_string(guard_result.value().id.value()) +
        " requires module.operating_temperature_max_celsius, which no source published:");
  print_decision(partial_decision.value());
  if (partial_decision.value().closure != KnowledgeClosure::Partial ||
      partial_decision.value().unmet_requirements.empty()) {
    return fail("query_compatibility(unpublished attribute)",
                Error{StatusCode::Internal,
                      "an unevaluable rule must report closure=partial with the unmet requirement listed"});
  }

  print("compatibility example completed");
  return 0;
}

}  // namespace

int main() { return run(); }
