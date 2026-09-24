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

// Shared fixtures for the registry test suites. Every fixture builds SYNTHETIC
// evidence: this runtime never talks to hardware, and the tests say so through
// the provenance they attach.

#include <memory>
#include <string>
#include <utility>

#include "test_support.hpp"
#include "trxreg/registry.hpp"

namespace trxreg::test {

inline constexpr WallNs kBaseWallNs = 1'700'000'000'000'000'000LL;

inline Provenance synthetic_provenance(std::string origin = "test-fixture", std::string method = "generated") {
  Provenance provenance;
  provenance.kind = EvidenceKind::Synthetic;
  provenance.origin = std::move(origin);
  provenance.method = std::move(method);
  return provenance;
}

inline std::shared_ptr<ManualClock> make_test_clock(WallNs wall_ns = kBaseWallNs, ClockDomainId domain = ClockDomainId{7}) {
  return std::make_shared<ManualClock>(wall_ns, domain);
}

/// Report a failed fixture step and return a default-constructed value.
template <class T>
inline T fixture_value(const Result<T>& result, const char* expression, const char* file, int line) {
  if (result.ok()) {
    return result.value();
  }
  report_failure(file, line, std::string("fixture step failed: ") + expression + " -> " +
                                 std::string(to_string(result.error().code)) + ": " + result.error().message);
  return T{};
}

#define TRXREG_FIXTURE(expression) ::trxreg::test::fixture_value((expression), #expression, __FILE__, __LINE__)

/// Report a failed fixture step that returns a bare Status.
inline void fixture_status(const Status& status, const char* expression, const char* file, int line) {
  if (!status.ok()) {
    report_failure(file, line, std::string("fixture step failed: ") + expression + " -> " +
                                 std::string(to_string(status.code())) + ": " + status.message());
  }
}

#define TRXREG_FIXTURE_STATUS(expression) ::trxreg::test::fixture_status((expression), #expression, __FILE__, __LINE__)

inline SourceHandle register_source(Registry& registry, const std::string& name,
                                    EvidenceKind kind = EvidenceKind::Synthetic) {
  SourceDescriptor descriptor;
  descriptor.name = name;
  descriptor.description = "synthetic test source";
  descriptor.declared_kind = kind;
  descriptor.instance_id = name + "-instance";
  return TRXREG_FIXTURE(registry.register_source(descriptor));
}

inline ModuleHandle register_module(Registry& registry, const AuthorityToken& authority, const std::string& key,
                                   RegisterIntent intent = RegisterIntent::EnsureCurrent,
                                   const std::string& vendor = "Acme Optics",
                                   const std::string& part = "AO-400G-SR8",
                                   const std::string& serial = "SN-0001") {
  ModuleRegistration registration;
  registration.key = TRXREG_FIXTURE(ModuleKey::parse(key, "module key"));
  registration.intent = intent;
  registration.provenance = synthetic_provenance("eeprom-page0", "decoded");
  registration.policy = MutationPolicy::AutoRetry;
  registration.identity.push_back(IdentityFieldValue{IdentityField::Vendor, {}, vendor});
  registration.identity.push_back(IdentityFieldValue{IdentityField::PartNumber, {}, part});
  registration.identity.push_back(IdentityFieldValue{IdentityField::SerialNumber, {}, serial});
  return TRXREG_FIXTURE(registry.register_module(registration, authority));
}

inline void publish_capability(Registry& registry, const AuthorityToken& authority, const ModuleHandle& module,
                               CapabilityKey key, CapabilityValue value, std::string subkey = {}) {
  const Status status = registry.publish_capability(authority, module, key, std::move(subkey), std::move(value),
                                                    synthetic_provenance("probe-agent", "declared"),
                                                    MutationPolicy::AutoRetry);
  REQUIRE_OK(status);
}

inline void publish_port_capability(Registry& registry, const AuthorityToken& authority, const std::string& port,
                                    CapabilityKey key, CapabilityValue value) {
  const PortKey parsed = TRXREG_FIXTURE(PortKey::parse(port, "port key"));
  const Status status = registry.publish_port_capability(authority, parsed, key, {}, std::move(value),
                                                         synthetic_provenance("chassis-config", "declared"),
                                                         MutationPolicy::AutoRetry);
  REQUIRE_OK(status);
}

inline void publish_threshold(Registry& registry, const AuthorityToken& authority, const HealthThreshold& threshold) {
  const Status status = registry.publish_threshold(authority, threshold, MutationPolicy::AutoRetry);
  REQUIRE_OK(status);
}

inline void ingest(Registry& registry, const AuthorityToken& authority, const ModuleHandle& module,
                   HealthMetric metric, double value, WallNs observed_at_wall_ns, std::uint16_t lane = kModuleLane,
                   SamplePresence presence = SamplePresence::Present,
                   std::uint64_t monotonic_ns = 0, ClockDomainId domain = ClockDomainId{}) {
  HealthSampleInput sample;
  sample.metric = metric;
  sample.lane = lane;
  sample.presence = presence;
  sample.value = value;
  sample.observed_at_wall_ns = observed_at_wall_ns;
  sample.observed_at_monotonic_ns = monotonic_ns;
  sample.clock_domain = domain;
  sample.provenance = synthetic_provenance("ddm-poll", "read");
  const Status status = registry.ingest_health(authority, module, sample, MutationPolicy::AutoRetry);
  REQUIRE_OK(status);
}

inline HealthThreshold temperature_threshold(WallNs max_age_ns = 60'000'000'000LL) {
  HealthThreshold threshold;
  threshold.metric = HealthMetric::TemperatureCelsius;
  threshold.direction = ThresholdDirection::Above;
  threshold.has_degraded = true;
  threshold.degraded_enter = 70.0;
  threshold.degraded_exit = 65.0;
  threshold.has_critical = true;
  threshold.critical_enter = 80.0;
  threshold.critical_exit = 75.0;
  threshold.escalate_after = 1;
  threshold.recover_after = 1;
  threshold.max_age_ns = max_age_ns;
  threshold.disagreement_tolerance = 1.0;
  threshold.provenance = synthetic_provenance("operator-policy", "declared");
  return threshold;
}

inline CompatRule allow_rule(std::string name, std::vector<Requirement> requirements, std::int32_t priority = 0) {
  CompatRule rule;
  rule.name = std::move(name);
  rule.requirements = std::move(requirements);
  rule.verdict = CompatVerdict::Compatible;
  rule.priority = priority;
  rule.rationale = "declared by the operator";
  rule.provenance = synthetic_provenance("operator-policy", "declared");
  return rule;
}

inline Requirement module_requirement(CapabilityKey key, RequirementOp op, CapabilityValue operand) {
  Requirement requirement;
  requirement.subject = RequirementSubject::Module;
  requirement.key = key;
  requirement.op = op;
  requirement.operand = std::move(operand);
  return requirement;
}

inline Requirement port_requirement(CapabilityKey key, RequirementOp op, CapabilityValue operand) {
  Requirement requirement;
  requirement.subject = RequirementSubject::Port;
  requirement.key = key;
  requirement.op = op;
  requirement.operand = std::move(operand);
  return requirement;
}

}  // namespace trxreg::test
