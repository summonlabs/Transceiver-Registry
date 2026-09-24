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

// trxreg_bench: measures COMPLETED useful work, not submission latency.
//
// Every scenario counts operations that the registry committed and answered
// before the clock is read, so a throughput number can never be produced by
// dropping work on the floor. Each scenario owns its own registry: the runtime
// copies its whole state per mutation, and sharing one registry between
// scenarios would measure the accumulated state instead of the operation.
//
// ALL DATA IS SYNTHETIC.

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/taxonomy.hpp"
#include "trxreg/wire.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

using trxreg::AuthorityToken;
using trxreg::CapabilityKey;
using trxreg::CapabilityValue;
using trxreg::ClockDomainId;
using trxreg::Generation;
using trxreg::HealthMetric;
using trxreg::HealthSampleInput;
using trxreg::HealthThreshold;
using trxreg::IdentityField;
using trxreg::IdentityFieldValue;
using trxreg::IncarnationId;
using trxreg::ModuleHandle;
using trxreg::ModuleKey;
using trxreg::ModuleRegistration;
using trxreg::ModuleUid;
using trxreg::MutationPolicy;
using trxreg::Provenance;
using trxreg::RegisterIntent;
using trxreg::Registry;
using trxreg::RegistryConfig;
using trxreg::Result;
using trxreg::SourceDescriptor;
using trxreg::SourceHandle;
using trxreg::StatusCode;
using trxreg::Status;
using trxreg::Value;

using Clock = std::chrono::steady_clock;

constexpr std::uint64_t kModuleRegistrationOps = 2000;
constexpr std::uint64_t kIdentityOps = 20000;
constexpr std::uint64_t kCapabilityOps = 20000;
constexpr std::uint64_t kHealthOps = 20000;
constexpr std::uint64_t kCompatibilityOps = 20000;
constexpr std::uint64_t kSnapshotCycles = 50;
constexpr std::uint64_t kTransportOps = 2000;
constexpr std::uint64_t kModulesPerScenario = 100;
constexpr std::uint64_t kCompatibilityRules = 64;
constexpr std::uint64_t kSnapshotModules = 500;

struct Totals {
  std::uint64_t operations{0};
  std::uint64_t registries{0};
  std::uint64_t mutations{0};
  std::uint64_t digest_bytes{0};
  std::string digest;
  std::uint64_t final_generation{0};
  double seconds{0.0};
};

double seconds_between(const Clock::time_point& start, const Clock::time_point& finish) {
  return std::chrono::duration<double>(finish - start).count();
}

Provenance synthetic_provenance() {
  Provenance provenance;
  provenance.kind = trxreg::EvidenceKind::Synthetic;
  provenance.origin = "trxreg-bench";
  provenance.method = "generated";
  return provenance;
}

bool fail(const char* what, const Status& status) {
  std::fprintf(stderr, "trxreg_bench: %s failed: %s: %s\n", what,
               std::string(trxreg::to_string(status.code())).c_str(), status.message().c_str());
  return false;
}

template <class T>
bool take(Result<T>& result, const char* what, T& out) {
  if (!result.ok()) {
    return fail(what, Status(result.error()));
  }
  out = std::move(result.value());
  return true;
}

bool bench_source(Registry& registry, const char* name, AuthorityToken& authority) {
  SourceDescriptor descriptor;
  descriptor.name = name;
  descriptor.description = "synthetic benchmark source";
  descriptor.declared_kind = trxreg::EvidenceKind::Synthetic;
  descriptor.instance_id = "trxreg-bench";
  Result<SourceHandle> handle = registry.register_source(descriptor);
  SourceHandle value;
  if (!take(handle, "register_source", value)) {
    return false;
  }
  authority = value.authority();
  return true;
}

/// Print one scenario line: completed operations, elapsed wall time, and the
/// throughput that follows from them.
void print_scenario(const char* name, std::uint64_t operations, double seconds, std::uint64_t generation,
                    std::uint64_t bytes, bool has_bytes) {
  const double throughput = seconds > 0.0 ? static_cast<double>(operations) / seconds : 0.0;
  if (has_bytes) {
    std::printf("%-24s ops=%-7llu elapsed_ms=%-9.1f ops_per_sec=%-12.1f generation=%-8llu bytes=%llu\n", name,
                static_cast<unsigned long long>(operations), seconds * 1000.0, throughput,
                static_cast<unsigned long long>(generation), static_cast<unsigned long long>(bytes));
  } else {
    std::printf("%-24s ops=%-7llu elapsed_ms=%-9.1f ops_per_sec=%-12.1f generation=%llu\n", name,
                static_cast<unsigned long long>(operations), seconds * 1000.0, throughput,
                static_cast<unsigned long long>(generation));
  }
  std::fflush(stdout);
}

/// Every scenario commits into its own registry, so the closing summary names
/// the registry that holds the most committed work rather than the last one.
void account(Totals& totals, std::uint64_t operations, double seconds, const Registry& registry) {
  const std::uint64_t generation = registry.generation().value();
  totals.operations += operations;
  totals.seconds += seconds;
  totals.mutations += generation;
  ++totals.registries;
  if (generation >= totals.final_generation) {
    totals.final_generation = generation;
    totals.digest = registry.state_digest().to_hex();
  }
  totals.digest_bytes = sizeof(trxreg::Digest::bytes);
}

std::uint64_t file_size(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return 0;
  }
  std::uint64_t size = 0;
  if (std::fseek(file, 0, SEEK_END) == 0) {
    const long end = std::ftell(file);
    if (end > 0) {
      size = static_cast<std::uint64_t>(end);
    }
  }
  std::fclose(file);
  return size;
}

std::int64_t current_pid() {
#ifdef _WIN32
  return static_cast<std::int64_t>(::_getpid());
#else
  return static_cast<std::int64_t>(::getpid());
#endif
}

std::string temporary_path(const std::string& leaf) {
  const char* directory = std::getenv("TEMP");
  if (directory == nullptr) {
    directory = std::getenv("TMP");
  }
  if (directory == nullptr) {
    directory = std::getenv("TMPDIR");
  }
  std::string base = directory != nullptr ? std::string(directory) : std::string(".");
  if (!base.empty() && base.back() != '/' && base.back() != '\\') {
#ifdef _WIN32
    base.push_back('\\');
#else
    base.push_back('/');
#endif
  }
  return base + leaf;
}

/// Scenario 1: module registration, N=2000, AutoRetry.
bool scenario_module_registration(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-registration", authority)) {
    return false;
  }
  const Provenance provenance = synthetic_provenance();
  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kModuleRegistrationOps; ++index) {
    ModuleRegistration registration;
    Result<ModuleKey> key = ModuleKey::parse("bench/module/" + std::to_string(index), "module key");
    ModuleKey parsed;
    if (!take(key, "ModuleKey::parse", parsed)) {
      return false;
    }
    registration.key = parsed;
    registration.identity.push_back(IdentityFieldValue{IdentityField::Vendor, "", "Summon Software Labs"});
    registration.identity.push_back(IdentityFieldValue{IdentityField::PartNumber, "", "TRX-1000"});
    registration.intent = RegisterIntent::EnsureCurrent;
    registration.provenance = provenance;
    registration.policy = MutationPolicy::AutoRetry;
    Result<ModuleHandle> handle = registry.register_module(registration, authority);
    ModuleHandle registered;
    if (!take(handle, "register_module", registered)) {
      return false;
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("module_registration", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

/// Scenario 2: identity claims, N=20000 update_identity calls over 100 modules.
bool scenario_identity_claims(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-identity", authority)) {
    return false;
  }
  const Provenance provenance = synthetic_provenance();
  std::vector<ModuleHandle> modules;
  modules.reserve(static_cast<std::size_t>(kModulesPerScenario));
  for (std::uint64_t index = 0; index < kModulesPerScenario; ++index) {
    ModuleRegistration registration;
    Result<ModuleKey> key = ModuleKey::parse("bench/identity/" + std::to_string(index), "module key");
    ModuleKey parsed;
    if (!take(key, "ModuleKey::parse", parsed)) {
      return false;
    }
    registration.key = parsed;
    registration.identity.push_back(IdentityFieldValue{IdentityField::Vendor, "", "Summon Software Labs"});
    registration.intent = RegisterIntent::EnsureCurrent;
    registration.provenance = provenance;
    registration.policy = MutationPolicy::AutoRetry;
    Result<ModuleHandle> handle = registry.register_module(registration, authority);
    ModuleHandle registered;
    if (!take(handle, "register_module", registered)) {
      return false;
    }
    modules.push_back(registered);
  }
  const IdentityField fields[] = {IdentityField::Vendor, IdentityField::PartNumber, IdentityField::SerialNumber,
                                  IdentityField::Revision};
  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kIdentityOps; ++index) {
    const ModuleHandle& module = modules[static_cast<std::size_t>(index % kModulesPerScenario)];
    IdentityFieldValue value;
    value.field = fields[static_cast<std::size_t>((index / kModulesPerScenario) % 4)];
    value.value = "value-" + std::to_string(index);
    const Status status = registry.update_identity(authority, module, value, provenance, MutationPolicy::AutoRetry);
    if (!status.ok()) {
      return fail("update_identity", status);
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("identity_claims", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

/// A shared helper: a registry with the given number of modules, each carrying
/// one identity claim.
bool make_modules(Registry& registry, const AuthorityToken& authority, const std::string& prefix, std::uint64_t count,
                  std::vector<ModuleHandle>& out) {
  const Provenance provenance = synthetic_provenance();
  out.clear();
  out.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t index = 0; index < count; ++index) {
    ModuleRegistration registration;
    Result<ModuleKey> key = ModuleKey::parse(prefix + std::to_string(index), "module key");
    ModuleKey parsed;
    if (!take(key, "ModuleKey::parse", parsed)) {
      return false;
    }
    registration.key = parsed;
    registration.identity.push_back(IdentityFieldValue{IdentityField::Vendor, "", "Summon Software Labs"});
    registration.intent = RegisterIntent::EnsureCurrent;
    registration.provenance = provenance;
    registration.policy = MutationPolicy::AutoRetry;
    Result<ModuleHandle> handle = registry.register_module(registration, authority);
    ModuleHandle registered;
    if (!take(handle, "register_module", registered)) {
      return false;
    }
    out.push_back(registered);
  }
  return true;
}

/// Scenario 3: capability publication, N=20000 publish_capability calls.
bool scenario_capability_publication(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-capability", authority)) {
    return false;
  }
  std::vector<ModuleHandle> modules;
  if (!make_modules(registry, authority, "bench/capability/", kModulesPerScenario, modules)) {
    return false;
  }
  const Provenance provenance = synthetic_provenance();
  const CapabilityValue speeds = CapabilityValue::of_speed_classes({trxreg::SpeedClass::Gb100, trxreg::SpeedClass::Gb400});
  const CapabilityValue lanes = CapabilityValue::count(4);
  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kCapabilityOps; ++index) {
    const ModuleHandle& module = modules[static_cast<std::size_t>(index % kModulesPerScenario)];
    const bool even = ((index / kModulesPerScenario) % 2) == 0;
    const Status status = registry.publish_capability(authority, module, even ? CapabilityKey::SpeedClasses
                                                                            : CapabilityKey::LaneCount,
                                                      "", even ? speeds : lanes, provenance, MutationPolicy::AutoRetry);
    if (!status.ok()) {
      return fail("publish_capability", status);
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("capability_publication", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

/// Scenario 4: health ingestion, N=20000 ingest_health calls.
bool scenario_health_ingestion(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-health", authority)) {
    return false;
  }
  std::vector<ModuleHandle> modules;
  if (!make_modules(registry, authority, "bench/health/", kModulesPerScenario, modules)) {
    return false;
  }
  const Provenance provenance = synthetic_provenance();
  HealthThreshold threshold;
  threshold.metric = HealthMetric::TemperatureCelsius;
  threshold.lane = trxreg::kModuleLane;
  threshold.direction = trxreg::ThresholdDirection::Above;
  threshold.has_degraded = true;
  threshold.degraded_enter = 70.0;
  threshold.degraded_exit = 65.0;
  threshold.has_critical = true;
  threshold.critical_enter = 80.0;
  threshold.critical_exit = 75.0;
  threshold.escalate_after = 2;
  threshold.recover_after = 2;
  threshold.max_age_ns = 60'000'000'000LL;
  threshold.disagreement_tolerance = 1.0;
  threshold.provenance = provenance;
  const Status published = registry.publish_threshold(authority, threshold, MutationPolicy::AutoRetry);
  if (!published.ok()) {
    return fail("publish_threshold", published);
  }

  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kHealthOps; ++index) {
    const ModuleHandle& module = modules[static_cast<std::size_t>(index % kModulesPerScenario)];
    HealthSampleInput sample;
    sample.metric = HealthMetric::TemperatureCelsius;
    sample.lane = trxreg::kModuleLane;
    sample.presence = trxreg::SamplePresence::Present;
    sample.value = 40.0 + static_cast<double>(index % 100) * 0.01;
    sample.observed_at_wall_ns = 0;
    sample.observed_at_monotonic_ns = 0;
    sample.clock_domain = ClockDomainId{0};
    sample.provenance = provenance;
    const Status status = registry.ingest_health(authority, module, sample, MutationPolicy::AutoRetry);
    if (!status.ok()) {
      return fail("ingest_health", status);
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("health_ingestion", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

/// Scenario 5: compatibility decisions, N=20000 queries against 64 rules.
bool scenario_compatibility_decisions(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-compatibility", authority)) {
    return false;
  }
  std::vector<ModuleHandle> modules;
  if (!make_modules(registry, authority, "bench/compatibility/", 1, modules)) {
    return false;
  }
  const ModuleHandle& module = modules.front();
  const Provenance provenance = synthetic_provenance();
  const CapabilityValue speeds =
      CapabilityValue::of_speed_classes({trxreg::SpeedClass::Gb100, trxreg::SpeedClass::Gb400});
  const CapabilityValue lanes = CapabilityValue::count(4);
  Status status = registry.publish_capability(authority, module, CapabilityKey::SpeedClasses, "", speeds, provenance,
                                              MutationPolicy::AutoRetry);
  if (!status.ok()) {
    return fail("publish_capability", status);
  }
  status = registry.publish_capability(authority, module, CapabilityKey::LaneCount, "", lanes, provenance,
                                       MutationPolicy::AutoRetry);
  if (!status.ok()) {
    return fail("publish_capability", status);
  }
  Result<trxreg::PortKey> parsed_port = trxreg::PortKey::parse("bench/compatibility/port0", "port key");
  trxreg::PortKey port;
  if (!take(parsed_port, "PortKey::parse", port)) {
    return false;
  }
  status = registry.publish_port_capability(authority, port, CapabilityKey::SpeedClasses, "", speeds, provenance,
                                            MutationPolicy::AutoRetry);
  if (!status.ok()) {
    return fail("publish_port_capability", status);
  }
  status = registry.publish_port_capability(authority, port, CapabilityKey::LaneCount, "", lanes, provenance,
                                            MutationPolicy::AutoRetry);
  if (!status.ok()) {
    return fail("publish_port_capability", status);
  }

  for (std::uint64_t index = 0; index < kCompatibilityRules; ++index) {
    trxreg::Requirement module_requirement;
    module_requirement.subject = trxreg::RequirementSubject::Module;
    module_requirement.key = CapabilityKey::SpeedClasses;
    module_requirement.op = trxreg::RequirementOp::SupersetOf;
    module_requirement.operand = speeds;
    trxreg::Requirement port_requirement;
    port_requirement.subject = trxreg::RequirementSubject::Port;
    port_requirement.key = CapabilityKey::LaneCount;
    port_requirement.op = trxreg::RequirementOp::AtLeast;
    port_requirement.operand = lanes;
    trxreg::CompatRule rule;
    rule.name = "bench/rule/" + std::to_string(index);
    rule.requirements.push_back(module_requirement);
    rule.requirements.push_back(port_requirement);
    rule.verdict = trxreg::CompatVerdict::Compatible;
    rule.priority = static_cast<std::int32_t>(kCompatibilityRules - index);
    rule.rationale = "synthetic benchmark rule";
    rule.provenance = provenance;
    rule.enabled = true;
    Result<trxreg::CompatRuleHandle> published = registry.publish_rule(authority, rule, MutationPolicy::AutoRetry);
    trxreg::CompatRuleHandle handle;
    if (!take(published, "publish_rule", handle)) {
      return false;
    }
  }

  trxreg::CompatQuery query;
  query.port = port;
  query.uid = module.uid;
  query.incarnation = module.incarnation;
  query.require_latest_generation = false;
  query.explain = true;
  query.max_rules = 1024;
  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kCompatibilityOps; ++index) {
    Result<trxreg::CompatDecision> decision = registry.query_compatibility(query);
    trxreg::CompatDecision value;
    if (!take(decision, "query_compatibility", value)) {
      return false;
    }
    if (value.outcome != trxreg::CompatOutcome::Compatible) {
      std::fprintf(stderr, "trxreg_bench: query_compatibility returned an unexpected outcome\n");
      return false;
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("compatibility_decisions", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

/// Scenario 6: snapshot round trip, N=50 save+load cycles.
bool scenario_snapshot_round_trip(Totals& totals, const std::string& path) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-snapshot", authority)) {
    return false;
  }
  std::vector<ModuleHandle> modules;
  if (!make_modules(registry, authority, "bench/snapshot/", kSnapshotModules, modules)) {
    return false;
  }
  const std::uint64_t generation = registry.generation().value();
  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  std::uint64_t bytes = 0;
  for (std::uint64_t cycle = 0; cycle < kSnapshotCycles; ++cycle) {
    const Status saved = registry.save(path);
    if (!saved.ok()) {
      return fail("save", saved);
    }
    bytes = file_size(path);
    Registry reloaded{RegistryConfig{}, trxreg::make_system_clock()};
    Result<trxreg::LoadReport> loaded = reloaded.load(path);
    trxreg::LoadReport value;
    if (!take(loaded, "load", value)) {
      return false;
    }
    // Loading is a new registry incarnation, so a faithful round trip reports
    // the saved generation plus one.
    if (value.generation.value() != generation + 1) {
      std::fprintf(stderr, "trxreg_bench: reloaded generation %llu does not follow the saved generation %llu\n",
                   static_cast<unsigned long long>(value.generation.value()),
                   static_cast<unsigned long long>(generation));
      return false;
    }
    if (value.modules != kSnapshotModules) {
      std::fprintf(stderr, "trxreg_bench: reloaded module count %llu does not match %llu\n",
                   static_cast<unsigned long long>(value.modules),
                   static_cast<unsigned long long>(kSnapshotModules));
      return false;
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  print_scenario("snapshot_round_trip", completed, seconds, generation, bytes, true);
  account(totals, completed, seconds, registry);
  return true;
}

/// Scenario 7: loopback transport, 2000 sequential request/response round trips
/// against an in-process server on an ephemeral port.
bool scenario_loopback_transport(Totals& totals) {
  Registry registry{RegistryConfig{}, trxreg::make_system_clock()};
  AuthorityToken authority;
  if (!bench_source(registry, "bench-transport", authority)) {
    return false;
  }
  trxreg::wire::ServerOptions options;
  options.port = 0;
  options.bind_address = "127.0.0.1";
  options.max_connections = 4;
  trxreg::wire::Server server(registry, std::move(options));
  const Status started = server.start();
  if (!started.ok()) {
    return fail("server.start", started);
  }
  std::thread runner([&server]() { static_cast<void>(server.run()); });

  Result<trxreg::wire::Client> connected = trxreg::wire::Client::connect("127.0.0.1", server.port());
  if (!connected.ok()) {
    static_cast<void>(server.stop());
    runner.join();
    return fail("Client::connect", Status(connected.error()));
  }
  trxreg::wire::Client client = std::move(connected.value());

  const Clock::time_point start = Clock::now();
  std::uint64_t completed = 0;
  for (std::uint64_t index = 0; index < kTransportOps; ++index) {
    Result<Value> response = client.call("registry.stats", Value::object({}));
    Value value;
    if (!take(response, "registry.stats", value)) {
      static_cast<void>(client.close());
      static_cast<void>(server.stop());
      runner.join();
      return false;
    }
    ++completed;
  }
  const double seconds = seconds_between(start, Clock::now());
  static_cast<void>(client.close());
  static_cast<void>(server.stop());
  runner.join();
  print_scenario("loopback_transport", completed, seconds, registry.generation().value(), 0, false);
  account(totals, completed, seconds, registry);
  return true;
}

void print_header() {
  std::printf("trxreg_bench: Transceiver Registry benchmark (library %s)\n",
              std::string(trxreg::version_string()).c_str());
  std::printf("  ALL DATA IS SYNTHETIC: every module, claim, capability, sample and rule below is generated by\n");
  std::printf("  this program. No hardware was contacted and nothing here reflects hardware performance; the\n");
  std::printf("  numbers describe completed library work only, timed with std::chrono::steady_clock.\n");
  std::printf("  throughput is measured on committed, answered operations, never on submission latency.\n\n");
  std::fflush(stdout);
}

int run() {
  print_header();
  Totals totals;
  const std::string snapshot_path =
      temporary_path("trxreg-bench-snapshot-" + std::to_string(current_pid()) + ".trxr");
  if (!scenario_module_registration(totals)) {
    return 1;
  }
  if (!scenario_identity_claims(totals)) {
    return 1;
  }
  if (!scenario_capability_publication(totals)) {
    return 1;
  }
  if (!scenario_health_ingestion(totals)) {
    return 1;
  }
  if (!scenario_compatibility_decisions(totals)) {
    return 1;
  }
  if (!scenario_snapshot_round_trip(totals, snapshot_path)) {
    return 1;
  }
  if (!scenario_loopback_transport(totals)) {
    return 1;
  }
  std::remove(snapshot_path.c_str());
  std::printf("\n");
  std::printf("committed: operations=%llu mutations=%llu registries=%llu elapsed_s=%.1f state_digest_bytes=%llu "
              "largest_registry_generation=%llu state_digest=%s\n",
              static_cast<unsigned long long>(totals.operations),
              static_cast<unsigned long long>(totals.mutations),
              static_cast<unsigned long long>(totals.registries), totals.seconds,
              static_cast<unsigned long long>(totals.digest_bytes),
              static_cast<unsigned long long>(totals.final_generation), totals.digest.c_str());
  std::fflush(stdout);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  static_cast<void>(argv);
  if (argc > 1) {
    std::fprintf(stderr, "usage: trxreg_bench\n");
    return 2;
  }
  try {
    return run();
  } catch (const std::exception& error) {
    std::fprintf(stderr, "error: internal: %s\n", error.what());
    return 1;
  } catch (...) {
    std::fprintf(stderr, "error: internal: an unknown exception escaped the benchmark\n");
    return 1;
  }
}




