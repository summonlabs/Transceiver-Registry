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

// Multi-process proof.
//
// The registry server runs as a separate OS process, reached over real loopback
// TCP with the framed transport. Threads are not used as a substitute anywhere
// here: the server is started, killed without warning, and restarted, and the
// only channel between the test and the server is the socket.

#include "child_process.hpp"
#include "registry_support.hpp"

#include "trxreg/version.hpp"
#include "trxreg/wire.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>

namespace {

using namespace trxreg;
using namespace trxreg::test;

// The suite launches the real server binary. When the tools are not part of the
// build there is nothing to launch, so the test reports that prerequisite
// explicitly rather than passing silently or failing to compile.
#if !defined(TRXREG_SERVER_EXECUTABLE)
#define TRXREG_MULTIPROCESS_UNAVAILABLE 1
#endif

Value codec_object(std::vector<Value::Member> members) { return Value::object(std::move(members)); }

/// Artifacts live under the OS temporary directory so a test run can never
/// leave files inside the source tree.
std::filesystem::path artifact(const std::string& name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "trxreg-tests";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / name;
}

Value authority_value(const AuthorityToken& authority) {
  return codec_object({{"epoch", Value::integer(static_cast<std::int64_t>(authority.epoch.value()))},
                       {"source", Value::integer(static_cast<std::int64_t>(authority.source.value()))}});
}

Value provenance_value(const char* origin) {
  return codec_object({{"capture_ref", Value::text("")},
                       {"content_digest", Value::text(Digest::zero().to_hex())},
                       {"kind", Value::integer(static_cast<std::int64_t>(EvidenceKind::Synthetic))},
                       {"method", Value::text("generated")},
                       {"origin", Value::text(origin)}});
}

/// Start the server binary, wait for its readiness line, and connect a client.
struct ServerProcess {
  ChildProcess child;
  wire::Client client;
  std::uint16_t port{0};
  std::string ready_file;
};

bool start_server(ServerProcess& server, const std::string& snapshot_path, const std::string& name) {
  server.ready_file = artifact(name + "-ready.txt").string();
  std::error_code error;
  std::filesystem::remove(server.ready_file, error);
  const std::string port_argument = "--port";
  const std::string ready_argument = "--ready-file";
  const std::string snapshot_argument = "--snapshot";
  std::string start_error;
  if (!server.child.start(TRXREG_SERVER_EXECUTABLE,
                          {"--port", "0", ready_argument, server.ready_file, snapshot_argument, snapshot_path},
                          start_error)) {
    report_failure(__FILE__, __LINE__, "server start failed: " + start_error);
    return false;
  }
  // The server may print informational lines (for example the load report of
  // the snapshot it restored) before announcing readiness; the readiness line
  // itself is the signal. A closed pipe always fails the test.
  const std::string marker = "READY port=";
  std::string line;
  std::size_t position = std::string::npos;
  for (int attempt = 0; attempt < 64; ++attempt) {
    std::string read_error;
    line = server.child.read_line(read_error);
    if (line.empty()) {
      report_failure(__FILE__, __LINE__, "server readiness failed: " + read_error);
      return false;
    }
    position = line.find(marker);
    if (position != std::string::npos) {
      break;
    }
  }
  if (position == std::string::npos) {
    report_failure(__FILE__, __LINE__, "the server never announced readiness");
    return false;
  }
  const std::string port_text = line.substr(position + marker.size());
  const long port = std::strtol(port_text.c_str(), nullptr, 10);
  if (port <= 0 || port > 65535) {
    report_failure(__FILE__, __LINE__, "server reported an unusable port: " + port_text);
    return false;
  }
  server.port = static_cast<std::uint16_t>(port);

  Result<wire::Client> client = wire::Client::connect("127.0.0.1", server.port);
  if (!client.ok()) {
    report_failure(__FILE__, __LINE__, std::string("client connect failed: ") +
                                          std::string(to_string(client.error().code)) + ": " +
                                          client.error().message);
    return false;
  }
  server.client = std::move(client.value());
  return true;
}

/// Call an operation over the loopback transport and return the result
/// document, reporting a classified failure through the harness.
Value call(wire::Client& client, const char* op, Value params) {
  const Result<Value> result = client.call(op, std::move(params));
  if (!result.ok()) {
    report_failure(__FILE__, __LINE__, std::string("transport call '") + op + "' failed: " +
                                          std::string(to_string(result.error().code)) + ": " + result.error().message);
    return Value::null();
  }
  return result.value();
}

/// Expect the operation to be refused with a specific classification.
void expect_refused(wire::Client& client, const char* op, Value params, StatusCode expected, const char* file,
                    int line) {
  const Result<Value> result = client.call(op, std::move(params));
  if (result.ok()) {
    report_failure(file, line, std::string("call '") + op + "' unexpectedly succeeded");
    return;
  }
  if (result.error().code != expected) {
    report_failure(file, line, std::string("call '") + op + "' failed with " +
                                   std::string(to_string(result.error().code)) + " instead of " +
                                   std::string(to_string(expected)) + ": " + result.error().message);
  }
}

#define EXPECT_REFUSED(client, op, params, code) expect_refused((client), (op), (params), (code), __FILE__, __LINE__)

std::uint64_t generation_of(wire::Client& client) {
  const Value result = call(client, "registry.generation", Value::object({}));
  const Value* field = result.find("generation");
  return field != nullptr && field->is_integer() ? static_cast<std::uint64_t>(field->as_integer()) : 0;
}

std::string identity_digest_of(wire::Client& client, ModuleUid uid, IncarnationId incarnation) {
  const Value result = call(client, "module.identity",
                            codec_object({{"incarnation", Value::integer(static_cast<std::int64_t>(incarnation.value()))},
                                          {"uid", Value::integer(static_cast<std::int64_t>(uid.value()))}}));
  const Value* digest = result.find("digest");
  return digest != nullptr && digest->is_text() ? digest->as_text() : std::string();
}

}  // namespace

#if defined(TRXREG_MULTIPROCESS_UNAVAILABLE)
TRXREG_TEST(multiprocess_publish_query_kill_restart) {
  report_failure(__FILE__, __LINE__,
                 "the multi-process proof needs the trxreg_server target: configure with TRXREG_BUILD_TOOLS=ON");
}
#else
TRXREG_TEST(multiprocess_publish_query_kill_restart) {
  const std::filesystem::path snapshot = artifact("multiprocess.trxr");
  std::error_code remove_error;
  std::filesystem::remove(snapshot, remove_error);

  // ---------------------------------------------------------------------
  // Phase 1: seed a snapshot in this process with the exact knowledge the
  // restarted server must still be able to explain.
  // ---------------------------------------------------------------------
  const auto clock = make_test_clock(WallNs{1'700'000'000'000'000'000LL}, ClockDomainId{101});
  SourceHandle source{};
  ModuleHandle module{};
  std::string identity_digest_before;
  {
    Registry registry({}, clock);
    source = register_source(registry, "probe-agent");
    module = register_module(registry, source.authority(), "chassis0/bay1");
    publish_capability(registry, source.authority(), module, CapabilityKey::MediaClass,
                       CapabilityValue::of(MediaClass::MultimodeFiber));
    publish_capability(registry, source.authority(), module, CapabilityKey::SpeedClasses,
                       CapabilityValue::of_speed_classes({SpeedClass::Gb400}));
    publish_port_capability(registry, source.authority(), "switch0/ethernet1/1", CapabilityKey::MediaClass,
                            CapabilityValue::of(MediaClass::MultimodeFiber));
    publish_threshold(registry, source.authority(), temperature_threshold(3'600'000'000'000LL));
    ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 41.0, clock->wall_now_ns());
    REQUIRE_OK(registry.publish_rule(
        source.authority(),
        allow_rule("allow-multimode", {module_requirement(CapabilityKey::MediaClass, RequirementOp::Equals,
                                                          CapabilityValue::of(MediaClass::MultimodeFiber))}),
        MutationPolicy::AutoRetry));
    const Result<IdentityView> view = registry.identity(module);
    REQUIRE_OK(view);
    identity_digest_before = view.value().digest.to_hex();
    REQUIRE_OK(registry.save(snapshot.string()));
  }

  // ---------------------------------------------------------------------
  // Phase 2: a real server process loads that snapshot and serves it.
  // ---------------------------------------------------------------------
  ServerProcess server;
  if (!start_server(server, snapshot.string(), "first")) {
    return;
  }
  note("multiprocess: server process serving on 127.0.0.1:" + std::to_string(server.port));

  const std::uint64_t generation_before = generation_of(server.client);
  CHECK(generation_before > 0);

  // The identity the seeding process recorded is visible from another process,
  // byte for byte: the digest matches what the first process computed.
  CHECK_EQ(identity_digest_of(server.client, module.uid, module.incarnation), identity_digest_before);

  // The compatibility rule and the capability declarations survived the process
  // boundary, so the decision is still decisive in the server process.
  const auto query_compatibility = [&](std::uint64_t expected_generation,
                                       bool require_latest) {
    return codec_object({{"expected_generation", Value::integer(static_cast<std::int64_t>(expected_generation))},
                         {"incarnation", Value::integer(static_cast<std::int64_t>(module.incarnation.value()))},
                         {"port", Value::text("switch0/ethernet1/1")},
                         {"require_latest_generation", Value::boolean(require_latest)},
                         {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}});
  };

  const Value decision = call(server.client, "compat.query", query_compatibility(0, false));
  const Value* outcome = decision.find("outcome");
  REQUIRE(outcome != nullptr);
  CHECK_EQ(outcome->as_integer(), static_cast<std::int64_t>(CompatOutcome::Compatible));

  // The authority minted before the restart belongs to the source incarnation
  // the snapshot carried forward, so it is still accepted: a snapshot restores
  // authority together with the knowledge it belongs to.
  const auto identity_update = [&](const AuthorityToken& token, const char* value) {
    return codec_object({{"authority", authority_value(token)},
                         {"field", Value::text("firmware_version")},
                         {"module",
                          codec_object({{"generation", Value::integer(0)},
                                        {"incarnation",
                                         Value::integer(static_cast<std::int64_t>(module.incarnation.value()))},
                                        {"key", Value::text("chassis0/bay1")},
                                        {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}})},
                         {"policy", Value::text("auto_retry")},
                         {"provenance", provenance_value("multi-process-client")},
                         {"value", Value::text(value)}});
  };
  call(server.client, "identity.update", identity_update(source.authority(), "1.2.3"));

  // A new incarnation of the source in this process fences the previous one.
  const auto register_source_over_wire = [&](wire::Client& client, const char* instance) {
    const Value registered = call(client, "source.register",
                                  codec_object({{"description", Value::text("multi-process client")},
                                                {"instance_id", Value::text(instance)},
                                                {"kind", Value::text("synthetic")},
                                                {"name", Value::text("probe-agent")}}));
    const Value* id = registered.find("id");
    const Value* epoch = registered.find("epoch");
    if (id == nullptr || epoch == nullptr) {
      report_failure(__FILE__, __LINE__, "source.register returned no authority");
      return AuthorityToken{};
    }
    return AuthorityToken{SourceId{static_cast<std::uint32_t>(id->as_integer())},
                          SourceEpoch{static_cast<std::uint32_t>(epoch->as_integer())}};
  };

  const AuthorityToken second_epoch = register_source_over_wire(server.client, "client-1");
  REQUIRE(second_epoch.source.valid());
  CHECK(second_epoch.epoch.value() > source.epoch.value());
  EXPECT_REFUSED(server.client, "identity.update", identity_update(source.authority(), "stale"),
                 StatusCode::StaleAuthority);
  call(server.client, "identity.update", identity_update(second_epoch, "9.9.9"));

  // The new incarnation republishes what it observes; the declarations of the
  // retired epoch are superseded, not merged.
  call(server.client, "capability.publish",
       codec_object({{"authority", authority_value(second_epoch)},
                     {"key", Value::text("media_class")},
                     {"module",
                      codec_object({{"generation", Value::integer(0)},
                                    {"incarnation",
                                     Value::integer(static_cast<std::int64_t>(module.incarnation.value()))},
                                    {"key", Value::text("chassis0/bay1")},
                                    {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}})},
                     {"policy", Value::text("auto_retry")},
                     {"provenance", provenance_value("multi-process-client")},
                     {"subkey", Value::text("")},
                     {"value", codec_object({{"i", Value::integer(static_cast<std::int64_t>(MediaClass::MultimodeFiber))},
                                             {"k", Value::text("enum")}})}}));

  // A measurement published by the client process, against the server's clock.
  call(server.client, "health.ingest",
       codec_object({{"authority", authority_value(second_epoch)},
                     {"module",
                      codec_object({{"generation", Value::integer(0)},
                                    {"incarnation",
                                     Value::integer(static_cast<std::int64_t>(module.incarnation.value()))},
                                    {"key", Value::text("chassis0/bay1")},
                                    {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}})},
                     {"policy", Value::text("auto_retry")},
                     {"sample", codec_object(
                                    {{"clock_domain", Value::integer(0)},
                                     {"lane", Value::integer(kModuleLane)},
                                     {"metric",
                                      Value::integer(static_cast<std::int64_t>(HealthMetric::TemperatureCelsius))},
                                     {"observed_at_monotonic_ns", Value::integer(0)},
                                     {"observed_at_wall_ns", Value::integer(0)},
                                     {"presence", Value::integer(static_cast<std::int64_t>(SamplePresence::Present))},
                                     {"provenance", provenance_value("multi-process-client")},
                                     {"value", Value::real(42.5)}})}}));

  // Flush the state synchronously, then kill the process outright.
  call(server.client, "registry.save", codec_object({{"path", Value::text(snapshot.string())}}));
  const std::uint64_t generation_at_kill = generation_of(server.client);
  CHECK(generation_at_kill > generation_before);
  static_cast<void>(server.client.close());
  CHECK(server.child.kill());
  CHECK(!server.child.running());

  // ---------------------------------------------------------------------
  // Phase 3: a brand new process loads the state the killed one left behind.
  // ---------------------------------------------------------------------
  ServerProcess restarted;
  if (!start_server(restarted, snapshot.string(), "second")) {
    return;
  }
  const std::uint64_t generation_after = generation_of(restarted.client);
  CHECK(generation_after > generation_at_kill);

  // The claims published by the killed process survived it.
  const Value identity = call(restarted.client, "module.identity",
                              codec_object({{"incarnation", Value::integer(static_cast<std::int64_t>(
                                                                module.incarnation.value()))},
                                            {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}}));
  const Value* fields = identity.find("fields");
  REQUIRE(fields != nullptr);
  bool saw_firmware = false;
  for (const Value& field_entry : fields->as_array()) {
    const Value* name = field_entry.find("field");
    const Value* value = field_entry.find("value");
    if (name != nullptr && value != nullptr && name->is_integer() &&
        name->as_integer() == static_cast<std::int64_t>(IdentityField::FirmwareVersion)) {
      saw_firmware = value->is_text() && value->as_text() == "9.9.9";
    }
  }
  CHECK(saw_firmware);

  // The measurement ingested before the kill is still fresh across the restart:
  // freshness follows the wall clock, not the lifetime of the process.
  const Value report = call(restarted.client, "health.report",
                            codec_object({{"incarnation", Value::integer(static_cast<std::int64_t>(
                                                             module.incarnation.value()))},
                                          {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}}));
  const Value* health_outcome = report.find("outcome");
  REQUIRE(health_outcome != nullptr);
  CHECK_EQ(health_outcome->as_integer(), static_cast<std::int64_t>(HealthOutcome::Fresh));

  // The decision is still decisive after the restart.
  const Value restarted_decision = call(restarted.client, "compat.query", query_compatibility(0, false));
  const Value* restarted_outcome = restarted_decision.find("outcome");
  REQUIRE(restarted_outcome != nullptr);
  CHECK_EQ(restarted_outcome->as_integer(), static_cast<std::int64_t>(CompatOutcome::Compatible));

  // The authority of the killed process is fenced once the restarted process
  // registers its own source incarnation.
  const AuthorityToken third_epoch = register_source_over_wire(restarted.client, "client-2");
  REQUIRE(third_epoch.source.valid());
  CHECK(third_epoch.epoch.value() > second_epoch.epoch.value());
  EXPECT_REFUSED(restarted.client, "identity.update", identity_update(second_epoch, "zombie"),
                 StatusCode::StaleAuthority);
  call(restarted.client, "identity.update", identity_update(third_epoch, "10.0.0"));

  // Replacing the module fences the evidence of the previous incarnation, and
  // the replacement starts with no evidence of its own.
  const Value replacement = call(
      restarted.client, "module.register",
      codec_object({{"authority", authority_value(third_epoch)},
                    {"expected_generation", Value::integer(0)},
                    {"identity", Value::array({codec_object(
                                     {{"field", Value::integer(static_cast<std::int64_t>(IdentityField::SerialNumber))},
                                      {"subkey", Value::text("")},
                                      {"value", Value::text("SN-REPLACEMENT")}})})},
                    {"intent", Value::text("new_incarnation")},
                    {"key", Value::text("chassis0/bay1")},
                    {"policy", Value::text("auto_retry")},
                    {"provenance", provenance_value("multi-process-client")}}));
  const Value* replacement_incarnation = replacement.find("incarnation");
  REQUIRE(replacement_incarnation != nullptr);
  CHECK(replacement_incarnation->as_integer() > static_cast<std::int64_t>(module.incarnation.value()));

  const Value replacement_report =
      call(restarted.client, "health.report",
           codec_object({{"incarnation", Value::integer(replacement_incarnation->as_integer())},
                         {"uid", Value::integer(static_cast<std::int64_t>(module.uid.value()))}}));
  const Value* replacement_outcome = replacement_report.find("outcome");
  REQUIRE(replacement_outcome != nullptr);
  CHECK(replacement_outcome->as_integer() != static_cast<std::int64_t>(HealthOutcome::Fresh));
  const Value* worst = replacement_report.find("worst");
  REQUIRE(worst != nullptr);
  CHECK_EQ(worst->as_integer(), static_cast<std::int64_t>(MetricState::Fenced));

  // A decision fenced against the generation the killed process reported is
  // refused by the restarted one.
  EXPECT_REFUSED(restarted.client, "compat.query", query_compatibility(generation_at_kill, true),
                 StatusCode::StaleGeneration);

  CHECK(restarted.child.kill());
}
#endif
