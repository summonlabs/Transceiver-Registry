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

// Loopback transport walkthrough of the Transceiver Registry.
//
// A wire::Server is bound to an ephemeral loopback port in this process with a
// bounded connection budget, a wire::Client drives a complete session over real
// sockets (source, module, capabilities, telemetry, a compatibility decision,
// and a snapshot written by the server), and every response document is printed
// as JSON. Every step reports its failures with a classified status code, and
// one deliberate refusal is exercised so the classified error path is visible
// rather than assumed.
//
// The server-side registry runs on a ManualClock, so the snapshot and the
// decision timestamps are deterministic.

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/snapshot.hpp"
#include "trxreg/taxonomy.hpp"
#include "trxreg/wire.hpp"

namespace {

using namespace trxreg;

constexpr WallNs kStartWallNs = 1'767'225'600'000'000'000LL;
constexpr ClockDomainId kClockDomain{23};

/// Snapshot written by the server, relative to the working directory.
constexpr char kSnapshotPath[] = "trxreg_transport_example.snapshot";

/// The wire protocol names operations and parameters as text but carries enums
/// as their numeric values; these two renderings come from compatibility.hpp,
/// which publishes no name table for them.
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

void print(std::string_view text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
}

int fail(std::string_view step, const Error& error) {
  std::string text = "transport_example: ";
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

/// Provenance as it travels on the wire: exactly the fields the codec reads.
Value provenance_document() {
  return Value::object({
      {"capture_ref", Value::text("")},
      {"content_digest", Value::text(Digest::zero().to_hex())},
      {"kind", Value::integer(static_cast<std::int64_t>(EvidenceKind::Synthetic))},
      {"method", Value::text("read")},
      {"origin", Value::text("wire-example")},
  });
}

Value handle_document(std::int64_t uid, std::int64_t incarnation, std::int64_t generation, std::string key) {
  return Value::object({
      {"generation", Value::integer(generation)},
      {"incarnation", Value::integer(incarnation)},
      {"key", Value::text(std::move(key))},
      {"uid", Value::integer(uid)},
  });
}

Value authority_document(std::int64_t source, std::int64_t epoch) {
  return Value::object({
      {"epoch", Value::integer(epoch)},
      {"source", Value::integer(source)},
  });
}

Result<std::int64_t> member_integer(const Value& document, std::string_view key) {
  const Value* field = document.find(key);
  if (field == nullptr || !field->is_integer()) {
    return make_error(StatusCode::Malformed, "the response document has no integer field '" + std::string(key) + "'");
  }
  return field->as_integer();
}

Result<std::string> member_text(const Value& document, std::string_view key) {
  const Value* field = document.find(key);
  if (field == nullptr || !field->is_text()) {
    return make_error(StatusCode::Malformed, "the response document has no text field '" + std::string(key) + "'");
  }
  return field->as_text();
}

/// Capability values are canonically encoded structures; the public
/// writer/reader pair produces exactly the document the server decodes.
Result<Value> capability_value_document(const CapabilityValue& value) {
  CanonicalWriter writer;
  write_canonical(writer, value);
  CanonicalReader reader(writer.bytes(), CanonicalLimits::request());
  return reader.read_document();
}

/// Stops the server and joins its accept loop on every exit path, so a failure
/// never leaves a thread blocked on a listener.
struct ServerGuard {
  wire::Server& server;
  std::thread& accept_thread;

  ~ServerGuard() {
    static_cast<void>(server.stop());
    if (accept_thread.joinable()) {
      accept_thread.join();
    }
  }
};

/// Everything the client asks the server to do, in order.
Status drive_session(wire::Client& client, const Value& authority, const Value& module, std::string_view port_key,
                     WallNs observed_at_wall_ns) {
  TRXREG_TRY_ASSIGN(hello, client.hello(1));
  print("[1] hello -> " + hello.to_json());

  TRXREG_TRY_ASSIGN(media_class_value, capability_value_document(CapabilityValue::of(MediaClass::MultimodeFiber)));
  TRXREG_TRY_ASSIGN(module_media,
                    client.call("capability.publish",
                                Value::object({
                                    {"authority", authority},
                                    {"key", Value::text("media_class")},
                                    {"module", module},
                                    {"policy", Value::text("auto_retry")},
                                    {"provenance", provenance_document()},
                                    {"subkey", Value::text("")},
                                    {"value", media_class_value},
                                })));
  print("[2] capability.publish media_class -> " + module_media.to_json());

  TRXREG_TRY_ASSIGN(lane_count_value, capability_value_document(CapabilityValue::count(8)));
  TRXREG_TRY_ASSIGN(module_lanes,
                    client.call("capability.publish",
                                Value::object({
                                    {"authority", authority},
                                    {"key", Value::text("lane_count")},
                                    {"module", module},
                                    {"policy", Value::text("auto_retry")},
                                    {"provenance", provenance_document()},
                                    {"subkey", Value::text("")},
                                    {"value", lane_count_value},
                                })));
  print("[3] capability.publish lane_count -> " + module_lanes.to_json());

  TRXREG_TRY_ASSIGN(connector_value, capability_value_document(CapabilityValue::of(ConnectorClass::Mpo16)));
  TRXREG_TRY_ASSIGN(port_media,
                    client.call("port.capability.publish",
                                Value::object({
                                    {"authority", authority},
                                    {"key", Value::text("media_class")},
                                    {"port", Value::text(std::string(port_key))},
                                    {"policy", Value::text("auto_retry")},
                                    {"provenance", provenance_document()},
                                    {"subkey", Value::text("")},
                                    {"value", media_class_value},
                                })));
  print("[4] port.capability.publish media_class -> " + port_media.to_json());

  TRXREG_TRY_ASSIGN(port_connector,
                    client.call("port.capability.publish",
                                Value::object({
                                    {"authority", authority},
                                    {"key", Value::text("connector_class")},
                                    {"port", Value::text(std::string(port_key))},
                                    {"policy", Value::text("auto_retry")},
                                    {"provenance", provenance_document()},
                                    {"subkey", Value::text("")},
                                    {"value", connector_value},
                                })));
  print("[5] port.capability.publish connector_class -> " + port_connector.to_json());

  const Value sample = Value::object({
      {"clock_domain", Value::integer(0)},
      {"lane", Value::integer(static_cast<std::int64_t>(kModuleLane))},
      {"metric", Value::integer(static_cast<std::int64_t>(HealthMetric::TemperatureCelsius))},
      {"observed_at_monotonic_ns", Value::integer(0)},
      {"observed_at_wall_ns", Value::integer(observed_at_wall_ns)},
      {"presence", Value::integer(static_cast<std::int64_t>(SamplePresence::Present))},
      {"provenance", provenance_document()},
      {"value", Value::real(64.25)},
  });
  TRXREG_TRY_ASSIGN(sample_ingested,
                    client.call("health.ingest",
                                Value::object({
                                    {"authority", authority},
                                    {"module", module},
                                    {"policy", Value::text("auto_retry")},
                                    {"sample", sample},
                                })));
  print("[6] health.ingest -> " + sample_ingested.to_json());

  // The deciding rule travels as a canonical document too, so the answer is
  // determined by published knowledge rather than by the example's hope.
  TRXREG_TRY_ASSIGN(lane_operand, capability_value_document(CapabilityValue::count(1)));
  const Value requirement = Value::object({
      {"key", Value::integer(static_cast<std::int64_t>(CapabilityKey::LaneCount))},
      {"note", Value::text("at least one lane")},
      {"op", Value::integer(static_cast<std::int64_t>(RequirementOp::AtLeast))},
      {"operand", lane_operand},
      {"subject", Value::integer(static_cast<std::int64_t>(RequirementSubject::Module))},
      {"subkey", Value::text("")},
  });
  const Value rule = Value::object({
      {"enabled", Value::boolean(true)},
      {"name", Value::text("transport-example-allow")},
      {"priority", Value::integer(10)},
      {"provenance", provenance_document()},
      {"rationale", Value::text("a module with at least one lane is usable")},
      {"requirements", Value::array({requirement})},
      {"verdict", Value::integer(static_cast<std::int64_t>(CompatVerdict::Compatible))},
  });
  TRXREG_TRY_ASSIGN(rule_published, client.call("compat.rule.publish",
                                                Value::object({
                                                    {"authority", authority},
                                                    {"policy", Value::text("auto_retry")},
                                                    {"rule", rule},
                                                })));
  print("[7] compat.rule.publish -> " + rule_published.to_json());

  TRXREG_TRY_ASSIGN(uid, member_integer(module, "uid"));
  TRXREG_TRY_ASSIGN(incarnation, member_integer(module, "incarnation"));
  TRXREG_TRY_ASSIGN(decision,
                    client.call("compat.query",
                                Value::object({
                                    {"explain", Value::boolean(true)},
                                    {"incarnation", Value::integer(incarnation)},
                                    {"port", Value::text(std::string(port_key))},
                                    {"require_latest_generation", Value::boolean(false)},
                                    {"uid", Value::integer(uid)},
                                })));
  print("[8] compat.query -> " + decision.to_json());
  TRXREG_TRY_ASSIGN(decision_outcome, member_integer(decision, "outcome"));
  TRXREG_TRY_ASSIGN(decision_closure, member_integer(decision, "closure"));
  TRXREG_TRY_ASSIGN(decision_digest, member_text(decision, "decision_digest"));
  print("    decision outcome=" + std::string(outcome_name(static_cast<CompatOutcome>(decision_outcome))) +
        " closure=" + std::string(closure_name(static_cast<KnowledgeClosure>(decision_closure))) +
        " decision_digest=" + decision_digest);
  if (decision_outcome != static_cast<std::int64_t>(CompatOutcome::Compatible) ||
      decision_closure != static_cast<std::int64_t>(KnowledgeClosure::Closed)) {
    return Status(StatusCode::Internal, "the published allow rule should have decided this pair as compatible");
  }

  TRXREG_TRY_ASSIGN(saved, client.call("registry.save", Value::object({
                                                                    {"path", Value::text(kSnapshotPath)},
                                                                })));
  print("[9] registry.save -> " + saved.to_json());

  // A deliberate refusal: the classified error path, not a crash and not a
  // silent success.
  const Result<Value> refused = client.call("registry.snapshot_meta", Value::object({}));
  if (refused.ok()) {
    return Status(StatusCode::Internal, "an unknown operation must be refused");
  }
  print("[10] registry.snapshot_meta refused -> code=" + std::string(to_string(refused.error().code)) +
        " message=" + refused.error().message);
  return ok_status();
}

int run() {
  const auto clock = std::make_shared<ManualClock>(kStartWallNs, kClockDomain);
  Registry registry{RegistryConfig{}, clock};

  print("Transceiver Registry - transport example");
  print("clock: ManualClock domain=" + std::to_string(kClockDomain.value()) +
        " start_wall_ns=" + std::to_string(kStartWallNs));

  wire::ServerOptions options;
  options.port = 0;
  options.bind_address = "127.0.0.1";
  options.max_connections = 4;
  options.max_requests_per_connection = 64;
  wire::Server server{registry, options};

  const Status start_status = server.start();
  if (!start_status.ok()) {
    return fail("wire::Server::start", start_status.error());
  }
  std::thread accept_thread([&server]() { static_cast<void>(server.run()); });
  const ServerGuard guard{server, accept_thread};
  print("[0] server listening on 127.0.0.1:" + std::to_string(server.port()) +
        " (ephemeral port, max_connections=4)");

  Result<wire::Client> client_result = wire::Client::connect("127.0.0.1", server.port());
  if (!client_result.ok()) {
    return fail("wire::Client::connect", client_result.error());
  }
  wire::Client& client = client_result.value();

  const Result<Value> source = client.call("source.register",
                                           Value::object({
                                               {"description", Value::text("loopback client of the transport example")},
                                               {"instance_id", Value::text("transport-example/run-1")},
                                               {"kind", Value::text("synthetic")},
                                               {"name", Value::text("transport-example")},
                                           }));
  if (!source.ok()) {
    return fail("source.register", source.error());
  }
  print("[0] source.register -> " + source.value().to_json());
  const Result<std::int64_t> source_id = member_integer(source.value(), "id");
  const Result<std::int64_t> source_epoch = member_integer(source.value(), "epoch");
  if (!source_id.ok() || !source_epoch.ok()) {
    return fail("source.register response", Error{StatusCode::Malformed, "the source handle document is incomplete"});
  }
  const Value authority = authority_document(source_id.value(), source_epoch.value());

  const Value identity_vendor = Value::object({
      {"field", Value::integer(static_cast<std::int64_t>(IdentityField::Vendor))},
      {"subkey", Value::text("")},
      {"value", Value::text("Acme Optics")},
  });
  const Value identity_part = Value::object({
      {"field", Value::integer(static_cast<std::int64_t>(IdentityField::PartNumber))},
      {"subkey", Value::text("")},
      {"value", Value::text("AO-400G-SR8")},
  });
  constexpr char kModuleKey[] = "chassis0/bay4/module0";
  const Result<Value> module = client.call("module.register",
                                           Value::object({
                                               {"authority", authority},
                                               {"expected_generation", Value::integer(0)},
                                               {"identity", Value::array({identity_vendor, identity_part})},
                                               {"intent", Value::text("current")},
                                               {"key", Value::text(kModuleKey)},
                                               {"policy", Value::text("auto_retry")},
                                               {"provenance", provenance_document()},
                                           }));
  if (!module.ok()) {
    return fail("module.register", module.error());
  }
  print("[0] module.register -> " + module.value().to_json());
  const Result<std::int64_t> uid = member_integer(module.value(), "uid");
  const Result<std::int64_t> incarnation = member_integer(module.value(), "incarnation");
  const Result<std::int64_t> generation = member_integer(module.value(), "generation");
  if (!uid.ok() || !incarnation.ok() || !generation.ok()) {
    return fail("module.register response",
                Error{StatusCode::Malformed, "the module handle document is incomplete"});
  }
  const Value module_handle = handle_document(uid.value(), incarnation.value(), generation.value(), kModuleKey);

  const std::string port_key = "switch0/ethernet2/1";
  const Status session_status = drive_session(client, authority, module_handle, port_key, clock->wall_now_ns());
  if (!session_status.ok()) {
    return fail("client session", session_status.error());
  }

  // The snapshot the server wrote is a real, inspectable file.
  const Result<LoadReport> report = inspect_snapshot(kSnapshotPath);
  if (!report.ok()) {
    return fail("inspect_snapshot", report.error());
  }
  print("[11] inspect_snapshot('" + std::string(kSnapshotPath) + "') -> format_version=" +
        std::to_string(report.value().format_version) +
        " generation=" + std::to_string(report.value().generation.value()) +
        " modules=" + std::to_string(report.value().modules) +
        " sources=" + std::to_string(report.value().sources) +
        " claims=" + std::to_string(report.value().claims) +
        " declarations=" + std::to_string(report.value().declarations) +
        " samples=" + std::to_string(report.value().samples) +
        " content_digest=" + report.value().content_digest.to_hex());

  const Status close_status = client.close();
  if (!close_status.ok()) {
    return fail("client.close", close_status.error());
  }

  const Status stop_status = server.stop();
  if (!stop_status.ok()) {
    return fail("wire::Server::stop", stop_status.error());
  }
  if (accept_thread.joinable()) {
    accept_thread.join();
  }
  print("[12] server stopped cleanly: running=" + std::string(server.running() ? "true" : "false"));
  print("transport example completed");
  return 0;
}

}  // namespace

int main() { return run(); }
