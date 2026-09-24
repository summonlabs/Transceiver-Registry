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

#include "trxreg/version.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace {

using namespace trxreg;
using namespace trxreg::test;

/// Artifacts live under the OS temporary directory so a test run can never
/// leave files inside the source tree.
std::filesystem::path artifact(const std::string& name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "trxreg-tests";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / name;
}

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::vector<std::byte> bytes;
  char buffer[4096];
  while (stream.read(buffer, sizeof(buffer)) || stream.gcount() > 0) {
    const std::streamsize count = stream.gcount();
    for (std::streamsize i = 0; i < count; ++i) {
      bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffer[i])));
    }
    if (count < static_cast<std::streamsize>(sizeof(buffer))) {
      break;
    }
  }
  return bytes;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

/// Build a state that exercises every record kind of the snapshot format.
struct Fixture {
  std::string key{"chassis0/bay1"};
  std::string port{"switch0/ethernet1/1"};
  std::string slot{"chassis0/slot1"};
  Digest identity_digest{};
  Digest capability_digest{};
};

Fixture populate(Registry& registry, const std::shared_ptr<ManualClock>& clock, const std::string& key_suffix = "") {
  Fixture fixture;
  fixture.key += key_suffix;
  const SourceHandle source = register_source(registry, "probe-agent" + key_suffix);
  const SourceHandle second = register_source(registry, "config-importer" + key_suffix);
  const ModuleHandle module = register_module(registry, source.authority(), fixture.key, RegisterIntent::EnsureCurrent,
                                              "Acme Optics", "AO-400G-SR8", "SN-1" + key_suffix);

  // A conflicting claim from a second source, so the reloaded state must still
  // report the conflict and keep both claims.
  TRXREG_FIXTURE_STATUS(registry.update_identity(second.authority(), module,
                                                IdentityFieldValue{IdentityField::SerialNumber, {}, "SN-2"},
                                                synthetic_provenance("vendor-tool", "decoded"),
                                                MutationPolicy::AutoRetry));

  publish_capability(registry, source.authority(), module, CapabilityKey::ModuleFamily,
                     CapabilityValue::of(ModuleFamily::OpticalTransceiver));
  publish_capability(registry, source.authority(), module, CapabilityKey::MediaClass,
                     CapabilityValue::of(MediaClass::MultimodeFiber));
  publish_capability(registry, source.authority(), module, CapabilityKey::SpeedClasses,
                     CapabilityValue::of_speed_classes({SpeedClass::Gb100, SpeedClass::Gb400}));
  publish_capability(registry, source.authority(), module, CapabilityKey::LaneCount, CapabilityValue::count(8));
  publish_capability(registry, source.authority(), module, CapabilityKey::TemperatureTelemetry,
                     CapabilityValue::boolean(true));
  publish_port_capability(registry, second.authority(), fixture.port, CapabilityKey::MediaClass,
                          CapabilityValue::of(MediaClass::MultimodeFiber));
  publish_port_capability(registry, second.authority(), fixture.port, CapabilityKey::SpeedClasses,
                          CapabilityValue::of_speed_classes({SpeedClass::Gb400}));

  const SlotKey slot = TRXREG_FIXTURE(SlotKey::parse(fixture.slot, "slot key"));
  TRXREG_FIXTURE(registry.attach(source.authority(), module, slot, 0, MutationPolicy::AutoRetry));

  publish_threshold(registry, source.authority(), temperature_threshold(3'600'000'000'000LL));
  ingest(registry, source.authority(), module, HealthMetric::TemperatureCelsius, 45.0, clock->wall_now_ns());

  TRXREG_FIXTURE(registry.publish_rule(
      source.authority(),
      allow_rule("allow-multimode", {module_requirement(CapabilityKey::MediaClass, RequirementOp::Equals,
                                                       CapabilityValue::of(MediaClass::MultimodeFiber))}),
      MutationPolicy::AutoRetry));

  const IdentityView identity = TRXREG_FIXTURE(registry.identity(module));
  fixture.identity_digest = identity.digest;
  const CapabilityView capabilities = TRXREG_FIXTURE(registry.capabilities(module));
  fixture.capability_digest = capabilities.digest;
  return fixture;
}

}  // namespace

// Everything the registry knows must survive a save/load cycle, including the
// conflicts, the provenance, and the attachments.
TRXREG_TEST(persistence_round_trip_preserves_knowledge) {
  const std::filesystem::path path = artifact("round-trip.trxr");
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{31});
  Fixture fixture;
  Digest state_digest{};
  RegistryStats before{};
  {
    Registry registry({}, clock);
    fixture = populate(registry, clock, "-a");
    before = registry.stats();
    state_digest = registry.state_digest();
    REQUIRE_OK(registry.save(path.string()));
  }

  const auto restarted = make_test_clock(kBaseWallNs + 1'000'000'000LL, ClockDomainId{32});
  Registry registry({}, restarted);
  const Result<LoadReport> loaded = registry.load(path.string());
  REQUIRE_OK(loaded);
  CHECK(!loaded.value().tail_recovered);
  CHECK_EQ(loaded.value().modules, std::uint64_t{1});
  CHECK_EQ(loaded.value().sources, std::uint64_t{2});
  CHECK_EQ(loaded.value().rules, std::uint64_t{1});
  CHECK_EQ(loaded.value().ports, std::uint64_t{1});
  CHECK_EQ(loaded.value().format_version, kSnapshotFormatVersion);
  CHECK(loaded.value().generation.value() > before.generation.value());

  const RegistryStats after = registry.stats();
  CHECK_EQ(after.modules, before.modules);
  CHECK_EQ(after.claims, before.claims);
  CHECK_EQ(after.declarations, before.declarations);
  CHECK_EQ(after.samples, before.samples);
  CHECK_EQ(after.rules, before.rules);
  CHECK_EQ(after.thresholds, before.thresholds);
  CHECK_EQ(after.ports, before.ports);
  CHECK_EQ(after.live_attachments, before.live_attachments);

  // Content-addressed identity survives persistence: the identity and capability
  // digests describe the same knowledge before and after the reload.
  const Result<IdentityView> identity = registry.identity_by_key(fixture.key);
  REQUIRE_OK(identity);
  CHECK_EQ(identity.value().digest.to_hex(), fixture.identity_digest.to_hex());
  CHECK(identity.value().any_conflict());
  CHECK_EQ(identity.value().conflicting_fields, std::uint32_t{1});
  ModuleHandle handle;
  handle.uid = identity.value().uid;
  handle.incarnation = identity.value().incarnation;
  handle.generation = identity.value().generation;
  handle.key = identity.value().key;
  const Result<CapabilityView> capabilities = registry.capabilities(handle);
  REQUIRE_OK(capabilities);
  CHECK_EQ(capabilities.value().digest.to_hex(), fixture.capability_digest.to_hex());

  // The attachment is still resolvable by slot.
  const Result<SlotKey> slot = SlotKey::parse(fixture.slot, "slot key");
  REQUIRE_OK(slot);
  const Result<AttachmentRecord> attachment = registry.attachment_of_slot(slot.value());
  REQUIRE_OK(attachment);
  CHECK_EQ(attachment.value().incarnation, handle.incarnation);

  // Compatibility is decidable again after the reload, with the same rule.
  CompatQuery query;
  query.port = TRXREG_FIXTURE(PortKey::parse(fixture.port, "port key"));
  query.uid = handle.uid;
  query.incarnation = handle.incarnation;
  query.require_latest_generation = false;
  const Result<CompatDecision> decision = registry.query_compatibility(query);
  REQUIRE_OK(decision);
  CHECK(decision.value().outcome == CompatOutcome::Compatible);
  CHECK_EQ(decision.value().matched_rules.size(), std::size_t{1});
  (void)state_digest;

  // A second save of the reloaded registry carries the same knowledge.
  const std::filesystem::path second = artifact("round-trip-2.trxr");
  REQUIRE_OK(registry.save(second.string()));
  const Result<LoadReport> replayed = inspect_snapshot(second.string());
  REQUIRE_OK(replayed);
  CHECK(!replayed.value().tail_recovered);
  CHECK_EQ(replayed.value().sources, std::uint64_t{2});
  CHECK(replayed.value().claims > 0);
}

// The system clock's domain is a 64-bit hash and therefore usually exceeds
// INT64_MAX. Everything that carries it must survive a snapshot round trip.
TRXREG_TEST(persistence_round_trip_with_system_clock_domain) {
  const std::filesystem::path path = artifact("system-clock.trxr");
  const ClockPtr clock = make_system_clock();
  CHECK(clock->domain().valid());
  if (clock->domain().value() <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    note("persistence: this process's clock domain fits in int64; the regression below is not exercised");
  }
  {
    Registry registry({}, clock);
    const SourceHandle source = register_source(registry, "system-clock-agent");
    const ModuleHandle module = register_module(registry, source.authority(), "chassis0/system");
    publish_capability(registry, source.authority(), module, CapabilityKey::LaneCount, CapabilityValue::count(4));
    HealthSampleInput sample;
    sample.metric = HealthMetric::TemperatureCelsius;
    sample.value = 45.0;
    sample.observed_at_wall_ns = clock->wall_now_ns();
    sample.provenance = synthetic_provenance("system-clock-agent");
    REQUIRE_OK(registry.ingest_health(source.authority(), module, sample, MutationPolicy::AutoRetry));
    REQUIRE_OK(registry.save(path.string()));
  }

  const Result<LoadReport> report = inspect_snapshot(path.string());
  REQUIRE_OK(report);
  CHECK_EQ(report.value().modules, std::uint64_t{1});
  CHECK_EQ(report.value().samples, std::uint64_t{1});
  Registry reloaded({}, make_system_clock());
  const Result<LoadReport> loaded = reloaded.load(path.string());
  REQUIRE_OK(loaded);
  const Result<IdentityView> view = reloaded.identity_by_key("chassis0/system");
  REQUIRE_OK(view);
  CHECK_EQ(view.value().incarnation, IncarnationId{1});
}

TRXREG_TEST(persistence_load_requires_an_empty_registry) {
  const std::filesystem::path path = artifact("empty-target.trxr");
  const auto clock = make_test_clock();
  {
    Registry registry({}, clock);
    populate(registry, clock, "-b");
    REQUIRE_OK(registry.save(path.string()));
  }
  Registry registry({}, clock);
  const SourceHandle source = register_source(registry, "other-agent");
  (void)source;
  REQUIRE_FAILS(registry.load(path.string()), StatusCode::Conflict);

  Registry fresh({}, clock);
  REQUIRE_FAILS(fresh.load(artifact("does-not-exist.trxr").string()), StatusCode::IoError);
}

// A damaged snapshot is rejected, and recovery drops the damaged tail instead
// of inventing state.
TRXREG_TEST(persistence_rejects_corruption_and_recovers_torn_tails) {
  const std::filesystem::path path = artifact("corruption.trxr");
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{41});
  {
    Registry registry({}, clock);
    populate(registry, clock, "-c");
    const SourceHandle extra = register_source(registry, "extra-agent");
    const ModuleHandle other = register_module(registry, extra.authority(), "chassis0/bay2", RegisterIntent::EnsureCurrent,
                                               "Acme Optics", "AO-100G-LR4", "SN-9");
    (void)other;
    REQUIRE_OK(registry.save(path.string()));
  }

  const std::vector<std::byte> original = read_bytes(path);
  REQUIRE(original.size() > 200);

  // Wrong magic.
  {
    std::vector<std::byte> damaged = original;
    damaged[0] = static_cast<std::byte>('X');
    const std::filesystem::path damaged_path = artifact("bad-magic.trxr");
    write_bytes(damaged_path, damaged);
    REQUIRE_FAILS(inspect_snapshot(damaged_path.string()), StatusCode::Corrupt);
  }

  // Unsupported format version.
  {
    std::vector<std::byte> damaged = original;
    damaged[8] = static_cast<std::byte>(0x7f);
    const std::filesystem::path damaged_path = artifact("bad-version.trxr");
    write_bytes(damaged_path, damaged);
    REQUIRE_FAILS(inspect_snapshot(damaged_path.string()), StatusCode::Unsupported);
  }

  // A single flipped byte inside the record stream: the record that contains it
  // and everything after it are dropped, and the load says so.
  {
    std::vector<std::byte> damaged = original;
    const std::size_t target = damaged.size() / 2;
    damaged[target] = static_cast<std::byte>(std::to_integer<std::uint8_t>(damaged[target]) ^ 0x5au);
    const std::filesystem::path damaged_path = artifact("bad-record.trxr");
    write_bytes(damaged_path, damaged);
    REQUIRE_FAILS(inspect_snapshot(damaged_path.string(), LoadOptions{false}), StatusCode::Corrupt);

    LoadOptions recover;
    recover.allow_tail_recovery = true;
    const Result<LoadReport> recovered = inspect_snapshot(damaged_path.string(), recover);
    REQUIRE_OK(recovered);
    CHECK(recovered.value().tail_recovered);
    CHECK(recovered.value().dropped_tail_bytes > 0);
    CHECK(!recovered.value().recovery_note.empty());
  }

  // Truncation at every record boundary: never a crash, always either a
  // classified rejection or an honest recovery report.
  for (std::size_t length = 40; length < original.size(); length += 37) {
    const std::vector<std::byte> truncated(original.begin(), original.begin() + static_cast<std::ptrdiff_t>(length));
    const std::filesystem::path truncated_path = artifact("truncated.trxr");
    write_bytes(truncated_path, truncated);

    LoadOptions strict;
    strict.allow_tail_recovery = false;
    const Result<LoadReport> rejected = inspect_snapshot(truncated_path.string(), strict);
    CHECK(!rejected.ok());

    LoadOptions recover;
    recover.allow_tail_recovery = true;
    const Result<LoadReport> recovered = inspect_snapshot(truncated_path.string(), recover);
    if (recovered.ok()) {
      CHECK(recovered.value().tail_recovered);
      CHECK(recovered.value().dropped_tail_bytes > 0);
    } else {
      // Rejection is also conservative: it never reports success.
      CHECK(recovered.error().code == StatusCode::Corrupt || recovered.error().code == StatusCode::Malformed);
    }
  }

  // Trailing garbage after a complete snapshot is refused rather than ignored.
  {
    std::vector<std::byte> extended = original;
    for (int i = 0; i < 32; ++i) {
      extended.push_back(static_cast<std::byte>(i));
    }
    const std::filesystem::path extended_path = artifact("trailing.trxr");
    write_bytes(extended_path, extended);
    REQUIRE_FAILS(inspect_snapshot(extended_path.string()), StatusCode::Corrupt);
  }

  // The intact snapshot still loads, so the damage above was the only difference.
  const Result<LoadReport> intact = inspect_snapshot(path.string());
  REQUIRE_OK(intact);
  CHECK_EQ(intact.value().modules, std::uint64_t{2});
}

// Autosave keeps a long-lived process recoverable: every committed mutation
// lands on disk.
TRXREG_TEST(persistence_autosave_tracks_committed_mutations) {
  const std::filesystem::path path = artifact("autosave.trxr");
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{51});
  {
    Registry registry({}, clock);
    REQUIRE_OK(registry.enable_autosave(path.string()));
    const SourceHandle source = register_source(registry, "autosave-agent");
    const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay7");
    (void)module;
    registry.disable_autosave();
    REQUIRE_OK(registry.enable_autosave(path.string()));
    const ModuleHandle second = register_module(registry, source.authority(), "chassis0/bay8");
    (void)second;
  }
  const Result<LoadReport> loaded = inspect_snapshot(path.string());
  REQUIRE_OK(loaded);
  CHECK_EQ(loaded.value().modules, std::uint64_t{2});
  CHECK_EQ(loaded.value().sources, std::uint64_t{1});
}

// Serialization is canonical: the same logical state produces the same digest,
// and the digest is stable across a save/load cycle of the same content.
TRXREG_TEST(persistence_state_digest_is_stable) {
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{61});
  Registry first({}, clock);
  const Fixture fixture_a = populate(first, clock, "-d");
  const Digest digest_a = first.state_digest();

  Registry second({}, clock);
  const Fixture fixture_b = populate(second, clock, "-d");
  const Digest digest_b = second.state_digest();
  CHECK_EQ(fixture_a.key, fixture_b.key);
  CHECK_EQ(digest_a.to_hex(), digest_b.to_hex());

  // A different logical state produces a different digest.
  Registry third({}, clock);
  const Fixture fixture_c = populate(third, clock, "-e");
  CHECK_NE(fixture_c.identity_digest.to_hex(), fixture_a.identity_digest.to_hex());
  CHECK_NE(third.state_digest().to_hex(), digest_a.to_hex());

  // Inspecting the same file twice yields the same content digest.
  const std::filesystem::path path = artifact("digest-stability.trxr");
  REQUIRE_OK(first.save(path.string()));
  const Result<LoadReport> one = inspect_snapshot(path.string());
  REQUIRE_OK(one);
  const Result<LoadReport> two = inspect_snapshot(path.string());
  REQUIRE_OK(two);
  CHECK_EQ(one.value().content_digest.to_hex(), two.value().content_digest.to_hex());
  CHECK(!one.value().content_digest.is_zero());
}

// Loading is a new registry incarnation: decisions fenced against the previous
// process are provably stale afterwards.
TRXREG_TEST(persistence_restart_fences_previous_generation) {
  const std::filesystem::path path = artifact("generation-fence.trxr");
  const auto clock = make_test_clock(kBaseWallNs, ClockDomainId{71});
  Generation generation_before{};
  {
    Registry registry({}, clock);
    populate(registry, clock, "-f");
    generation_before = registry.generation();
    REQUIRE_OK(registry.save(path.string()));
  }
  const auto restarted = make_test_clock(kBaseWallNs, ClockDomainId{72});
  Registry registry({}, restarted);
  REQUIRE_OK(registry.load(path.string()));
  CHECK(registry.generation().value() > generation_before.value());
  REQUIRE_FAILS(registry.verify_generation(generation_before), StatusCode::StaleGeneration);
  CHECK(registry.registry_incarnation() >= 2);
}
