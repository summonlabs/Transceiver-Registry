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

IdentityFieldValue field(IdentityField which, const std::string& value) {
  IdentityFieldValue entry;
  entry.field = which;
  entry.value = value;
  return entry;
}

}  // namespace

// Two sources that disagree must both stay visible: the registry never lets one
// source silently overwrite another, and the consensus outcome says so.
TRXREG_TEST(identity_conflicting_sources_stay_visible) {
  Registry registry;
  const SourceHandle first = register_source(registry, "source-a");
  const SourceHandle second = register_source(registry, "source-b");
  const ModuleHandle module = register_module(registry, first.authority(), "chassis0/bay1", RegisterIntent::EnsureCurrent,
                                              "Acme Optics", "AO-400G-SR8", "SN-AAAA");

  REQUIRE_OK(registry.update_identity(second.authority(), module, field(IdentityField::SerialNumber, "SN-BBBB"),
                                      synthetic_provenance("vendor-tool", "decoded"), MutationPolicy::AutoRetry));

  const Result<IdentityView> view = registry.identity(module);
  REQUIRE_OK(view);
  const FieldConsensus* serial = view.value().find(IdentityField::SerialNumber);
  REQUIRE(serial != nullptr);
  CHECK(serial->outcome == ConsensusOutcome::Conflicting);
  CHECK(!serial->has_value);
  CHECK_EQ(serial->claims.size(), std::size_t{2});
  CHECK(view.value().any_conflict());
  CHECK_EQ(view.value().conflicting_fields, std::uint32_t{1});

  // Both claims, with their provenance, are still individually inspectable.
  bool saw_first = false;
  bool saw_second = false;
  for (const IdentityClaim& claim : serial->claims) {
    if (claim.source == first.id) {
      saw_first = claim.value == "SN-AAAA";
      CHECK(claim.provenance.origin == "eeprom-page0");
    }
    if (claim.source == second.id) {
      saw_second = claim.value == "SN-BBBB";
      CHECK(claim.provenance.origin == "vendor-tool");
    }
  }
  CHECK(saw_first);
  CHECK(saw_second);

  // A third source agreeing with one of them does not erase the conflict.
  const SourceHandle third = register_source(registry, "source-c");
  REQUIRE_OK(registry.update_identity(third.authority(), module, field(IdentityField::SerialNumber, "SN-BBBB"),
                                      synthetic_provenance("field-audit", "read"), MutationPolicy::AutoRetry));
  const Result<IdentityView> again = registry.identity(module);
  REQUIRE_OK(again);
  const FieldConsensus* serial_again = again.value().find(IdentityField::SerialNumber);
  REQUIRE(serial_again != nullptr);
  CHECK(serial_again->outcome == ConsensusOutcome::Conflicting);
  CHECK_EQ(serial_again->claims.size(), std::size_t{3});
}

// A source may revise its own claim; the revision supersedes it without hiding it.
TRXREG_TEST(identity_self_revision_supersedes_without_hiding) {
  Registry registry;
  const SourceHandle source = register_source(registry, "source-a");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay2");
  REQUIRE_OK(registry.update_identity(source.authority(), module, field(IdentityField::FirmwareVersion, "1.0.0"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.update_identity(source.authority(), module, field(IdentityField::FirmwareVersion, "1.0.1"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));

  const Result<IdentityView> view = registry.identity(module);
  REQUIRE_OK(view);
  const FieldConsensus* firmware = view.value().find(IdentityField::FirmwareVersion);
  REQUIRE(firmware != nullptr);
  CHECK(firmware->outcome == ConsensusOutcome::SingleSource);
  CHECK(firmware->has_value);
  CHECK_EQ(firmware->value, std::string("1.0.1"));
  CHECK_EQ(firmware->claims.size(), std::size_t{1});
  CHECK_EQ(firmware->superseded_claims.size(), std::size_t{1});
  CHECK_EQ(firmware->superseded_claims.front().value, std::string("1.0.0"));
  CHECK(view.value().superseded_fields >= 1);

  ClaimQuery query;
  query.field = IdentityField::FirmwareVersion;
  query.include_superseded = true;
  const Result<std::vector<IdentityClaim>> history = registry.claim_history(module, query);
  REQUIRE_OK(history);
  REQUIRE(history.value().size() == 2);
  CHECK_EQ(history.value().front().value, std::string("1.0.0"));
  CHECK(!history.value().front().live);
  CHECK_EQ(history.value().back().value, std::string("1.0.1"));
  CHECK(history.value().back().live);

  // Without superseded history only the current claim is returned.
  ClaimQuery current_only;
  current_only.field = IdentityField::FirmwareVersion;
  const Result<std::vector<IdentityClaim>> live = registry.claim_history(module, current_only);
  REQUIRE_OK(live);
  REQUIRE(live.value().size() == 1);
  CHECK_EQ(live.value().front().value, std::string("1.0.1"));
}

// Re-registering a source name mints a new incarnation; the previous epoch's
// claims stop deciding anything but remain in history.
TRXREG_TEST(identity_retired_source_epoch_is_fenced_not_deleted) {
  Registry registry;
  const SourceHandle first = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, first.authority(), "chassis0/bay3");
  REQUIRE_OK(registry.update_identity(first.authority(), module, field(IdentityField::Vendor, "Acme Optics"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));

  // A different agent incarnation reusing the name mints a new epoch; the
  // helper's instance id is derived from the name, so registering under a new
  // instance id is exactly that case.
  SourceDescriptor descriptor;
  descriptor.name = "probe-agent";
  descriptor.description = "synthetic test source";
  descriptor.declared_kind = EvidenceKind::Synthetic;
  descriptor.instance_id = "probe-agent-restarted";
  const Result<SourceHandle> restarted = registry.register_source(descriptor);
  REQUIRE_OK(restarted);
  const SourceHandle second = restarted.value();
  CHECK(second.id == first.id);
  CHECK(second.epoch != first.epoch);
  CHECK(second.epoch.value() > first.epoch.value());

  // The old authority token is refused outright.
  REQUIRE_FAILS(registry.update_identity(first.authority(), module, field(IdentityField::Vendor, "Other Vendor"),
                                         synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry),
                StatusCode::StaleAuthority);

  const Result<IdentityView> view = registry.identity(module);
  REQUIRE_OK(view);
  const FieldConsensus* vendor = view.value().find(IdentityField::Vendor);
  REQUIRE(vendor != nullptr);
  CHECK(vendor->outcome == ConsensusOutcome::Superseded);
  CHECK(!vendor->has_value);
  // Every claim of the retired epoch is fenced, including the one written at
  // registration time; none of them decides the current value.
  REQUIRE(!vendor->superseded_claims.empty());
  for (const IdentityClaim& claim : vendor->superseded_claims) {
    CHECK(!claim.live);
    CHECK_EQ(claim.source_epoch, first.epoch);
  }

  REQUIRE_OK(registry.update_identity(second.authority(), module, field(IdentityField::Vendor, "Acme Optics"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));
  const Result<IdentityView> revised = registry.identity(module);
  REQUIRE_OK(revised);
  const FieldConsensus* vendor_again = revised.value().find(IdentityField::Vendor);
  REQUIRE(vendor_again != nullptr);
  CHECK(vendor_again->outcome == ConsensusOutcome::SingleSource);
  CHECK_EQ(vendor_again->value, std::string("Acme Optics"));
  CHECK(!vendor_again->superseded_claims.empty());
}

// Reconnecting with the same instance id renews the source instead of fencing
// its earlier claims; a different instance id fences them.
TRXREG_TEST(identity_source_renewal_keeps_claims_live) {
  Registry registry;
  const SourceHandle first = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, first.authority(), "chassis0/bay10");
  REQUIRE_OK(registry.update_identity(first.authority(), module, field(IdentityField::Vendor, "Acme Optics"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));

  SourceDescriptor renewal;
  renewal.name = "probe-agent";
  renewal.description = "the same agent reconnecting";
  renewal.declared_kind = EvidenceKind::Synthetic;
  renewal.instance_id = "probe-agent-instance";
  const Result<SourceHandle> renewed = registry.register_source(renewal);
  REQUIRE_OK(renewed);
  CHECK_EQ(renewed.value().epoch, first.epoch);
  CHECK_EQ(renewed.value().id, first.id);

  const Result<IdentityView> view = registry.identity(module);
  REQUIRE_OK(view);
  const FieldConsensus* vendor = view.value().find(IdentityField::Vendor);
  REQUIRE(vendor != nullptr);
  CHECK(vendor->outcome == ConsensusOutcome::SingleSource);
  CHECK_EQ(vendor->value, std::string("Acme Optics"));
  // The renewed authority is still accepted.
  REQUIRE_OK(registry.update_identity(renewed.value().authority(), module,
                                      field(IdentityField::FirmwareVersion, "3.0.0"),
                                      synthetic_provenance("eeprom-page0", "decoded"),
                                      MutationPolicy::AutoRetry));

  SourceDescriptor replacement;
  replacement.name = "probe-agent";
  replacement.description = "a different agent reusing the name";
  replacement.declared_kind = EvidenceKind::Synthetic;
  replacement.instance_id = "probe-agent-other";
  const Result<SourceHandle> fenced = registry.register_source(replacement);
  REQUIRE_OK(fenced);
  CHECK(fenced.value().epoch.value() > renewed.value().epoch.value());
  REQUIRE_FAILS(registry.update_identity(renewed.value().authority(), module,
                                         field(IdentityField::FirmwareVersion, "4.0.0"),
                                         synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry),
                StatusCode::StaleAuthority);
}

// A new physical module in the same position fences the previous incarnation.
TRXREG_TEST(identity_replacement_fences_previous_incarnation) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle original = register_module(registry, source.authority(), "chassis0/bay4", RegisterIntent::EnsureCurrent,
                                                "Acme Optics", "AO-400G-SR8", "SN-OLD1");
  REQUIRE_OK(registry.update_identity(source.authority(), original, field(IdentityField::FirmwareVersion, "2.0.0"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));

  const ModuleHandle replacement = register_module(registry, source.authority(), "chassis0/bay4",
                                                   RegisterIntent::NewIncarnation, "Other Vendor", "OV-100G-LR4",
                                                   "SN-NEW1");
  CHECK(replacement.uid == original.uid);
  CHECK(replacement.incarnation != original.incarnation);
  CHECK(replacement.incarnation.value() == original.incarnation.value() + 1);

  // The old handle is fenced: it cannot be queried, mutated, or attached.
  REQUIRE_FAILS(registry.identity(original), StatusCode::Fenced);
  REQUIRE_FAILS(registry.capabilities(original), StatusCode::Fenced);
  REQUIRE_FAILS(registry.health(original), StatusCode::Fenced);
  REQUIRE_FAILS(registry.evidence_summary(original), StatusCode::Fenced);
  REQUIRE_FAILS(registry.update_identity(source.authority(), original, field(IdentityField::Vendor, "Stale"),
                                         synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry),
                StatusCode::Fenced);

  // The replacement's identity is what the registry now reports.
  const Result<IdentityView> current = registry.identity(replacement);
  REQUIRE_OK(current);
  const FieldConsensus* serial = current.value().find(IdentityField::SerialNumber);
  REQUIRE(serial != nullptr);
  CHECK(serial->outcome == ConsensusOutcome::SingleSource);
  CHECK_EQ(serial->value, std::string("SN-NEW1"));
  CHECK_EQ(current.value().incarnation, replacement.incarnation);

  // History of the previous incarnation is still inspectable.
  ClaimQuery query;
  query.include_superseded = true;
  const Result<std::vector<IdentityClaim>> old_history = registry.claim_history(original, query);
  REQUIRE_OK(old_history);
  CHECK(old_history.value().size() >= 4);
  bool saw_firmware = false;
  for (const IdentityClaim& claim : old_history.value()) {
    CHECK_EQ(claim.incarnation, original.incarnation);
    if (claim.field == IdentityField::FirmwareVersion && claim.value == "2.0.0") {
      saw_firmware = true;
    }
  }
  CHECK(saw_firmware);

  // EnsureCurrent describes whichever incarnation currently occupies the key:
  // it lands on the replacement and never resurrects the fenced one.
  ModuleRegistration repeat;
  const Result<ModuleKey> repeat_key = ModuleKey::parse("chassis0/bay4", "module key");
  REQUIRE_OK(repeat_key);
  repeat.key = repeat_key.value();
  repeat.provenance = synthetic_provenance();
  repeat.policy = MutationPolicy::AutoRetry;
  const Result<ModuleHandle> again = registry.register_module(repeat, source.authority());
  REQUIRE_OK(again);
  CHECK_EQ(again.value().incarnation, replacement.incarnation);

  // A retired key cannot be re-registered implicitly: that requires an explicit
  // new incarnation, because the physical module is gone.
  REQUIRE_OK(registry.transition(source.authority(), replacement, LifecycleState::Retired, "end of life",
                                 MutationPolicy::AutoRetry));
  REQUIRE_FAILS(registry.register_module(repeat, source.authority()), StatusCode::StaleIncarnation);
}

// Identity digests are a stable function of the recorded claims.
TRXREG_TEST(identity_digest_is_stable_and_content_addressed) {
  Registry registry;
  const SourceHandle source = register_source(registry, "source-a");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay5");
  const Result<IdentityView> before = registry.identity(module);
  REQUIRE_OK(before);
  const Result<IdentityView> before_again = registry.identity(module);
  REQUIRE_OK(before_again);
  CHECK_EQ(before.value().digest.to_hex(), before_again.value().digest.to_hex());

  REQUIRE_OK(registry.update_identity(source.authority(), module, field(IdentityField::Vendor, "Acme Optics"),
                                      synthetic_provenance("eeprom-page0", "decoded"), MutationPolicy::AutoRetry));
  const Result<IdentityView> after = registry.identity(module);
  REQUIRE_OK(after);
  CHECK(before.value().digest != after.value().digest);
}

// Bounded identity history: the claim budget is enforced instead of growing.
TRXREG_TEST(identity_claim_budget_is_bounded) {
  RegistryConfig config;
  config.max_claims_per_module = 2;
  config.max_claim_history = 1;
  Registry registry(config);
  const SourceHandle source = register_source(registry, "source-a");

  ModuleRegistration registration;
  const Result<ModuleKey> key = ModuleKey::parse("chassis0/bay6", "module key");
  REQUIRE_OK(key);
  registration.key = key.value();
  (void)0;
  registration.provenance = synthetic_provenance();
  registration.policy = MutationPolicy::AutoRetry;
  const Result<ModuleHandle> module = registry.register_module(registration, source.authority());
  REQUIRE_OK(module);

  REQUIRE_OK(registry.update_identity(source.authority(), module.value(), field(IdentityField::Vendor, "A"),
                                      synthetic_provenance(), MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.update_identity(source.authority(), module.value(), field(IdentityField::PartNumber, "B"),
                                      synthetic_provenance(), MutationPolicy::AutoRetry));
  // The third distinct attribute cannot be retained: every stored claim is live.
  REQUIRE_FAILS(registry.update_identity(source.authority(), module.value(), field(IdentityField::SerialNumber, "C"),
                                         synthetic_provenance(), MutationPolicy::AutoRetry),
                StatusCode::CapacityExceeded);
}
