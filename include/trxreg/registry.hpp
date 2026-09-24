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

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/health.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/lifecycle.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/result.hpp"
#include "trxreg/snapshot.hpp"
#include "trxreg/taxonomy.hpp"

// The Transceiver Registry runtime.
//
// Scope: authoritative identity, capability, health, compatibility, and
// lifecycle knowledge about transceiver modules and the host ports they attach
// to. Out of scope by design: optical path allocation, wavelength assignment,
// route planning, cable identity, and active hardware programming. This runtime
// never talks to hardware; every observation enters through these APIs with
// provenance, so REAL, SYNTHETIC, and UNSUPPORTED evidence stay distinguishable.

namespace trxreg {

/// Bounded resources. Every limit is enforced before allocation.
struct RegistryConfig {
  std::uint32_t max_sources{256};
  std::uint32_t max_modules{4096};
  std::uint32_t max_ports{4096};
  std::uint32_t max_rules{4096};
  std::uint32_t max_thresholds{4096};
  std::uint32_t max_attachments{4096};
  std::uint32_t max_claims_per_attribute{16};
  std::uint32_t max_claims_per_module{4096};
  std::uint32_t max_declarations_per_module{4096};
  std::uint32_t max_declarations_per_port{1024};
  std::uint32_t max_samples_per_series{256};
  std::uint32_t max_samples_per_module{65536};
  std::uint32_t max_claim_history{64};
  std::uint32_t max_lifecycle_history{64};
  /// Largest lane index accepted in a health sample.
  std::uint16_t max_lane_index{63};
  /// An observation timestamp further in the future than this is treated as
  /// implausible: the sample never becomes fresh evidence.
  WallNs max_future_skew_ns{5'000'000'000LL};
};

struct RegistryStats {
  friend bool operator==(const RegistryStats& lhs, const RegistryStats& rhs) noexcept = default;

  Generation generation{};
  std::uint32_t registry_incarnation{0};
  std::uint64_t sources{0};
  std::uint64_t modules{0};
  std::uint64_t incarnations{0};
  /// Module records that have had more than one incarnation, i.e. positions
  /// where a physical module was replaced at least once.
  std::uint64_t fenced_incarnations{0};
  std::uint64_t ports{0};
  std::uint64_t rules{0};
  std::uint64_t thresholds{0};
  std::uint64_t attachments{0};
  std::uint64_t live_attachments{0};
  std::uint64_t claims{0};
  std::uint64_t declarations{0};
  std::uint64_t samples{0};
  std::uint64_t mutations{0};
  /// Mutation attempts the registry refused after entering the mutation path:
  /// generation fences, state-machine refusals, and capacity limits. Arguments
  /// rejected by validation never reach that path and are not counted here.
  std::uint64_t refusals{0};
  std::uint64_t queries{0};
  std::uint64_t conflicts_observed{0};
  /// Digest of the canonical form of the entire registry state.
  Digest state_digest{};
};

/// Whether registering a module key continues the current incarnation or
/// declares a physical replacement.
enum class RegisterIntent : std::uint8_t {
  /// Create the module if absent; otherwise add this source's claims to the
  /// current incarnation. Never overwrites another source's claims.
  EnsureCurrent = 0,
  /// A different physical module now occupies this key. The previous
  /// incarnation is fenced: its evidence stops applying, and its record stays
  /// visible in history as Replaced.
  NewIncarnation,
};

struct ModuleRegistration {
  ModuleKey key{};
  std::vector<IdentityFieldValue> identity;
  RegisterIntent intent{RegisterIntent::EnsureCurrent};
  Provenance provenance{};
  MutationPolicy policy{MutationPolicy::RequireGeneration};
  /// Required with MutationPolicy::RequireGeneration.
  Generation expected_generation{};

  friend bool operator==(const ModuleRegistration& lhs, const ModuleRegistration& rhs) noexcept = default;
};

/// Where a module incarnation is attached.
struct AttachmentRecord {
  SlotKey slot{};
  std::uint32_t port_index{0};
  ModuleUid uid{};
  IncarnationId incarnation{};
  SourceId source{};
  SourceEpoch source_epoch{};
  Generation generation{};
  Sequence sequence{};
  WallNs attached_at_wall_ns{0};
  bool live{true};
  std::string note;

  friend bool operator==(const AttachmentRecord& lhs, const AttachmentRecord& rhs) noexcept = default;
};

struct SampleQuery {
  HealthMetric metric{HealthMetric::Unknown};  ///< Unknown selects every metric.
  std::uint16_t lane{kModuleLane};
  bool all_lanes{true};
  std::uint64_t limit{64};
  /// Include samples from fenced incarnations and retired epochs.
  bool include_superseded{false};
};

/// Implementation type of Registry, defined in the library. Held by pointer so
/// that no internal state appears in the installed headers.
struct RegistryImpl;
/// Internal accessor used by the persistence layer.
struct RegistryAccess;

struct ClaimQuery {
  IdentityField field{IdentityField::Unknown};  ///< Unknown selects every field.
  std::uint64_t limit{64};
  bool include_superseded{false};
};

struct DeclarationQuery {
  CapabilityKey key{CapabilityKey::Unknown};
  std::uint64_t limit{64};
  bool include_superseded{false};
};

/// A short digest-identified summary of the evidence supporting one module.
struct EvidenceSummary {
  ModuleUid uid{};
  IncarnationId incarnation{};
  Generation generation{};
  std::uint64_t live_claims{0};
  std::uint64_t superseded_claims{0};
  std::uint64_t live_declarations{0};
  std::uint64_t superseded_declarations{0};
  std::uint64_t live_samples{0};
  std::uint64_t stale_samples{0};
  std::uint64_t fenced_samples{0};
  std::uint32_t conflicting_attributes{0};
  WallNs oldest_sample_wall_ns{0};
  WallNs newest_sample_wall_ns{0};
  Digest digest{};

  friend bool operator==(const EvidenceSummary& lhs, const EvidenceSummary& rhs) noexcept = default;
};

/// The registry runtime. All public methods are thread-safe; no callback is
/// ever invoked while internal state is locked.
class Registry {
 public:
  explicit Registry(RegistryConfig config = {}, ClockPtr clock = nullptr);
  ~Registry();

  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  // -- sources ------------------------------------------------------------

  /// Register an evidence source. Re-registering the same name allocates a new
  /// epoch, which fences every authority token minted under the old one.
  Result<SourceHandle> register_source(const SourceDescriptor& descriptor, MutationPolicy policy = MutationPolicy::AutoRetry);
  Result<SourceHandle> source_handle(SourceId id) const;

  // -- module identity ----------------------------------------------------

  Result<ModuleHandle> register_module(const ModuleRegistration& registration,
                                       const AuthorityToken& authority);
  Status update_identity(const AuthorityToken& authority, const ModuleHandle& module, const IdentityFieldValue& value,
                         const Provenance& provenance, MutationPolicy policy = MutationPolicy::RequireGeneration);
  Result<IdentityView> identity(const ModuleHandle& module) const;
  Result<IdentityView> identity_by_key(std::string_view key) const;
  std::vector<ModuleHandle> modules() const;

  // -- capability ---------------------------------------------------------

  Status publish_capability(const AuthorityToken& authority, const ModuleHandle& module, CapabilityKey key,
                            std::string subkey, CapabilityValue value, const Provenance& provenance,
                            MutationPolicy policy = MutationPolicy::RequireGeneration);
  Status publish_port_capability(const AuthorityToken& authority, const PortKey& port, CapabilityKey key,
                                 std::string subkey, CapabilityValue value, const Provenance& provenance,
                                 MutationPolicy policy = MutationPolicy::RequireGeneration);
  Result<CapabilityView> capabilities(const ModuleHandle& module) const;
  Result<CapabilityView> port_capabilities(const PortKey& port) const;
  std::vector<PortKey> ports() const;

  // -- attachment ---------------------------------------------------------

  Result<AttachmentRecord> attach(const AuthorityToken& authority, const ModuleHandle& module, const SlotKey& slot,
                                  std::uint32_t port_index, MutationPolicy policy = MutationPolicy::RequireGeneration);
  Status detach(const AuthorityToken& authority, const SlotKey& slot,
                MutationPolicy policy = MutationPolicy::RequireGeneration);
  Result<AttachmentRecord> attachment_of_slot(const SlotKey& slot) const;
  Result<AttachmentRecord> attachment_of_module(const ModuleHandle& module) const;
  std::vector<SlotKey> slots() const;

  // -- health -------------------------------------------------------------

  Status ingest_health(const AuthorityToken& authority, const ModuleHandle& module, const HealthSampleInput& sample,
                       MutationPolicy policy = MutationPolicy::RequireGeneration);
  Status publish_threshold(const AuthorityToken& authority, const HealthThreshold& threshold,
                           MutationPolicy policy = MutationPolicy::RequireGeneration);
  Result<HealthReport> health(const ModuleHandle& module) const;
  Result<std::vector<HealthSample>> samples(const ModuleHandle& module, const SampleQuery& query) const;
  Result<HealthLatch> latch(const ModuleHandle& module, HealthMetric metric, std::uint16_t lane) const;

  // -- compatibility ------------------------------------------------------

  Result<CompatRuleHandle> publish_rule(const AuthorityToken& authority, const CompatRule& rule,
                                        MutationPolicy policy = MutationPolicy::RequireGeneration);
  Status retire_rule(const AuthorityToken& authority, RuleId id, MutationPolicy policy = MutationPolicy::RequireGeneration);
  std::vector<CompatRuleRecord> rules() const;
  Result<CompatDecision> query_compatibility(const CompatQuery& query) const;
  /// Re-check that a decision still describes the current registry.
  Status verify_decision(const CompatDecision& decision) const;

  // -- lifecycle ----------------------------------------------------------

  Result<LifecycleEvent> transition(const AuthorityToken& authority, const ModuleHandle& module, LifecycleState to,
                                    std::string reason, MutationPolicy policy = MutationPolicy::RequireGeneration);
  /// Derive Active/Degraded from the current health report and apply the
  /// corresponding transition when one is required. Never invents health.
  Result<LifecycleEvent> reconcile_lifecycle(const AuthorityToken& authority, const ModuleHandle& module,
                                             MutationPolicy policy = MutationPolicy::RequireGeneration);
  Result<LifecycleState> lifecycle_state(const ModuleHandle& module) const;
  Result<std::vector<LifecycleEvent>> lifecycle_history(const ModuleHandle& module) const;

  // -- evidence inspection ------------------------------------------------

  Result<std::vector<IdentityClaim>> claim_history(const ModuleHandle& module, const ClaimQuery& query) const;
  Result<std::vector<CapabilityDeclaration>> declaration_history(const ModuleHandle& module,
                                                                 const DeclarationQuery& query) const;
  Result<EvidenceSummary> evidence_summary(const ModuleHandle& module) const;

  // -- registry introspection ---------------------------------------------

  [[nodiscard]] Generation generation() const;
  [[nodiscard]] std::uint32_t registry_incarnation() const;
  [[nodiscard]] RegistryStats stats() const;
  [[nodiscard]] const RegistryConfig& config() const noexcept;
  /// Canonical digest of the whole registry state. Two registries holding the
  /// same logical state produce the same digest regardless of insertion order.
  [[nodiscard]] Digest state_digest() const;
  Status verify_generation(Generation expected) const;

  // -- persistence --------------------------------------------------------

  Status save(const std::string& path, const SaveOptions& options = {}) const;
  /// Load a snapshot. The registry must have no modules, rules, or ports yet.
  Result<LoadReport> load(const std::string& path, const LoadOptions& options = {});
  /// Persist after every committed mutation. Used by long-lived daemons so a
  /// kill -9 leaves a recoverable snapshot.
  Status enable_autosave(std::string path, SaveOptions options = {});
  void disable_autosave();

 private:
  friend struct RegistryAccess;
  std::unique_ptr<RegistryImpl> impl_;
};

/// Parse a register intent from text (`current`, `new_incarnation`).
bool register_intent_from_string(std::string_view text, RegisterIntent& out) noexcept;
std::string_view to_string(RegisterIntent intent) noexcept;

}  // namespace trxreg
