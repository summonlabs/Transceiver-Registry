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

#include "trxreg/registry.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <map>
#include <utility>

#include "domain.hpp"
#include "registry_internal.hpp"

namespace trxreg {

// ---------------------------------------------------------------------------
// Status code vocabulary
// ---------------------------------------------------------------------------

Status validate_key_text(std::string_view text, std::string_view what, std::uint64_t max_bytes) {
  if (text.empty()) {
    return Status(StatusCode::InvalidArgument, std::string(what) + " must not be empty");
  }
  if (static_cast<std::uint64_t>(text.size()) > max_bytes) {
    return Status(StatusCode::InvalidArgument, std::string(what) + " is longer than the accepted maximum");
  }
  for (const char raw : text) {
    const auto byte = static_cast<unsigned char>(raw);
    if (byte < 0x21u || byte > 0x7eu) {
      return Status(StatusCode::InvalidArgument,
                    std::string(what) + " must contain printable ASCII characters without spaces");
    }
  }
  return ok_status();
}

Error make_error(StatusCode code, std::string message) {
  Error error;
  error.code = code;
  error.message = std::move(message);
  return error;
}

std::string_view to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok:
      return "ok";
    case StatusCode::InvalidArgument:
      return "invalid_argument";
    case StatusCode::NotFound:
      return "not_found";
    case StatusCode::Conflict:
      return "conflict";
    case StatusCode::StaleAuthority:
      return "stale_authority";
    case StatusCode::StaleGeneration:
      return "stale_generation";
    case StatusCode::StaleIncarnation:
      return "stale_incarnation";
    case StatusCode::Fenced:
      return "fenced";
    case StatusCode::CapacityExceeded:
      return "capacity_exceeded";
    case StatusCode::Malformed:
      return "malformed";
    case StatusCode::Corrupt:
      return "corrupt";
    case StatusCode::Unsupported:
      return "unsupported";
    case StatusCode::Refused:
      return "refused";
    case StatusCode::IoError:
      return "io_error";
    case StatusCode::ClockSkew:
      return "clock_skew";
    case StatusCode::InvalidTransition:
      return "invalid_transition";
    case StatusCode::KnowledgeOpen:
      return "knowledge_open";
    case StatusCode::Internal:
      return "internal";
  }
  return "internal";
}

bool status_code_from_string(std::string_view text, StatusCode& out) noexcept {
  static constexpr StatusCode kAll[] = {
      StatusCode::Ok,           StatusCode::InvalidArgument, StatusCode::NotFound,
      StatusCode::Conflict,     StatusCode::StaleAuthority,  StatusCode::StaleGeneration,
      StatusCode::StaleIncarnation, StatusCode::Fenced,      StatusCode::CapacityExceeded,
      StatusCode::Malformed,    StatusCode::Corrupt,         StatusCode::Unsupported,
      StatusCode::Refused,      StatusCode::IoError,         StatusCode::ClockSkew,
      StatusCode::InvalidTransition, StatusCode::KnowledgeOpen, StatusCode::Internal};
  for (const StatusCode candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(RegisterIntent intent) noexcept {
  switch (intent) {
    case RegisterIntent::EnsureCurrent:
      return "current";
    case RegisterIntent::NewIncarnation:
      return "new_incarnation";
  }
  return "current";
}

bool register_intent_from_string(std::string_view text, RegisterIntent& out) noexcept {
  if (text == "current") {
    out = RegisterIntent::EnsureCurrent;
    return true;
  }
  if (text == "new_incarnation") {
    out = RegisterIntent::NewIncarnation;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

Status validate_provenance(const Provenance& provenance) {
  if (provenance.kind == EvidenceKind::Unsupported) {
    return Status(StatusCode::InvalidArgument,
                  "evidence must declare how it was obtained: real or synthetic provenance is required");
  }
  if (provenance.origin.empty()) {
    return Status(StatusCode::InvalidArgument, "evidence provenance must name an origin");
  }
  if (provenance.origin.size() > 128 || provenance.method.size() > 128 || provenance.capture_ref.size() > 256) {
    return Status(StatusCode::InvalidArgument, "evidence provenance text is too long");
  }
  if (!is_valid_utf8(provenance.origin) || !is_valid_utf8(provenance.method)) {
    return Status(StatusCode::InvalidArgument, "evidence provenance must be valid UTF-8");
  }
  return ok_status();
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kMaxIdentityValueBytes = 256;

Status require_authority(const State& state, const AuthorityToken& authority) {
  if (!authority.source.valid()) {
    return Status(StatusCode::InvalidArgument, "an authority token with a source id is required");
  }
  const auto it = state.sources.find(authority.source.value());
  if (it == state.sources.end()) {
    return Status(StatusCode::StaleAuthority, "the authority token names a source that is not registered");
  }
  if (it->second.epoch != authority.epoch) {
    return Status(StatusCode::StaleAuthority,
                  "the authority token belongs to a retired source incarnation; re-register the source");
  }
  return ok_status();
}

Status validate_identity_value(const IdentityFieldValue& value) {
  if (value.field == IdentityField::Unknown) {
    return Status(StatusCode::InvalidArgument, "identity field must be named");
  }
  if (value.value.empty()) {
    return Status(StatusCode::InvalidArgument, "identity value must not be empty");
  }
  if (value.value.size() > kMaxIdentityValueBytes) {
    return Status(StatusCode::InvalidArgument, "identity value is too long");
  }
  if (!is_valid_utf8(value.value) || !is_valid_utf8(value.subkey)) {
    return Status(StatusCode::InvalidArgument, "identity value must be valid UTF-8");
  }
  if (value.field == IdentityField::VendorSpecific && value.subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "vendor specific identity fields require a subkey");
  }
  if (value.field != IdentityField::VendorSpecific && !value.subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "only vendor specific identity fields may carry a subkey");
  }
  if (value.subkey.size() > 128) {
    return Status(StatusCode::InvalidArgument, "identity subkey is too long");
  }
  return ok_status();
}

bool claim_is_superseded(const std::vector<IdentityClaim>& claims, std::size_t index) {
  const IdentityClaim& candidate = claims[index];
  for (std::size_t i = 0; i < claims.size(); ++i) {
    if (i == index) {
      continue;
    }
    const IdentityClaim& other = claims[i];
    if (other.source == candidate.source && other.source_epoch == candidate.source_epoch &&
        other.field == candidate.field && other.subkey == candidate.subkey &&
        other.incarnation == candidate.incarnation && candidate.sequence < other.sequence) {
      return true;
    }
  }
  return false;
}

Status trim_claims(ModuleRecord& record, std::uint32_t max_total, std::uint32_t max_history) {
  std::size_t guard = record.claims.size();
  while (record.claims.size() > max_total && guard-- > 0) {
    bool removed = false;
    for (std::size_t i = 0; i < record.claims.size(); ++i) {
      if (claim_is_superseded(record.claims, i)) {
        record.claims.erase(record.claims.begin() + static_cast<std::ptrdiff_t>(i));
        removed = true;
        break;
      }
    }
    if (!removed) {
      return Status(StatusCode::CapacityExceeded, "module identity claim budget is exhausted");
    }
  }
  if (record.claims.size() > max_total) {
    return Status(StatusCode::CapacityExceeded, "module identity claim budget is exhausted");
  }

  // Bound the per-attribute history so a single chattering source cannot grow
  // without limit.
  std::map<std::tuple<std::uint8_t, std::string, std::uint32_t, std::uint32_t>, std::vector<std::size_t>> grouped;
  for (std::size_t i = 0; i < record.claims.size(); ++i) {
    const IdentityClaim& claim = record.claims[i];
    grouped[{static_cast<std::uint8_t>(claim.field), claim.subkey, claim.source.value(), claim.source_epoch.value()}]
        .push_back(i);
  }
  std::vector<bool> drop(record.claims.size(), false);
  std::size_t drop_count = 0;
  for (auto& entry : grouped) {
    auto& indices = entry.second;
    if (indices.size() <= max_history) {
      continue;
    }
    std::sort(indices.begin(), indices.end(),
              [&record](std::size_t lhs, std::size_t rhs) { return record.claims[lhs].sequence < record.claims[rhs].sequence; });
    const std::size_t excess = indices.size() - max_history;
    for (std::size_t i = 0; i < excess; ++i) {
      drop[indices[i]] = true;
      ++drop_count;
    }
  }
  if (drop_count > 0) {
    std::vector<IdentityClaim> kept;
    kept.reserve(record.claims.size() - drop_count);
    for (std::size_t i = 0; i < record.claims.size(); ++i) {
      if (!drop[i]) {
        kept.push_back(std::move(record.claims[i]));
      }
    }
    record.claims = std::move(kept);
  }
  return ok_status();
}

bool declaration_is_superseded(const std::vector<CapabilityDeclaration>& declarations, std::size_t index) {
  const CapabilityDeclaration& candidate = declarations[index];
  for (std::size_t i = 0; i < declarations.size(); ++i) {
    if (i == index) {
      continue;
    }
    const CapabilityDeclaration& other = declarations[i];
    if (other.source == candidate.source && other.source_epoch == candidate.source_epoch &&
        other.key == candidate.key && other.subkey == candidate.subkey && other.module == candidate.module &&
        other.incarnation == candidate.incarnation && candidate.sequence < other.sequence) {
      return true;
    }
  }
  return false;
}

Status trim_declarations(ModuleRecord& record, std::uint32_t max_total, std::uint32_t max_history) {
  std::size_t guard = record.declarations.size();
  while (record.declarations.size() > max_total && guard-- > 0) {
    bool removed = false;
    for (std::size_t i = 0; i < record.declarations.size(); ++i) {
      if (declaration_is_superseded(record.declarations, i)) {
        record.declarations.erase(record.declarations.begin() + static_cast<std::ptrdiff_t>(i));
        removed = true;
        break;
      }
    }
    if (!removed) {
      return Status(StatusCode::CapacityExceeded, "module capability declaration budget is exhausted");
    }
  }
  if (record.declarations.size() > max_total) {
    return Status(StatusCode::CapacityExceeded, "module capability declaration budget is exhausted");
  }

  std::map<std::tuple<std::uint8_t, std::string, std::uint32_t, std::uint32_t>, std::vector<std::size_t>> grouped;
  for (std::size_t i = 0; i < record.declarations.size(); ++i) {
    const CapabilityDeclaration& declaration = record.declarations[i];
    grouped[{static_cast<std::uint8_t>(declaration.key), declaration.subkey, declaration.source.value(),
             declaration.source_epoch.value()}]
        .push_back(i);
  }
  std::vector<bool> drop(record.declarations.size(), false);
  std::size_t drop_count = 0;
  for (auto& entry : grouped) {
    auto& indices = entry.second;
    if (indices.size() <= max_history) {
      continue;
    }
    std::sort(indices.begin(), indices.end(), [&record](std::size_t lhs, std::size_t rhs) {
      return record.declarations[lhs].sequence < record.declarations[rhs].sequence;
    });
    const std::size_t excess = indices.size() - max_history;
    for (std::size_t i = 0; i < excess; ++i) {
      drop[indices[i]] = true;
      ++drop_count;
    }
  }
  if (drop_count > 0) {
    std::vector<CapabilityDeclaration> kept;
    kept.reserve(record.declarations.size() - drop_count);
    for (std::size_t i = 0; i < record.declarations.size(); ++i) {
      if (!drop[i]) {
        kept.push_back(std::move(record.declarations[i]));
      }
    }
    record.declarations = std::move(kept);
  }
  return ok_status();
}

Status trim_declarations(std::vector<CapabilityDeclaration>& declarations, std::uint32_t max_total,
                         std::uint32_t max_history) {
  std::size_t guard = declarations.size();
  while (declarations.size() > max_total && guard-- > 0) {
    bool removed = false;
    for (std::size_t i = 0; i < declarations.size(); ++i) {
      const CapabilityDeclaration& candidate = declarations[i];
      for (std::size_t j = 0; j < declarations.size(); ++j) {
        if (i == j) {
          continue;
        }
        const CapabilityDeclaration& other = declarations[j];
        if (other.source == candidate.source && other.source_epoch == candidate.source_epoch &&
            other.key == candidate.key && other.subkey == candidate.subkey && candidate.sequence < other.sequence) {
          removed = true;
          break;
        }
      }
      if (removed) {
        declarations.erase(declarations.begin() + static_cast<std::ptrdiff_t>(i));
        break;
      }
    }
    if (!removed) {
      return Status(StatusCode::CapacityExceeded, "port capability declaration budget is exhausted");
    }
  }
  (void)max_history;
  return ok_status();
}

Status trim_samples(State& state, ModuleRecord& record, const RegistryConfig& config) {
  // Per-series ring: drop the oldest sample of the series that overflowed.
  for (auto& entry : record.series_counts) {
    const std::uint32_t limit = config.max_samples_per_series;
    std::uint32_t& count = entry.second;
    while (count > limit) {
      bool removed = false;
      for (std::size_t i = 0; i < record.samples.size(); ++i) {
        const HealthSample& sample = record.samples[i];
        if (static_cast<std::uint8_t>(sample.metric) == entry.first.first && sample.lane == entry.first.second) {
          record.samples.erase(record.samples.begin() + static_cast<std::ptrdiff_t>(i));
          --count;
          ++state.dropped_samples;
          removed = true;
          break;
        }
      }
      if (!removed) {
        break;
      }
    }
  }

  while (record.samples.size() > config.max_samples_per_module) {
    record.samples.erase(record.samples.begin());
    ++state.dropped_samples;
  }
  return ok_status();
}

/// True when a later claim from the same source incarnation covers the same
/// attribute, which is how a source revises its own earlier statement.
bool claim_shadowed(const std::vector<IdentityClaim>& claims, const IdentityClaim& claim) {
  for (const IdentityClaim& other : claims) {
    if (other.source == claim.source && other.source_epoch == claim.source_epoch &&
        other.incarnation == claim.incarnation && other.field == claim.field && other.subkey == claim.subkey &&
        other.sequence > claim.sequence) {
      return true;
    }
  }
  return false;
}

bool declaration_shadowed(const std::vector<CapabilityDeclaration>& declarations,
                          const CapabilityDeclaration& declaration) {
  for (const CapabilityDeclaration& other : declarations) {
    if (other.source == declaration.source && other.source_epoch == declaration.source_epoch &&
        other.incarnation == declaration.incarnation && other.module == declaration.module &&
        other.port.str() == declaration.port.str() && other.key == declaration.key &&
        other.subkey == declaration.subkey && other.sequence > declaration.sequence) {
      return true;
    }
  }
  return false;
}

HealthLatchRecord* find_latch(ModuleRecord& record, HealthMetric metric, std::uint16_t lane) {
  for (HealthLatchRecord& entry : record.latches) {
    if (entry.metric == metric && entry.lane == lane) {
      return &entry;
    }
  }
  return nullptr;
}

const HealthLatchRecord* find_latch(const ModuleRecord& record, HealthMetric metric, std::uint16_t lane) {
  for (const HealthLatchRecord& entry : record.latches) {
    if (entry.metric == metric && entry.lane == lane) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

bool source_is_live(const State& state, SourceId source, SourceEpoch epoch) {
  const auto it = state.sources.find(source.value());
  if (it == state.sources.end()) {
    return false;
  }
  return it->second.epoch == epoch;
}

bool incarnation_is_current(const ModuleRecord& record, IncarnationId incarnation) {
  return record.incarnation == incarnation;
}

std::vector<IdentityClaim> live_claims(const State& state, const ModuleRecord& record, IncarnationId incarnation) {
  std::vector<IdentityClaim> out;
  out.reserve(record.claims.size());
  for (const IdentityClaim& claim : record.claims) {
    if (claim.incarnation != incarnation) {
      continue;
    }
    IdentityClaim copy = claim;
    copy.live = source_is_live(state, claim.source, claim.source_epoch) && !claim_shadowed(record.claims, claim);
    out.push_back(std::move(copy));
  }
  return out;
}

std::vector<CapabilityDeclaration> live_declarations(const State& state, const ModuleRecord& record,
                                                     IncarnationId incarnation) {
  std::vector<CapabilityDeclaration> out;
  out.reserve(record.declarations.size());
  for (const CapabilityDeclaration& declaration : record.declarations) {
    if (declaration.incarnation != incarnation) {
      continue;
    }
    CapabilityDeclaration copy = declaration;
    copy.live = source_is_live(state, declaration.source, declaration.source_epoch) &&
                !declaration_shadowed(record.declarations, declaration);
    out.push_back(std::move(copy));
  }
  return out;
}

std::vector<CapabilityDeclaration> live_port_declarations(const State& state, const PortRecord& record) {
  std::vector<CapabilityDeclaration> out;
  out.reserve(record.declarations.size());
  for (const CapabilityDeclaration& declaration : record.declarations) {
    CapabilityDeclaration copy = declaration;
    copy.live = source_is_live(state, declaration.source, declaration.source_epoch) &&
                !declaration_shadowed(record.declarations, declaration);
    out.push_back(std::move(copy));
  }
  return out;
}

std::vector<HealthSample> live_samples(const State& state, const ModuleRecord& record, IncarnationId incarnation) {
  std::vector<HealthSample> out;
  out.reserve(record.samples.size());
  for (const HealthSample& sample : record.samples) {
    if (sample.incarnation != incarnation) {
      continue;
    }
    HealthSample copy = sample;
    copy.live = source_is_live(state, sample.source, sample.source_epoch);
    out.push_back(std::move(copy));
  }
  return out;
}

std::uint64_t next_sequence(State& state) {
  const std::uint64_t value = state.next_sequence;
  state.next_sequence = value + 1;
  if (state.next_sequence == 0) {
    state.next_sequence = 1;
  }
  return value;
}

RegistryImpl::RegistryImpl(RegistryConfig config_in, ClockPtr clock_in)
    : config(config_in), clock(clock_in ? std::move(clock_in) : make_system_clock()),
      state(std::make_shared<State>()) {}

StatePtr RegistryImpl::current() const {
  std::unique_lock<std::mutex> lock(mutex);
  return state;
}

Generation RegistryImpl::generation() const {
  std::unique_lock<std::mutex> lock(mutex);
  return state->generation;
}

void RegistryImpl::maybe_autosave() {
  std::string path;
  SaveOptions options;
  {
    std::unique_lock<std::mutex> lock(autosave_mutex);
    if (!autosave_enabled) {
      return;
    }
    path = autosave_path;
    options = autosave_options;
  }
  auto* self = this;
  // save_snapshot takes the state lock only to copy the state pointer, so this
  // never re-enters the mutation path.
  const Status status = save_snapshot_impl(*self, path, options);
  if (status.ok()) {
    std::unique_lock<std::mutex> lock(autosave_mutex);
    autosave_generation = generation();
  }
}

// ---------------------------------------------------------------------------
// Registry: construction and introspection
// ---------------------------------------------------------------------------

Registry::Registry(RegistryConfig config, ClockPtr clock)
    : impl_(std::make_unique<RegistryImpl>(config, std::move(clock))) {}

Registry::~Registry() = default;

Generation Registry::generation() const { return impl_->generation(); }

std::uint32_t Registry::registry_incarnation() const { return impl_->current()->registry_incarnation; }

const RegistryConfig& Registry::config() const noexcept { return impl_->config; }

Status Registry::verify_generation(Generation expected) const {
  const Generation current = impl_->generation();
  if (expected.valid() && expected != current) {
    return Status(StatusCode::StaleGeneration,
                  "the decision was taken at generation " + std::to_string(expected.value()) +
                      " but the registry is at generation " + std::to_string(current.value()));
  }
  return ok_status();
}

Digest Registry::state_digest() const { return compute_state_digest(*impl_->current()); }

RegistryStats Registry::stats() const {
  const StatePtr state = impl_->current();
  RegistryStats stats;
  stats.generation = state->generation;
  stats.registry_incarnation = state->registry_incarnation;
  stats.sources = state->sources.size();
  stats.modules = state->modules.size();
  stats.ports = state->ports.size();
  stats.rules = state->rules.size();
  stats.attachments = state->attachments.size();
  stats.mutations = state->mutations;
  stats.refusals = impl_->refusals.load(std::memory_order_relaxed);
  stats.queries = impl_->queries.load(std::memory_order_relaxed);
  stats.conflicts_observed = state->conflicts_observed;
  for (const auto& entry : state->modules) {
    const ModuleRecord& record = entry.second;
    stats.incarnations += record.incarnation_count;
    if (record.incarnation_count > 1) {
      ++stats.fenced_incarnations;
    }
    stats.claims += record.claims.size();
    stats.declarations += record.declarations.size();
    stats.samples += record.samples.size();
  }
  for (const auto& entry : state->ports) {
    stats.declarations += entry.second.declarations.size();
  }
  for (const auto& entry : state->thresholds) {
    if (entry.live) {
      ++stats.thresholds;
    }
  }
  for (const auto& entry : state->attachments) {
    if (entry.second.live) {
      ++stats.live_attachments;
    }
  }
  stats.state_digest = compute_state_digest(*state);
  return stats;
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

Result<SourceHandle> Registry::register_source(const SourceDescriptor& descriptor, MutationPolicy policy) {
  if (descriptor.name.empty() || descriptor.name.size() > kMaxKeyBytes) {
    return make_error(StatusCode::InvalidArgument, "source name must be between 1 and 128 characters");
  }
  if (!is_valid_utf8(descriptor.name) || !is_valid_utf8(descriptor.instance_id)) {
    return make_error(StatusCode::InvalidArgument, "source descriptor text must be valid UTF-8");
  }
  if (descriptor.description.size() > 512 || descriptor.instance_id.size() > 128) {
    return make_error(StatusCode::InvalidArgument, "source descriptor text is too long");
  }

  SourceHandle handle;
  const Status status = impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{}, [&](State& state,
                                                                                                    Generation generation,
                                                                                                    Sequence sequence) {
    const WallNs now = impl_->clock->wall_now_ns();
    const auto existing = state.source_id_by_name.find(descriptor.name);
    SourceRecord record;
    if (existing != state.source_id_by_name.end()) {
      record = state.sources.at(existing->second);
      // Re-registering the same name is either the same agent reconnecting or a
      // different incarnation of that agent. A matching, non-empty instance id
      // is a renewal: the source keeps its epoch and its earlier claims stay
      // live. Anything else (a new instance id, or none at all) mints a new
      // epoch, which fences every authority token and claim of the previous one.
      const bool renewal = !descriptor.instance_id.empty() &&
                           descriptor.instance_id == record.descriptor.instance_id;
      if (!renewal) {
        if (record.epoch.value() == 0xFFFFFFFFu) {
          return Status(StatusCode::CapacityExceeded, "source incarnation counter is exhausted");
        }
        record.epoch = SourceEpoch{record.epoch.value() + 1};
      }
      record.descriptor = descriptor;
      record.generation = generation;
      record.sequence = sequence;
      record.registered_wall_ns = now;
      state.sources[record.id.value()] = record;
    } else {
      if (state.sources.size() >= impl_->config.max_sources) {
        return Status(StatusCode::CapacityExceeded, "source budget is exhausted");
      }
      record.id = SourceId{static_cast<std::uint32_t>(state.next_source_id)};
      if (state.next_source_id >= 0xFFFFFFFFull) {
        return Status(StatusCode::CapacityExceeded, "source id space is exhausted");
      }
      state.next_source_id += 1;
      record.name = descriptor.name;
      record.epoch = SourceEpoch{1};
      record.descriptor = descriptor;
      record.generation = generation;
      record.sequence = sequence;
      record.registered_wall_ns = now;
      state.sources[record.id.value()] = record;
      state.source_id_by_name[descriptor.name] = record.id.value();
    }
    handle.id = record.id;
    handle.epoch = record.epoch;
    handle.generation = generation;
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return handle;
}

Result<SourceHandle> Registry::source_handle(SourceId id) const {
  const StatePtr state = impl_->current();
  const auto it = state->sources.find(id.value());
  if (it == state->sources.end()) {
    return make_error(StatusCode::NotFound, "no such source");
  }
  SourceHandle handle;
  handle.id = it->second.id;
  handle.epoch = it->second.epoch;
  handle.generation = it->second.generation;
  return handle;
}

// ---------------------------------------------------------------------------
// Module identity
// ---------------------------------------------------------------------------

Result<ModuleHandle> Registry::register_module(const ModuleRegistration& registration, const AuthorityToken& authority) {
  if (registration.key.empty()) {
    return make_error(StatusCode::InvalidArgument, "module registration requires a module key");
  }
  TRXREG_TRY(validate_provenance(registration.provenance));
  for (const IdentityFieldValue& value : registration.identity) {
    TRXREG_TRY(validate_identity_value(value));
  }
  {
    std::vector<std::pair<std::uint8_t, std::string>> seen;
    for (const IdentityFieldValue& value : registration.identity) {
      const std::pair<std::uint8_t, std::string> key{static_cast<std::uint8_t>(value.field), value.subkey};
      if (std::find(seen.begin(), seen.end(), key) != seen.end()) {
        return make_error(StatusCode::InvalidArgument, "module registration repeats an identity field");
      }
      seen.push_back(key);
    }
  }

  ModuleHandle handle;
  const Status status = impl_->mutate(registration.policy == MutationPolicy::RequireGeneration,
                                      registration.expected_generation,
                                      [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const WallNs now = impl_->clock->wall_now_ns();
    const ClockDomainId domain = impl_->clock->domain();

    const auto existing = state.module_uid_by_key.find(registration.key.str());
    ModuleUid uid;
    if (existing == state.module_uid_by_key.end()) {
      if (state.modules.size() >= impl_->config.max_modules) {
        return Status(StatusCode::CapacityExceeded, "module budget is exhausted");
      }
      uid = ModuleUid{state.next_module_uid};
      state.next_module_uid += 1;
      ModuleRecord record;
      record.key = registration.key;
      record.uid = uid;
      record.incarnation = IncarnationId{1};
      record.state = LifecycleState::Discovered;
      record.created_generation = generation;
      record.created_sequence = sequence;
      record.created_wall_ns = now;
      record.state_generation = generation;
      record.state_sequence = sequence;
      record.state_wall_ns = now;
      LifecycleEvent discovered;
      discovered.from = LifecycleState::Discovered;
      discovered.to = LifecycleState::Discovered;
      discovered.incarnation = record.incarnation;
      discovered.reason = "module key observed for the first time";
      discovered.source = authority.source;
      discovered.source_epoch = authority.epoch;
      discovered.generation = generation;
      discovered.sequence = sequence;
      discovered.wall_ns = now;
      record.lifecycle.push_back(discovered);
      state.modules[uid.value()] = std::move(record);
      state.module_uid_by_key[registration.key.str()] = uid.value();
    } else {
      uid = ModuleUid{existing->second};
      ModuleRecord& record = state.modules.at(uid.value());
      if (registration.intent == RegisterIntent::EnsureCurrent) {
        if (record.state == LifecycleState::Replaced || record.state == LifecycleState::Retired) {
          return Status(StatusCode::StaleIncarnation,
                        "this module key was replaced or retired; declare a new incarnation to register a replacement");
        }
      } else {
        // A different physical module now occupies this key: fence the previous
        // incarnation's evidence and any attachment it held.
        const LifecycleState previous_state = record.state;
        if (previous_state != LifecycleState::Replaced && previous_state != LifecycleState::Retired) {
          LifecycleEvent replaced;
          replaced.from = previous_state;
          replaced.to = LifecycleState::Replaced;
          replaced.incarnation = record.incarnation;
          replaced.reason = "a new physical module incarnation was registered for this module key";
          replaced.source = authority.source;
          replaced.source_epoch = authority.epoch;
          replaced.generation = generation;
          replaced.sequence = sequence;
          replaced.wall_ns = now;
          record.lifecycle.push_back(replaced);
          record.fenced_generation = generation;
          for (auto& attachment : state.attachments) {
            if (attachment.second.live && attachment.second.uid == record.uid) {
              attachment.second.live = false;
              attachment.second.note = "the module occupying this slot was replaced";
            }
          }
        }
        if (record.incarnation.value() == 0xFFFFFFFFu) {
          return Status(StatusCode::CapacityExceeded, "module incarnation counter is exhausted");
        }
        record.incarnation = IncarnationId{record.incarnation.value() + 1};
        record.incarnation_count += 1;
        record.state = LifecycleState::Discovered;
        record.fenced_generation = generation;
        record.latches.clear();
        LifecycleEvent observed;
        observed.from = LifecycleState::Discovered;
        observed.to = LifecycleState::Discovered;
        observed.incarnation = record.incarnation;
        observed.reason = "new module incarnation discovered";
        observed.source = authority.source;
        observed.source_epoch = authority.epoch;
        observed.generation = generation;
        observed.sequence = sequence;
        observed.wall_ns = now;
        record.lifecycle.push_back(observed);
      }
    }

    ModuleRecord& record = state.modules.at(uid.value());
    if (record.state == LifecycleState::Discovered) {
      if (!lifecycle_transition_allowed(record.state, LifecycleState::Registered)) {
        return Status(StatusCode::Internal, "discovered modules must be registrable");
      }
      LifecycleEvent registered;
      registered.from = record.state;
      registered.to = LifecycleState::Registered;
      registered.incarnation = record.incarnation;
      registered.reason = "module identity registered";
      registered.source = authority.source;
      registered.source_epoch = authority.epoch;
      registered.generation = generation;
      registered.sequence = sequence;
      registered.wall_ns = now;
      record.state = LifecycleState::Registered;
      record.state_generation = generation;
      record.state_sequence = sequence;
      record.state_wall_ns = now;
      record.lifecycle.push_back(registered);
    }

    for (const IdentityFieldValue& value : registration.identity) {
      IdentityClaim claim;
      claim.field = value.field;
      claim.subkey = value.subkey;
      claim.value = value.value;
      claim.source = authority.source;
      claim.source_epoch = authority.epoch;
      claim.module = record.uid;
      claim.incarnation = record.incarnation;
      claim.generation = generation;
      claim.sequence = sequence;
      claim.observed_at_wall_ns = now;
      claim.clock_domain = domain;
      claim.provenance = registration.provenance;
      claim.live = true;
      record.claims.push_back(std::move(claim));
    }

    TRXREG_TRY(trim_claims(record, impl_->config.max_claims_per_module, impl_->config.max_claim_history));
    while (record.lifecycle.size() > impl_->config.max_lifecycle_history) {
      record.lifecycle.erase(record.lifecycle.begin());
    }

    handle.uid = record.uid;
    handle.incarnation = record.incarnation;
    handle.generation = generation;
    handle.key = record.key;
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return handle;
}

Status Registry::update_identity(const AuthorityToken& authority, const ModuleHandle& module,
                                 const IdentityFieldValue& value, const Provenance& provenance, MutationPolicy policy) {
  TRXREG_TRY(validate_identity_value(value));
  TRXREG_TRY(validate_provenance(provenance));
  return impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced,
                    "the referenced module incarnation was replaced; identity updates cannot target it");
    }
    const WallNs now = impl_->clock->wall_now_ns();
    IdentityClaim claim;
    claim.field = value.field;
    claim.subkey = value.subkey;
    claim.value = value.value;
    claim.source = authority.source;
    claim.source_epoch = authority.epoch;
    claim.module = record.uid;
    claim.incarnation = record.incarnation;
    claim.generation = generation;
    claim.sequence = sequence;
    claim.observed_at_wall_ns = now;
    claim.clock_domain = impl_->clock->domain();
    claim.provenance = provenance;
    claim.live = true;
    record.claims.push_back(std::move(claim));
    return trim_claims(record, impl_->config.max_claims_per_module, impl_->config.max_claim_history);
  });
}

Result<IdentityView> Registry::identity(const ModuleHandle& module) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  if (!incarnation_is_current(record, module.incarnation)) {
    return make_error(StatusCode::Fenced,
                      "the referenced module incarnation was replaced; query the current incarnation or inspect history");
  }
  IdentityView view;
  view.uid = record.uid;
  view.incarnation = record.incarnation;
  view.key = record.key;
  view.generation = state->generation;
  view.lifecycle = record.state;
  view.fields = detail::build_identity_consensus(live_claims(*state, record, record.incarnation));
  view.digest = digest_identity_fields(view.fields);
  for (const FieldConsensus& consensus : view.fields) {
    if (consensus.outcome == ConsensusOutcome::Conflicting) {
      ++view.conflicting_fields;
    }
    if (!consensus.superseded_claims.empty()) {
      ++view.superseded_fields;
    }
  }
  return view;
}

Result<IdentityView> Registry::identity_by_key(std::string_view key) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto found = state->module_uid_by_key.find(std::string(key));
  if (found == state->module_uid_by_key.end()) {
    return make_error(StatusCode::NotFound, "no module is registered under this key");
  }
  const ModuleRecord& record = state->modules.at(found->second);
  ModuleHandle handle;
  handle.uid = record.uid;
  handle.incarnation = record.incarnation;
  handle.generation = state->generation;
  handle.key = record.key;
  return identity(handle);
}

std::vector<ModuleHandle> Registry::modules() const {
  const StatePtr state = impl_->current();
  std::vector<ModuleHandle> handles;
  handles.reserve(state->modules.size());
  for (const auto& entry : state->modules) {
    ModuleHandle handle;
    handle.uid = entry.second.uid;
    handle.incarnation = entry.second.incarnation;
    handle.generation = state->generation;
    handle.key = entry.second.key;
    handles.push_back(std::move(handle));
  }
  return handles;
}


// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

Status Registry::publish_capability(const AuthorityToken& authority, const ModuleHandle& module, CapabilityKey key,
                                    std::string subkey, CapabilityValue value, const Provenance& provenance,
                                    MutationPolicy policy) {
  if (key == CapabilityKey::Unknown || key == CapabilityKey::Unsupported) {
    return Status(StatusCode::Unsupported, "this runtime does not model the requested capability key");
  }
  if (key == CapabilityKey::VendorSpecific && subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "vendor specific capabilities require a subkey");
  }
  if (key != CapabilityKey::VendorSpecific && !subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "only vendor specific capabilities may carry a subkey");
  }
  if (subkey.size() > 128) {
    return Status(StatusCode::InvalidArgument, "capability subkey is too long");
  }
  TRXREG_TRY(value.validate_for(key));
  TRXREG_TRY(validate_provenance(provenance));

  return impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced,
                    "the referenced module incarnation was replaced; capability publications cannot target it");
    }
    CapabilityDeclaration declaration;
    declaration.key = key;
    declaration.subkey = std::move(subkey);
    declaration.value = std::move(value);
    declaration.source = authority.source;
    declaration.source_epoch = authority.epoch;
    declaration.module = record.uid;
    declaration.incarnation = record.incarnation;
    declaration.module_subject = true;
    declaration.generation = generation;
    declaration.sequence = sequence;
    declaration.observed_at_wall_ns = impl_->clock->wall_now_ns();
    declaration.clock_domain = impl_->clock->domain();
    declaration.provenance = provenance;
    declaration.live = true;
    record.declarations.push_back(std::move(declaration));
    return trim_declarations(record, impl_->config.max_declarations_per_module, impl_->config.max_claim_history);
  });
}

Status Registry::publish_port_capability(const AuthorityToken& authority, const PortKey& port, CapabilityKey key,
                                         std::string subkey, CapabilityValue value, const Provenance& provenance,
                                         MutationPolicy policy) {
  if (key == CapabilityKey::Unknown || key == CapabilityKey::Unsupported) {
    return Status(StatusCode::Unsupported, "this runtime does not model the requested capability key");
  }
  if (key == CapabilityKey::VendorSpecific && subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "vendor specific capabilities require a subkey");
  }
  if (key != CapabilityKey::VendorSpecific && !subkey.empty()) {
    return Status(StatusCode::InvalidArgument, "only vendor specific capabilities may carry a subkey");
  }
  if (port.empty()) {
    return Status(StatusCode::InvalidArgument, "a port key is required");
  }
  TRXREG_TRY(value.validate_for(key));
  TRXREG_TRY(validate_provenance(provenance));

  return impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{},
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    auto it = state.ports.find(port.str());
    if (it == state.ports.end()) {
      if (state.ports.size() >= impl_->config.max_ports) {
        return Status(StatusCode::CapacityExceeded, "port budget is exhausted");
      }
      PortRecord record;
      record.key = port;
      record.first_generation = generation;
      record.sequence = sequence;
      record.first_wall_ns = impl_->clock->wall_now_ns();
      it = state.ports.emplace(port.str(), std::move(record)).first;
    }
    PortRecord& record = it->second;
    if (record.declarations.size() >= impl_->config.max_declarations_per_port) {
      TRXREG_TRY(trim_declarations(record.declarations, impl_->config.max_declarations_per_port - 1,
                                   impl_->config.max_claim_history));
    }
    CapabilityDeclaration declaration;
    declaration.key = key;
    declaration.subkey = std::move(subkey);
    declaration.value = std::move(value);
    declaration.source = authority.source;
    declaration.source_epoch = authority.epoch;
    declaration.module_subject = false;
    declaration.port = port;
    declaration.generation = generation;
    declaration.sequence = sequence;
    declaration.observed_at_wall_ns = impl_->clock->wall_now_ns();
    declaration.clock_domain = impl_->clock->domain();
    declaration.provenance = provenance;
    declaration.live = true;
    record.declarations.push_back(std::move(declaration));
    return trim_declarations(record.declarations, impl_->config.max_declarations_per_port,
                             impl_->config.max_claim_history);
  });
}

Result<CapabilityView> Registry::capabilities(const ModuleHandle& module) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  if (!incarnation_is_current(record, module.incarnation)) {
    return make_error(StatusCode::Fenced,
                      "the referenced module incarnation was replaced; query the current incarnation or inspect history");
  }
  CapabilityView view;
  view.module_subject = true;
  view.uid = record.uid;
  view.incarnation = record.incarnation;
  view.generation = state->generation;
  view.attributes = detail::build_capability_consensus(live_declarations(*state, record, record.incarnation));
  view.digest = digest_capability_attributes(view.attributes);
  for (const CapabilityConsensus& attribute : view.attributes) {
    if (attribute.outcome == ConsensusOutcome::Conflicting) {
      ++view.conflicting_attributes;
    }
    if (!attribute.established()) {
      ++view.unestablished_attributes;
    }
  }
  return view;
}

Result<CapabilityView> Registry::port_capabilities(const PortKey& port) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->ports.find(port.str());
  if (it == state->ports.end()) {
    return make_error(StatusCode::NotFound, "no such port");
  }
  CapabilityView view;
  view.module_subject = false;
  view.port = port;
  view.generation = state->generation;
  view.attributes = detail::build_capability_consensus(live_port_declarations(*state, it->second));
  view.digest = digest_capability_attributes(view.attributes);
  for (const CapabilityConsensus& attribute : view.attributes) {
    if (attribute.outcome == ConsensusOutcome::Conflicting) {
      ++view.conflicting_attributes;
    }
    if (!attribute.established()) {
      ++view.unestablished_attributes;
    }
  }
  return view;
}

std::vector<PortKey> Registry::ports() const {
  const StatePtr state = impl_->current();
  std::vector<PortKey> keys;
  keys.reserve(state->ports.size());
  for (const auto& entry : state->ports) {
    const Result<PortKey> parsed = PortKey::parse(entry.first, "port key");
    if (parsed.ok()) {
      keys.push_back(parsed.value());
    }
  }
  return keys;
}

// ---------------------------------------------------------------------------
// Attachment
// ---------------------------------------------------------------------------

Result<AttachmentRecord> Registry::attach(const AuthorityToken& authority, const ModuleHandle& module,
                                          const SlotKey& slot, std::uint32_t port_index, MutationPolicy policy) {
  if (slot.empty()) {
    return make_error(StatusCode::InvalidArgument, "a slot key is required");
  }
  if (port_index > 255) {
    return make_error(StatusCode::InvalidArgument, "port index is out of range");
  }

  AttachmentRecord result;
  const Status status = impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                                      [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced,
                    "the referenced module incarnation was replaced; it cannot be attached to a slot");
    }

    const auto existing = state.attachments.find(slot.str());
    if (existing != state.attachments.end() && existing->second.live) {
      if (existing->second.uid == record.uid && existing->second.incarnation == record.incarnation) {
        // Idempotent re-attachment of the same module incarnation.
        result = existing->second;
        return ok_status();
      }
    }

    const WallNs now = impl_->clock->wall_now_ns();
    if (record.state != LifecycleState::Attached) {
      if (!lifecycle_transition_allowed(record.state, LifecycleState::Attached)) {
        return Status(StatusCode::InvalidTransition,
                      std::string("a module in state ") + std::string(to_string(record.state)) +
                          " cannot be attached");
      }
    }

    if (existing != state.attachments.end() && existing->second.live) {
      existing->second.live = false;
      existing->second.note = "slot taken over by another module incarnation";
    } else if (existing == state.attachments.end()) {
      std::size_t live_attachments = 0;
      for (const auto& entry : state.attachments) {
        if (entry.second.live) {
          ++live_attachments;
        }
      }
      if (live_attachments >= impl_->config.max_attachments) {
        return Status(StatusCode::CapacityExceeded, "attachment budget is exhausted");
      }
    }

    AttachmentRecord attachment;
    attachment.slot = slot;
    attachment.port_index = port_index;
    attachment.uid = record.uid;
    attachment.incarnation = record.incarnation;
    attachment.source = authority.source;
    attachment.source_epoch = authority.epoch;
    attachment.generation = generation;
    attachment.sequence = sequence;
    attachment.attached_at_wall_ns = now;
    attachment.live = true;

    if (record.state != LifecycleState::Attached) {
      LifecycleEvent event;
      event.from = record.state;
      event.to = LifecycleState::Attached;
      event.incarnation = record.incarnation;
      event.reason = "module attached to slot " + slot.str();
      event.source = authority.source;
      event.source_epoch = authority.epoch;
      event.generation = generation;
      event.sequence = sequence;
      event.wall_ns = now;
      record.state = LifecycleState::Attached;
      record.state_generation = generation;
      record.state_sequence = sequence;
      record.state_wall_ns = now;
      record.lifecycle.push_back(event);
      while (record.lifecycle.size() > impl_->config.max_lifecycle_history) {
        record.lifecycle.erase(record.lifecycle.begin());
      }
    }

    state.attachments[slot.str()] = attachment;
    result = attachment;
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return result;
}

Status Registry::detach(const AuthorityToken& authority, const SlotKey& slot, MutationPolicy policy) {
  return impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{},
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.attachments.find(slot.str());
    if (it == state.attachments.end() || !it->second.live) {
      return Status(StatusCode::NotFound, "no live attachment exists for this slot");
    }
    AttachmentRecord& attachment = it->second;
    attachment.live = false;
    attachment.note = "detached";
    const auto module = state.modules.find(attachment.uid.value());
    if (module == state.modules.end()) {
      return ok_status();
    }
    ModuleRecord& record = module->second;
    if (record.incarnation != attachment.incarnation) {
      // The attachment belonged to a superseded incarnation: nothing to update.
      return ok_status();
    }
    if (lifecycle_state_implies_attachment(record.state)) {
      if (!lifecycle_transition_allowed(record.state, LifecycleState::Removed)) {
        return Status(StatusCode::Internal, "a physically attached module must be removable");
      }
      LifecycleEvent event;
      event.from = record.state;
      event.to = LifecycleState::Removed;
      event.incarnation = record.incarnation;
      event.reason = "module detached from slot " + slot.str();
      event.source = authority.source;
      event.source_epoch = authority.epoch;
      event.generation = generation;
      event.sequence = sequence;
      event.wall_ns = impl_->clock->wall_now_ns();
      record.state = LifecycleState::Removed;
      record.state_generation = generation;
      record.state_sequence = sequence;
      record.state_wall_ns = event.wall_ns;
      record.lifecycle.push_back(event);
      while (record.lifecycle.size() > impl_->config.max_lifecycle_history) {
        record.lifecycle.erase(record.lifecycle.begin());
      }
    }
    return ok_status();
  });
}

Result<AttachmentRecord> Registry::attachment_of_slot(const SlotKey& slot) const {
  const StatePtr state = impl_->current();
  const auto it = state->attachments.find(slot.str());
  if (it == state->attachments.end() || !it->second.live) {
    return make_error(StatusCode::NotFound, "no live attachment exists for this slot");
  }
  return it->second;
}

Result<AttachmentRecord> Registry::attachment_of_module(const ModuleHandle& module) const {
  const StatePtr state = impl_->current();
  for (const auto& entry : state->attachments) {
    if (entry.second.live && entry.second.uid == module.uid && entry.second.incarnation == module.incarnation) {
      return entry.second;
    }
  }
  return make_error(StatusCode::NotFound, "this module incarnation is not attached to any slot");
}

std::vector<SlotKey> Registry::slots() const {
  const StatePtr state = impl_->current();
  std::vector<SlotKey> keys;
  keys.reserve(state->attachments.size());
  for (const auto& entry : state->attachments) {
    const Result<SlotKey> parsed = SlotKey::parse(entry.first, "slot key");
    if (parsed.ok()) {
      keys.push_back(parsed.value());
    }
  }
  return keys;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

Status Registry::ingest_health(const AuthorityToken& authority, const ModuleHandle& module,
                               const HealthSampleInput& sample, MutationPolicy policy) {
  if (sample.metric == HealthMetric::Unknown || sample.metric == HealthMetric::Unsupported) {
    return Status(StatusCode::Unsupported, "this runtime does not model the requested health metric");
  }
  if (sample.lane != kModuleLane && sample.lane > impl_->config.max_lane_index) {
    return Status(StatusCode::InvalidArgument, "lane index is out of range");
  }
  if (sample.presence == SamplePresence::Present) {
    if (!std::isfinite(sample.value)) {
      return Status(StatusCode::InvalidArgument, "a measurement must be a finite number");
    }
    double min_value = 0.0;
    double max_value = 0.0;
    if (!metric_plausible_range(sample.metric, min_value, max_value)) {
      return Status(StatusCode::InvalidArgument, "the metric has no plausible range");
    }
    if (sample.value < min_value || sample.value > max_value) {
      return Status(StatusCode::InvalidArgument, "the measurement is outside the plausible range for this metric");
    }
  }
  TRXREG_TRY(validate_provenance(sample.provenance));

  const WallNs now = impl_->clock->wall_now_ns();
  if (sample.observed_at_wall_ns > now + impl_->config.max_future_skew_ns) {
    return Status(StatusCode::ClockSkew, "the observation timestamp is in the future");
  }

  return impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced,
                    "the referenced module incarnation was replaced; its telemetry is fenced");
    }

    const ClockDomainId domain = sample.clock_domain.valid() ? sample.clock_domain : impl_->clock->domain();
    std::uint64_t monotonic = sample.observed_at_monotonic_ns;
    if (monotonic == 0 && domain == impl_->clock->domain()) {
      monotonic = impl_->clock->monotonic_now_ns();
    }
    const WallNs observed = sample.observed_at_wall_ns == 0 ? now : sample.observed_at_wall_ns;

    // Replay and reordering protection inside one clock domain: a source may not
    // move its own series backwards in monotonic time.
    if (monotonic != 0) {
      for (const HealthSample& existing : record.samples) {
        if (existing.source != authority.source || existing.metric != sample.metric ||
            existing.lane != sample.lane || existing.clock_domain != domain) {
          continue;
        }
        if (existing.observed_at_monotonic_ns != 0 && existing.observed_at_monotonic_ns >= monotonic) {
          return Status(StatusCode::Refused,
                        "the observation is not newer than the last one recorded for this series");
        }
      }
    }

    HealthSample stored;
    stored.metric = sample.metric;
    stored.lane = sample.lane;
    stored.presence = sample.presence;
    stored.value = sample.presence == SamplePresence::Present ? sample.value : 0.0;
    stored.observed_at_wall_ns = observed;
    stored.observed_at_monotonic_ns = monotonic;
    stored.clock_domain = domain;
    stored.provenance = sample.provenance;
    stored.source = authority.source;
    stored.source_epoch = authority.epoch;
    stored.module = record.uid;
    stored.incarnation = record.incarnation;
    stored.generation = generation;
    stored.sequence = sequence;
    stored.live = true;
    record.samples.push_back(std::move(stored));
    record.series_counts[{static_cast<std::uint8_t>(sample.metric), sample.lane}] += 1;

    if (sample.presence == SamplePresence::Present) {
      // The threshold vector must outlive the pointer taken from it.
      const std::vector<HealthThreshold> thresholds = live_thresholds(state);
      const HealthThreshold* threshold = detail::select_threshold(thresholds, sample.metric, sample.lane);
      if (threshold != nullptr) {
        HealthLatchRecord* latch = find_latch(record, sample.metric, sample.lane);
        if (latch == nullptr) {
          HealthLatchRecord created;
          created.metric = sample.metric;
          created.lane = sample.lane;
          record.latches.push_back(created);
          latch = &record.latches.back();
        }
        latch->latch = advance_latch(*threshold, latch->latch, sample.value, observed, sequence, generation);
      }
    }

    return trim_samples(state, record, impl_->config);
  });
}

namespace {

std::vector<HealthThreshold> collect_live_thresholds(const State& state) {
  std::vector<HealthThreshold> thresholds;
  thresholds.reserve(state.thresholds.size());
  for (const ThresholdRecord& record : state.thresholds) {
    if (record.live) {
      thresholds.push_back(record.threshold);
    }
  }
  return thresholds;
}

}  // namespace

std::vector<HealthThreshold> live_thresholds(const State& state) { return collect_live_thresholds(state); }

Status Registry::publish_threshold(const AuthorityToken& authority, const HealthThreshold& threshold,
                                   MutationPolicy policy) {
  TRXREG_TRY(detail::validate_threshold(threshold));
  TRXREG_TRY(validate_provenance(threshold.provenance));
  return impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{},
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    for (ThresholdRecord& record : state.thresholds) {
      if (record.live && record.threshold.metric == threshold.metric && record.threshold.lane == threshold.lane) {
        record.live = false;
      }
    }
    std::size_t live = 0;
    for (const ThresholdRecord& record : state.thresholds) {
      if (record.live) {
        ++live;
      }
    }
    if (live >= impl_->config.max_thresholds) {
      return Status(StatusCode::CapacityExceeded, "threshold budget is exhausted");
    }
    ThresholdRecord record;
    record.threshold = threshold;
    record.threshold.source = authority.source;
    record.threshold.source_epoch = authority.epoch;
    record.threshold.generation = generation;
    record.threshold.sequence = sequence;
    record.threshold.live = true;
    state.thresholds.push_back(std::move(record));

    std::uint32_t history = 0;
    for (std::size_t i = 0; i < state.thresholds.size(); ++i) {
      const ThresholdRecord& candidate = state.thresholds[i];
      if (candidate.threshold.metric != threshold.metric || candidate.threshold.lane != threshold.lane) {
        continue;
      }
      ++history;
    }
    while (history > impl_->config.max_claim_history) {
      for (std::size_t i = 0; i < state.thresholds.size(); ++i) {
        if (!state.thresholds[i].live && state.thresholds[i].threshold.metric == threshold.metric &&
            state.thresholds[i].threshold.lane == threshold.lane) {
          state.thresholds.erase(state.thresholds.begin() + static_cast<std::ptrdiff_t>(i));
          --history;
          break;
        }
      }
      break;
    }
    return ok_status();
  });
}

Result<HealthReport> Registry::health(const ModuleHandle& module) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  if (!incarnation_is_current(record, module.incarnation)) {
    return make_error(StatusCode::Fenced,
                      "the referenced module incarnation was replaced; its evidence does not describe the replacement");
  }
  return build_health_report(*state, record, impl_->config, impl_->clock);
}

Result<std::vector<HealthSample>> Registry::samples(const ModuleHandle& module, const SampleQuery& query) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  const std::vector<HealthSample> marked = live_samples(*state, record, module.incarnation);

  std::vector<HealthSample> out;
  for (const HealthSample& sample : marked) {
    if (query.metric != HealthMetric::Unknown && sample.metric != query.metric) {
      continue;
    }
    if (!query.all_lanes && sample.lane != query.lane) {
      continue;
    }
    if (!query.include_superseded && !sample.live) {
      continue;
    }
    if (!query.include_superseded && sample.incarnation != module.incarnation) {
      continue;
    }
    out.push_back(sample);
  }
  std::sort(out.begin(), out.end(), [](const HealthSample& lhs, const HealthSample& rhs) {
    if (lhs.observed_at_wall_ns != rhs.observed_at_wall_ns) {
      return lhs.observed_at_wall_ns > rhs.observed_at_wall_ns;
    }
    return lhs.sequence > rhs.sequence;
  });
  if (out.size() > query.limit) {
    out.resize(static_cast<std::size_t>(query.limit));
  }
  return out;
}

Result<HealthLatch> Registry::latch(const ModuleHandle& module, HealthMetric metric, std::uint16_t lane) const {
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  if (!incarnation_is_current(it->second, module.incarnation)) {
    return make_error(StatusCode::Fenced, "the referenced module incarnation was replaced");
  }
  const HealthLatchRecord* found = find_latch(it->second, metric, lane);
  if (found == nullptr) {
    return HealthLatch{};
  }
  return found->latch;
}


// ---------------------------------------------------------------------------
// Health report construction
// ---------------------------------------------------------------------------

namespace {

bool is_threshold_zone(MetricState state) noexcept {
  return state == MetricState::Ok || state == MetricState::Degraded || state == MetricState::Critical;
}

bool is_fresh_state(MetricState state) noexcept {
  return is_threshold_zone(state) || state == MetricState::Unclassified;
}

}  // namespace

HealthReport build_health_report(const State& state, const ModuleRecord& record, const RegistryConfig& config,
                                 const ClockPtr& clock) {
  const WallNs now = clock->wall_now_ns();
  HealthReport report;
  report.uid = record.uid;
  report.incarnation = record.incarnation;
  report.generation = state.generation;
  report.evaluated_at_wall_ns = now;
  report.clock_domain = clock->domain();

  const std::vector<HealthThreshold> thresholds = live_thresholds(state);

  // Series considered for this module: published policy, ingested evidence, and
  // the telemetry the module declares that it can report.
  std::vector<std::pair<std::uint8_t, std::uint16_t>> rows;
  const auto add_row = [&rows](HealthMetric metric, std::uint16_t lane) {
    const std::pair<std::uint8_t, std::uint16_t> key{static_cast<std::uint8_t>(metric), lane};
    if (std::find(rows.begin(), rows.end(), key) == rows.end()) {
      rows.push_back(key);
    }
  };
  for (const HealthThreshold& threshold : thresholds) {
    add_row(threshold.metric, threshold.lane);
  }
  for (const HealthSample& sample : record.samples) {
    if (sample.incarnation == record.incarnation) {
      add_row(sample.metric, sample.lane);
    }
  }
  for (const CapabilityDeclaration& declaration : record.declarations) {
    if (declaration.incarnation != record.incarnation || !declaration.live) {
      continue;
    }
    HealthMetric metric = HealthMetric::Unknown;
    if (!detail::telemetry_capability_metric(declaration.key, metric)) {
      continue;
    }
    bool declared = false;
    if (!declaration.value.as_boolean(declared) || !declared) {
      continue;
    }
    add_row(metric, kModuleLane);
  }
  std::sort(rows.begin(), rows.end());
  report.metrics.reserve(rows.size());

  std::vector<HealthSample> marked;
  marked.reserve(record.samples.size());
  for (const HealthSample& sample : record.samples) {
    HealthSample copy = sample;
    copy.live = sample.incarnation == record.incarnation && source_is_live(state, sample.source, sample.source_epoch);
    marked.push_back(std::move(copy));
  }

  std::size_t fresh_rows = 0;
  std::size_t stale_rows = 0;
  std::size_t unknown_rows = 0;
  std::size_t conflicting_rows = 0;
  std::size_t fenced_rows = 0;
  MetricState worst = MetricState::Ok;

  for (const auto& row : rows) {
    const HealthMetric metric_key = static_cast<HealthMetric>(row.first);
    const std::uint16_t lane = row.second;

    std::vector<HealthSample> series;
    for (const HealthSample& sample : marked) {
      if (sample.metric == metric_key && sample.lane == lane) {
        series.push_back(sample);
      }
    }

    const HealthThreshold* threshold = detail::select_threshold(thresholds, metric_key, lane);
    detail::SeriesClassification classification = detail::classify_series(
        series, threshold, record.uid, record.incarnation, now, config.max_future_skew_ns);

    MetricHealth metric;
    metric.metric = metric_key;
    metric.lane = lane;
    metric.state = classification.state;
    metric.has_value = classification.has_value;
    metric.value = classification.value;
    metric.has_age = classification.has_age;
    metric.age_ns = classification.age_ns;
    metric.fresh_count = classification.fresh;
    metric.stale_count = classification.stale;
    metric.fenced_count = classification.fenced;
    metric.source_count = classification.sources;
    metric.sample_count = static_cast<std::int64_t>(series.size());
    metric.reason = classification.reason;

    // The evidence path decides freshness, absence, and conflict. Hysteresis
    // only refines a classification that the evidence path already produced.
    if (is_threshold_zone(classification.state)) {
      const HealthLatchRecord* latch = find_latch(record, metric_key, lane);
      if (latch != nullptr && is_threshold_zone(latch->latch.state)) {
        metric.state = latch->latch.state;
        metric.reason = "latched classification with hysteresis";
      }
    }

    HealthIssue issue;
    issue.metric = metric_key;
    issue.lane = lane;
    switch (metric.state) {
      case MetricState::Stale:
        issue.kind = classification.reason_kind;
        issue.detail = classification.reason;
        report.issues.push_back(issue);
        ++stale_rows;
        break;
      case MetricState::Unknown:
        issue.kind = classification.reason_kind;
        issue.detail = classification.reason;
        report.issues.push_back(issue);
        ++unknown_rows;
        break;
      case MetricState::Fenced:
        issue.kind = HealthIssueKind::Fenced;
        issue.detail = classification.reason;
        report.issues.push_back(issue);
        ++fenced_rows;
        break;
      case MetricState::Conflicting:
        issue.kind = HealthIssueKind::SourceConflict;
        issue.detail = classification.reason;
        report.issues.push_back(issue);
        ++conflicting_rows;
        break;
      case MetricState::Unclassified:
        issue.kind = HealthIssueKind::NoThreshold;
        issue.detail = classification.reason;
        report.issues.push_back(issue);
        ++fresh_rows;
        break;
      case MetricState::Ok:
      case MetricState::Degraded:
      case MetricState::Critical:
        ++fresh_rows;
        break;
    }

    const int severity = metric_state_severity(metric.state);
    if (severity > metric_state_severity(worst) || report.metrics.empty()) {
      worst = metric.state;
    }
    report.metrics.push_back(std::move(metric));
  }

  if (report.metrics.empty()) {
    report.outcome = HealthOutcome::Unknown;
    report.worst = MetricState::Unknown;
  } else {
    report.worst = worst;
    const std::size_t total = report.metrics.size();
    if (conflicting_rows > 0) {
      report.outcome = HealthOutcome::Conflicting;
    } else if (fenced_rows == total) {
      report.outcome = HealthOutcome::Fenced;
    } else if (unknown_rows == total) {
      report.outcome = HealthOutcome::Unknown;
    } else if (stale_rows == total) {
      report.outcome = HealthOutcome::Stale;
    } else if (fresh_rows == total) {
      report.outcome = HealthOutcome::Fresh;
    } else {
      report.outcome = HealthOutcome::Partial;
    }
  }

  CanonicalWriter writer;
  writer.begin_object(8);
  writer.field("incarnation");
  writer.integer(static_cast<std::int64_t>(report.incarnation.value()));
  writer.field("metrics");
  writer.begin_array(static_cast<std::uint64_t>(report.metrics.size()));
  for (const MetricHealth& metric : report.metrics) {
    writer.begin_object(4);
    writer.field("lane");
    writer.integer(static_cast<std::int64_t>(metric.lane));
    writer.field("metric");
    writer.integer(static_cast<std::int64_t>(metric.metric));
    writer.field("state");
    writer.integer(static_cast<std::int64_t>(metric.state));
    writer.field("value");
    if (metric.has_value) {
      writer.real(metric.value);
    } else {
      writer.null_value();
    }
    writer.end_object();
  }
  writer.end_array();
  writer.field("outcome");
  writer.integer(static_cast<std::int64_t>(report.outcome));
  writer.field("uid");
  writer.integer(static_cast<std::int64_t>(report.uid.value()));
  writer.field("worst");
  writer.integer(static_cast<std::int64_t>(report.worst));
  writer.end_object();
  report.digest = writer.digest();

  return report;
}


// ---------------------------------------------------------------------------
// Compatibility
// ---------------------------------------------------------------------------

Result<CompatRuleHandle> Registry::publish_rule(const AuthorityToken& authority, const CompatRule& rule,
                                                MutationPolicy policy) {
  TRXREG_TRY(detail::validate_rule(rule));
  TRXREG_TRY(validate_provenance(rule.provenance));
  CompatRuleHandle handle;
  const Status status = impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{},
                                      [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    if (state.rules.size() >= impl_->config.max_rules) {
      return Status(StatusCode::CapacityExceeded, "compatibility rule budget is exhausted");
    }
    CompatRuleRecord record;
    record.id = RuleId{static_cast<std::uint32_t>(state.next_rule_id)};
    state.next_rule_id += 1;
    record.rule = rule;
    record.rule.provenance = rule.provenance;
    record.source = authority.source;
    record.source_epoch = authority.epoch;
    record.generation = generation;
    record.sequence = sequence;
    record.live = true;
    handle.id = record.id;
    handle.generation = generation;
    state.rules[record.id.value()] = std::move(record);
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return handle;
}

Status Registry::retire_rule(const AuthorityToken& authority, RuleId id, MutationPolicy policy) {
  return impl_->mutate(policy == MutationPolicy::RequireGeneration, Generation{},
                       [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.rules.find(id.value());
    if (it == state.rules.end()) {
      return Status(StatusCode::NotFound, "no such compatibility rule");
    }
    if (!it->second.live) {
      return Status(StatusCode::Conflict, "the compatibility rule is already retired");
    }
    it->second.live = false;
    it->second.generation = generation;
    it->second.sequence = sequence;
    return ok_status();
  });
}

std::vector<CompatRuleRecord> Registry::rules() const {
  const StatePtr state = impl_->current();
  std::vector<CompatRuleRecord> out;
  out.reserve(state->rules.size());
  for (const auto& entry : state->rules) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(), [](const CompatRuleRecord& lhs, const CompatRuleRecord& rhs) {
    if (lhs.rule.priority != rhs.rule.priority) {
      return lhs.rule.priority > rhs.rule.priority;
    }
    return lhs.id < rhs.id;
  });
  return out;
}

Result<CompatDecision> Registry::query_compatibility(const CompatQuery& query) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  if (!query.uid.valid() || !query.incarnation.valid()) {
    return make_error(StatusCode::InvalidArgument, "a compatibility query must name a module incarnation");
  }
  if (query.port.empty()) {
    return make_error(StatusCode::InvalidArgument, "a compatibility query must name a host port");
  }
  const StatePtr state = impl_->current();
  if (query.require_latest_generation && query.expected_generation.valid() &&
      query.expected_generation != state->generation) {
    return make_error(StatusCode::StaleGeneration,
                      "the compatibility query was fenced against generation " +
                          std::to_string(query.expected_generation.value()) + " but the registry is at generation " +
                          std::to_string(state->generation.value()));
  }
  const auto it = state->modules.find(query.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  if (!incarnation_is_current(record, query.incarnation)) {
    return make_error(StatusCode::Fenced,
                      "the referenced module incarnation was replaced; its capabilities do not describe the replacement");
  }

  const std::vector<CapabilityConsensus> module_attributes =
      detail::build_capability_consensus(live_declarations(*state, record, record.incarnation));
  std::vector<CapabilityConsensus> port_attributes;
  const auto port = state->ports.find(query.port.str());
  if (port != state->ports.end()) {
    port_attributes = detail::build_capability_consensus(live_port_declarations(*state, port->second));
  }

  const AttributeResolver resolver = [&](RequirementSubject subject, CapabilityKey key,
                                         std::string_view subkey) -> const CapabilityConsensus* {
    const std::vector<CapabilityConsensus>& source =
        subject == RequirementSubject::Module ? module_attributes : port_attributes;
    for (const CapabilityConsensus& attribute : source) {
      if (attribute.key == key && attribute.subkey == subkey) {
        return &attribute;
      }
    }
    return nullptr;
  };

  std::vector<CompatRuleRecord> live;
  live.reserve(state->rules.size());
  for (const auto& entry : state->rules) {
    if (entry.second.live) {
      live.push_back(entry.second);
    }
  }

  return evaluate_compatibility(query, live, resolver, state->generation, impl_->clock->wall_now_ns(),
                                impl_->clock->domain());
}

Status Registry::verify_decision(const CompatDecision& decision) const {
  return verify_generation(decision.generation);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Result<LifecycleEvent> Registry::transition(const AuthorityToken& authority, const ModuleHandle& module,
                                            LifecycleState to, std::string reason, MutationPolicy policy) {
  if (reason.size() > 512) {
    return make_error(StatusCode::InvalidArgument, "lifecycle reason is too long");
  }
  LifecycleEvent result;
  const Status status = impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                                      [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced,
                    "the referenced module incarnation was replaced; its lifecycle cannot be advanced");
    }
    if (!lifecycle_transition_allowed(record.state, to)) {
      return Status(StatusCode::InvalidTransition,
                    std::string("transition from ") + std::string(to_string(record.state)) + " to " +
                        std::string(to_string(to)) + " is not permitted");
    }
    const WallNs now = impl_->clock->wall_now_ns();
    LifecycleEvent event;
    event.from = record.state;
    event.to = to;
    event.incarnation = record.incarnation;
    event.reason = std::move(reason);
    event.source = authority.source;
    event.source_epoch = authority.epoch;
    event.generation = generation;
    event.sequence = sequence;
    event.wall_ns = now;
    record.state = to;
    record.state_generation = generation;
    record.state_sequence = sequence;
    record.state_wall_ns = now;
    record.lifecycle.push_back(event);
    while (record.lifecycle.size() > impl_->config.max_lifecycle_history) {
      record.lifecycle.erase(record.lifecycle.begin());
    }
    result = event;
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return result;
}

Result<LifecycleEvent> Registry::reconcile_lifecycle(const AuthorityToken& authority, const ModuleHandle& module,
                                                     MutationPolicy policy) {
  LifecycleEvent result;
  const Status status = impl_->mutate(policy == MutationPolicy::RequireGeneration, module.generation,
                                      [&](State& state, Generation generation, Sequence sequence) {
    TRXREG_TRY(require_authority(state, authority));
    const auto it = state.modules.find(module.uid.value());
    if (it == state.modules.end()) {
      return Status(StatusCode::NotFound, "no such module");
    }
    ModuleRecord& record = it->second;
    if (!incarnation_is_current(record, module.incarnation)) {
      return Status(StatusCode::Fenced, "the referenced module incarnation was replaced");
    }
    const WallNs now = impl_->clock->wall_now_ns();
    const HealthReport report = build_health_report(state, record, impl_->config, impl_->clock);

    LifecycleState target = record.state;
    const bool unhealthy = report.worst == MetricState::Critical || report.worst == MetricState::Degraded;
    const bool healthy = report.outcome == HealthOutcome::Fresh && report.worst == MetricState::Ok;
    // Reconciliation only ever follows evidence: a module becomes Active when
    // fresh nominal evidence supports it, Degraded when fresh evidence says so,
    // and is left alone when the evidence is missing, stale, or conflicted.
    if (unhealthy && (record.state == LifecycleState::Active || record.state == LifecycleState::Attached)) {
      target = LifecycleState::Degraded;
    } else if (healthy && (record.state == LifecycleState::Degraded || record.state == LifecycleState::Attached)) {
      target = LifecycleState::Active;
    }

    if (target == record.state) {
      result.from = record.state;
      result.to = record.state;
      result.incarnation = record.incarnation;
      result.reason = "no transition required";
      result.source = authority.source;
      result.source_epoch = authority.epoch;
      result.generation = generation;
      result.sequence = Sequence{};
      result.wall_ns = now;
      return ok_status();
    }
    if (!lifecycle_transition_allowed(record.state, target)) {
      return Status(StatusCode::InvalidTransition,
                    std::string("health reconciliation would need an illegal transition from ") +
                        std::string(to_string(record.state)) + " to " + std::string(to_string(target)));
    }
    LifecycleEvent event;
    event.from = record.state;
    event.to = target;
    event.incarnation = record.incarnation;
    event.reason = target == LifecycleState::Degraded ? "health evidence indicates degradation"
                                                      : "health evidence is fresh and nominal";
    event.source = authority.source;
    event.source_epoch = authority.epoch;
    event.generation = generation;
    event.sequence = sequence;
    event.wall_ns = now;
    record.state = target;
    record.state_generation = generation;
    record.state_sequence = sequence;
    record.state_wall_ns = now;
    record.lifecycle.push_back(event);
    while (record.lifecycle.size() > impl_->config.max_lifecycle_history) {
      record.lifecycle.erase(record.lifecycle.begin());
    }
    result = event;
    return ok_status();
  });
  if (!status.ok()) {
    return status.error();
  }
  return result;
}

Result<LifecycleState> Registry::lifecycle_state(const ModuleHandle& module) const {
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  if (!incarnation_is_current(it->second, module.incarnation)) {
    return make_error(StatusCode::Fenced, "the referenced module incarnation was replaced");
  }
  return it->second.state;
}

Result<std::vector<LifecycleEvent>> Registry::lifecycle_history(const ModuleHandle& module) const {
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  std::vector<LifecycleEvent> events;
  events.reserve(it->second.lifecycle.size());
  for (const LifecycleEvent& event : it->second.lifecycle) {
    if (event.incarnation == module.incarnation) {
      events.push_back(event);
    }
  }
  return events;
}

// ---------------------------------------------------------------------------
// Evidence inspection
// ---------------------------------------------------------------------------

Result<std::vector<IdentityClaim>> Registry::claim_history(const ModuleHandle& module, const ClaimQuery& query) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  std::vector<IdentityClaim> out;
  for (const IdentityClaim& claim : record.claims) {
    if (claim.incarnation != module.incarnation) {
      continue;
    }
    if (query.field != IdentityField::Unknown && claim.field != query.field) {
      continue;
    }
    IdentityClaim copy = claim;
    copy.live = source_is_live(*state, claim.source, claim.source_epoch) && !claim_shadowed(record.claims, claim);
    if (!query.include_superseded && !copy.live) {
      continue;
    }
    out.push_back(std::move(copy));
  }
  std::sort(out.begin(), out.end(), [](const IdentityClaim& lhs, const IdentityClaim& rhs) {
    return lhs.sequence < rhs.sequence;
  });
  if (out.size() > query.limit) {
    out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(query.limit));
  }
  return out;
}

Result<std::vector<CapabilityDeclaration>> Registry::declaration_history(const ModuleHandle& module,
                                                                        const DeclarationQuery& query) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  std::vector<CapabilityDeclaration> out;
  for (const CapabilityDeclaration& declaration : record.declarations) {
    if (declaration.incarnation != module.incarnation) {
      continue;
    }
    if (query.key != CapabilityKey::Unknown && declaration.key != query.key) {
      continue;
    }
    CapabilityDeclaration copy = declaration;
    copy.live = source_is_live(*state, declaration.source, declaration.source_epoch) &&
                !declaration_shadowed(record.declarations, declaration);
    if (!query.include_superseded && !copy.live) {
      continue;
    }
    out.push_back(std::move(copy));
  }
  std::sort(out.begin(), out.end(), [](const CapabilityDeclaration& lhs, const CapabilityDeclaration& rhs) {
    return lhs.sequence < rhs.sequence;
  });
  if (out.size() > query.limit) {
    out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(query.limit));
  }
  return out;
}

Result<EvidenceSummary> Registry::evidence_summary(const ModuleHandle& module) const {
  impl_->queries.fetch_add(1, std::memory_order_relaxed);
  const StatePtr state = impl_->current();
  const auto it = state->modules.find(module.uid.value());
  if (it == state->modules.end()) {
    return make_error(StatusCode::NotFound, "no such module");
  }
  const ModuleRecord& record = it->second;
  if (!incarnation_is_current(record, module.incarnation)) {
    return make_error(StatusCode::Fenced, "the referenced module incarnation was replaced");
  }

  EvidenceSummary summary;
  summary.uid = record.uid;
  summary.incarnation = record.incarnation;
  summary.generation = state->generation;

  const std::vector<IdentityClaim> claims = live_claims(*state, record, record.incarnation);
  for (const IdentityClaim& claim : claims) {
    if (claim.live) {
      ++summary.live_claims;
    } else {
      ++summary.superseded_claims;
    }
  }
  const std::vector<CapabilityDeclaration> declarations = live_declarations(*state, record, record.incarnation);
  for (const CapabilityDeclaration& declaration : declarations) {
    if (declaration.live) {
      ++summary.live_declarations;
    } else {
      ++summary.superseded_declarations;
    }
  }

  const std::vector<HealthThreshold> thresholds = live_thresholds(*state);
  bool first_sample = true;
  for (const HealthSample& sample : record.samples) {
    if (sample.incarnation != record.incarnation) {
      ++summary.fenced_samples;
      continue;
    }
    if (!source_is_live(*state, sample.source, sample.source_epoch)) {
      ++summary.superseded_declarations;
      continue;
    }
    ++summary.live_samples;
    const HealthThreshold* threshold = detail::select_threshold(thresholds, sample.metric, sample.lane);
    const WallNs now = impl_->clock->wall_now_ns();
    const WallNs age = now > sample.observed_at_wall_ns ? now - sample.observed_at_wall_ns : 0;
    if (threshold == nullptr || age > threshold->max_age_ns) {
      ++summary.stale_samples;
    }
    if (first_sample || sample.observed_at_wall_ns < summary.oldest_sample_wall_ns) {
      summary.oldest_sample_wall_ns = sample.observed_at_wall_ns;
    }
    if (first_sample || sample.observed_at_wall_ns > summary.newest_sample_wall_ns) {
      summary.newest_sample_wall_ns = sample.observed_at_wall_ns;
    }
    first_sample = false;
  }

  const std::vector<FieldConsensus> fields = detail::build_identity_consensus(live_claims(*state, record, record.incarnation));
  for (const FieldConsensus& field : fields) {
    if (field.outcome == ConsensusOutcome::Conflicting) {
      ++summary.conflicting_attributes;
    }
  }
  const std::vector<CapabilityConsensus> attributes =
      detail::build_capability_consensus(live_declarations(*state, record, record.incarnation));
  for (const CapabilityConsensus& attribute : attributes) {
    if (attribute.outcome == ConsensusOutcome::Conflicting) {
      ++summary.conflicting_attributes;
    }
  }

  CanonicalWriter writer;
  writer.begin_object(8);
  writer.field("conflicting");
  writer.integer(summary.conflicting_attributes);
  writer.field("fenced_samples");
  writer.integer(static_cast<std::int64_t>(summary.fenced_samples));
  writer.field("incarnation");
  writer.integer(static_cast<std::int64_t>(summary.incarnation.value()));
  writer.field("live_claims");
  writer.integer(static_cast<std::int64_t>(summary.live_claims));
  writer.field("live_declarations");
  writer.integer(static_cast<std::int64_t>(summary.live_declarations));
  writer.field("live_samples");
  writer.integer(static_cast<std::int64_t>(summary.live_samples));
  writer.field("stale_samples");
  writer.integer(static_cast<std::int64_t>(summary.stale_samples));
  writer.field("uid");
  writer.integer(static_cast<std::int64_t>(summary.uid.value()));
  writer.end_object();
  summary.digest = writer.digest();
  return summary;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

Status Registry::save(const std::string& path, const SaveOptions& options) const {
  return save_snapshot(*this, path, options);
}

Result<LoadReport> Registry::load(const std::string& path, const LoadOptions& options) {
  return load_snapshot(*this, path, options);
}

Status Registry::enable_autosave(std::string path, SaveOptions options) {
  if (path.empty()) {
    return Status(StatusCode::InvalidArgument, "an autosave path is required");
  }
  std::unique_lock<std::mutex> lock(impl_->autosave_mutex);
  impl_->autosave_path = std::move(path);
  impl_->autosave_options = options;
  impl_->autosave_enabled = true;
  return ok_status();
}

void Registry::disable_autosave() {
  std::unique_lock<std::mutex> lock(impl_->autosave_mutex);
  impl_->autosave_enabled = false;
  impl_->autosave_path.clear();
}

RegistryImpl& RegistryAccess::impl(Registry& registry) { return *registry.impl_; }

const RegistryImpl& RegistryAccess::impl(const Registry& registry) { return *registry.impl_; }

}  // namespace trxreg
