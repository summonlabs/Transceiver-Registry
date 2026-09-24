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
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// One identity assertion about one module incarnation, made by one source.
///
/// Claims are never merged across sources. A claim from a newer epoch of the
/// same source supersedes that source's earlier claim for the same field, but
/// the earlier claim remains queryable in history.
struct IdentityClaim {
  IdentityField field{IdentityField::Unknown};
  /// Required when `field == VendorSpecific`; empty otherwise.
  std::string subkey;
  std::string value;
  SourceId source{};
  SourceEpoch source_epoch{};
  ModuleUid module{};
  IncarnationId incarnation{};
  Generation generation{};
  Sequence sequence{};
  WallNs observed_at_wall_ns{0};
  ClockDomainId clock_domain{};
  Provenance provenance{};
  /// True when the claim belongs to the current incarnation and the source's
  /// current epoch. Superseded claims stay visible but never decide anything.
  bool live{true};

  friend bool operator==(const IdentityClaim& lhs, const IdentityClaim& rhs) noexcept = default;
};

/// Identity value supplied at registration or update time.
struct IdentityFieldValue {
  IdentityField field{IdentityField::Unknown};
  std::string subkey;
  std::string value;

  friend bool operator==(const IdentityFieldValue& lhs, const IdentityFieldValue& rhs) noexcept = default;
};

/// Consensus over the live claims for one identity field of one incarnation.
struct FieldConsensus {
  IdentityField field{IdentityField::Unknown};
  std::string subkey;
  ConsensusOutcome outcome{ConsensusOutcome::Unknown};
  bool has_value{false};
  /// Set only when `outcome == Agreed` or `outcome == SingleSource`.
  std::string value;
  std::vector<IdentityClaim> claims;             ///< live claims, at most one per source
  std::vector<IdentityClaim> superseded_claims;  ///< retired epochs / fenced incarnations
  Digest digest{};

  friend bool operator==(const FieldConsensus& lhs, const FieldConsensus& rhs) noexcept = default;

  [[nodiscard]] bool conflicted() const noexcept { return outcome == ConsensusOutcome::Conflicting; }
};

/// Complete identity answer for one module incarnation.
struct IdentityView {
  ModuleUid uid{};
  IncarnationId incarnation{};
  ModuleKey key{};
  Generation generation{};
  LifecycleState lifecycle{LifecycleState::Registered};
  std::vector<FieldConsensus> fields;
  /// Digest over the canonical form of the whole view, including claim provenance.
  Digest digest{};
  /// Number of fields whose live claims disagree.
  std::uint32_t conflicting_fields{0};
  /// Number of fields that have at least one superseded claim.
  std::uint32_t superseded_fields{0};

  friend bool operator==(const IdentityView& lhs, const IdentityView& rhs) noexcept = default;

  [[nodiscard]] const FieldConsensus* find(IdentityField field, std::string_view subkey = {}) const noexcept;
  [[nodiscard]] bool any_conflict() const noexcept { return conflicting_fields > 0; }
};

/// Compute the canonical digest of a set of consensus fields.
Digest digest_identity_fields(const std::vector<FieldConsensus>& fields);

}  // namespace trxreg
