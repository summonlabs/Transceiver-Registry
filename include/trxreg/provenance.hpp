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

#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/result.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// Where a piece of knowledge came from and how it was obtained.
struct Provenance {
  EvidenceKind kind{EvidenceKind::Unsupported};
  /// Coarse origin of the evidence, for example `eeprom-page0`, `probe-agent`,
  /// `operator-config`, `test-fixture`.
  std::string origin;
  /// How it was obtained, for example `read`, `decoded`, `declared`, `imported`.
  std::string method;
  /// Optional digest of the raw captured bytes the claim was derived from.
  Digest content_digest{};
  /// Optional opaque reference to the captured artifact (file, capture id).
  std::string capture_ref;

  friend bool operator==(const Provenance& lhs, const Provenance& rhs) noexcept = default;
};

/// Validate that a provenance record is usable as evidence provenance.
/// `Unsupported` provenance is accepted only for explicitly unsupported claims.
Status validate_provenance(const Provenance& provenance);

/// Description of an evidence source at registration time.
struct SourceDescriptor {
  /// Stable operator-chosen name, for example `probe-agent-1`.
  std::string name;
  /// Free-form description of what the source is.
  std::string description;
  /// What the source is expected to produce; informational, never authority.
  EvidenceKind declared_kind{EvidenceKind::Unsupported};
  /// Identity of the process/agent instance that owns this registration. Used to
  /// distinguish "the same source reconnected" from "a different agent reused
  /// the name": registering an existing name with the same, non-empty instance
  /// id renews that source's current epoch, while a different (or empty)
  /// instance id mints a new epoch and fences the previous one.
  std::string instance_id;

  friend bool operator==(const SourceDescriptor& lhs, const SourceDescriptor& rhs) noexcept = default;
};

/// Authority granted to a source incarnation. Every mutation presents one.
struct AuthorityToken {
  SourceId source{};
  SourceEpoch epoch{};

  friend bool operator==(const AuthorityToken& lhs, const AuthorityToken& rhs) noexcept = default;
};

/// Handle returned by source registration.
struct SourceHandle {
  SourceId id{};
  SourceEpoch epoch{};
  Generation generation{};  ///< Registry generation at which the source was registered.

  [[nodiscard]] AuthorityToken authority() const noexcept { return AuthorityToken{id, epoch}; }

  friend bool operator==(const SourceHandle& lhs, const SourceHandle& rhs) noexcept = default;
};

/// A module plus the exact incarnation the caller is speaking about. Mutations
/// carrying a superseded incarnation are refused rather than applied to the
/// replacement module.
struct ModuleHandle {
  ModuleUid uid{};
  IncarnationId incarnation{};
  /// Fence token for MutationPolicy::RequireGeneration: mutations carrying this
  /// handle are refused unless the registry is still at this generation. A
  /// handle returned by register_module carries the generation at which it was
  /// minted, so any later commit makes it stale by design. Callers that want to
  /// publish against a freshly observed state set this field to
  /// Registry::generation() before the call, or use MutationPolicy::AutoRetry.
  Generation generation{};
  ModuleKey key{};

  friend bool operator==(const ModuleHandle& lhs, const ModuleHandle& rhs) noexcept = default;
};

}  // namespace trxreg
