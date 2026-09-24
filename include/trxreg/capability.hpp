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
#include <variant>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// One lane (or the whole module) of a wavelength/frequency descriptor.
struct SpectrumDescriptor {
  /// Lane index, or 0xFFFF for a module-level descriptor.
  std::uint16_t lane{0xFFFF};
  /// Center wavelength in nanometres. Zero when only a frequency is declared.
  double center_nm{0.0};
  /// Center frequency in terahertz. Zero when only a wavelength is declared.
  double frequency_thz{0.0};
  WavelengthGrid grid{WavelengthGrid::Unknown};
  /// Optional channel label, for example `CWDM4-2`.
  std::string channel;

  friend bool operator==(const SpectrumDescriptor& lhs, const SpectrumDescriptor& rhs) noexcept = default;
  friend auto operator<=>(const SpectrumDescriptor& lhs, const SpectrumDescriptor& rhs) noexcept = default;
};

/// A typed capability value. The accepted shape for each key is fixed by
/// `capability_value_kind`, so a mis-shaped publication is rejected at the
/// boundary instead of being silently coerced.
/// A single enumerator stored as its numeric value. Distinct from Count so that
/// the value kind stays observable: an enum capability must never be published
/// or compared as if it were a free integer.
struct EnumValue {
  std::int64_t value{0};

  friend bool operator==(const EnumValue& lhs, const EnumValue& rhs) noexcept = default;
};

class CapabilityValue {
 public:
  using EnumSet = std::vector<std::int64_t>;
  using TextSet = std::vector<std::string>;
  using Spectrum = std::vector<SpectrumDescriptor>;
  using Storage = std::variant<std::monostate, bool, std::int64_t, EnumValue, double, std::string, EnumSet, TextSet,
                               Spectrum>;

  CapabilityValue() = default;

  [[nodiscard]] static CapabilityValue none();
  [[nodiscard]] static CapabilityValue boolean(bool value);
  [[nodiscard]] static CapabilityValue count(std::int64_t value);
  [[nodiscard]] static CapabilityValue real(double value);
  [[nodiscard]] static CapabilityValue text(std::string value);
  /// Enum-valued capabilities store the enum's numeric value.
  [[nodiscard]] static CapabilityValue enumeration(std::int64_t value);
  [[nodiscard]] static CapabilityValue enumeration(EnumValue value);
  [[nodiscard]] static CapabilityValue enum_set(EnumSet values);
  [[nodiscard]] static CapabilityValue text_set(TextSet values);
  [[nodiscard]] static CapabilityValue spectrum(Spectrum values);

  [[nodiscard]] static CapabilityValue of(ModuleFamily value);
  [[nodiscard]] static CapabilityValue of(MediaClass value);
  [[nodiscard]] static CapabilityValue of(ConnectorClass value);
  [[nodiscard]] static CapabilityValue of(ReachClass value);
  [[nodiscard]] static CapabilityValue of(PowerClass value);
  [[nodiscard]] static CapabilityValue of(WavelengthGrid value);
  [[nodiscard]] static CapabilityValue of_speed_classes(std::vector<SpeedClass> values);
  [[nodiscard]] static CapabilityValue of_encodings(std::vector<EncodingClass> values);
  [[nodiscard]] static CapabilityValue of_fec_modes(std::vector<FecClass> values);

  [[nodiscard]] CapabilityValueKind kind() const noexcept;
  [[nodiscard]] bool is_none() const noexcept { return storage_.index() == 0; }
  [[nodiscard]] const Storage& storage() const noexcept { return storage_; }

  [[nodiscard]] bool as_boolean(bool& out) const noexcept;
  [[nodiscard]] bool as_count(std::int64_t& out) const noexcept;
  [[nodiscard]] bool as_real(double& out) const noexcept;
  [[nodiscard]] const std::string* as_text() const noexcept;
  [[nodiscard]] const EnumSet* as_enum_set() const noexcept;
  [[nodiscard]] const TextSet* as_text_set() const noexcept;
  [[nodiscard]] const Spectrum* as_spectrum() const noexcept;
  [[nodiscard]] bool as_enumeration(std::int64_t& out) const noexcept;
  /// Numeric value for Count and Real capabilities.
  [[nodiscard]] bool number_as_double(double& out) const noexcept;

  [[nodiscard]] bool as_family(ModuleFamily& out) const noexcept;
  [[nodiscard]] bool as_media_class(MediaClass& out) const noexcept;
  [[nodiscard]] bool as_connector_class(ConnectorClass& out) const noexcept;
  [[nodiscard]] bool as_reach_class(ReachClass& out) const noexcept;
  [[nodiscard]] bool as_power_class(PowerClass& out) const noexcept;
  [[nodiscard]] bool as_wavelength_grid(WavelengthGrid& out) const noexcept;
  [[nodiscard]] bool as_speed_classes(std::vector<SpeedClass>& out) const noexcept;
  [[nodiscard]] bool as_encodings(std::vector<EncodingClass>& out) const noexcept;
  [[nodiscard]] bool as_fec_modes(std::vector<FecClass>& out) const noexcept;

  /// Validate the shape against the key's required value kind.
  [[nodiscard]] Status validate_for(CapabilityKey key) const;

  /// Human-readable rendering used by the CLI and by explanations.
  [[nodiscard]] std::string describe(CapabilityKey key) const;

  friend bool operator==(const CapabilityValue& lhs, const CapabilityValue& rhs) noexcept = default;

 private:
  Storage storage_{};
};

void write_canonical(CanonicalWriter& writer, const CapabilityValue& value);
Result<CapabilityValue> read_canonical(const Value& encoded, CapabilityValue& value);

/// One capability assertion by one source about one subject.
struct CapabilityDeclaration {
  CapabilityKey key{CapabilityKey::Unknown};
  std::string subkey;
  CapabilityValue value{};
  SourceId source{};
  SourceEpoch source_epoch{};
  ModuleUid module{};
  IncarnationId incarnation{};
  /// Port declarations leave the module fields invalid and set `port`.
  PortKey port{};
  bool module_subject{true};
  Generation generation{};
  Sequence sequence{};
  WallNs observed_at_wall_ns{0};
  ClockDomainId clock_domain{};
  Provenance provenance{};
  bool live{true};

  friend bool operator==(const CapabilityDeclaration& lhs, const CapabilityDeclaration& rhs) noexcept = default;
};

/// Consensus over the live declarations of one attribute.
struct CapabilityConsensus {
  CapabilityKey key{CapabilityKey::Unknown};
  std::string subkey;
  ConsensusOutcome outcome{ConsensusOutcome::Unknown};
  bool has_value{false};
  CapabilityValue value{};
  std::vector<CapabilityDeclaration> declarations;
  std::vector<CapabilityDeclaration> superseded;
  Digest digest{};

  friend bool operator==(const CapabilityConsensus& lhs, const CapabilityConsensus& rhs) noexcept = default;

  [[nodiscard]] bool conflicted() const noexcept { return outcome == ConsensusOutcome::Conflicting; }
  /// True only when the attribute is established by live, agreeing evidence.
  [[nodiscard]] bool established() const noexcept {
    return has_value && (outcome == ConsensusOutcome::Agreed || outcome == ConsensusOutcome::SingleSource);
  }
};

/// Complete capability answer for one subject.
struct CapabilityView {
  bool module_subject{true};
  ModuleUid uid{};
  IncarnationId incarnation{};
  PortKey port{};
  Generation generation{};
  std::vector<CapabilityConsensus> attributes;
  Digest digest{};
  std::uint32_t conflicting_attributes{0};
  std::uint32_t unestablished_attributes{0};

  friend bool operator==(const CapabilityView& lhs, const CapabilityView& rhs) noexcept = default;

  [[nodiscard]] const CapabilityConsensus* find(CapabilityKey key, std::string_view subkey = {}) const noexcept;
};

Digest digest_capability_attributes(const std::vector<CapabilityConsensus>& attributes);

}  // namespace trxreg
