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

#include "trxreg/taxonomy.hpp"

#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

// Canonical rendering and parsing of the vendor-neutral vocabulary.
//
// The canonical string of an enumerator inserts '_' before every uppercase
// letter that opens a word and lowercases the rest, so `RsFec528` renders as
// "rs_fec528" and `BaseR` as "base_r". Parsing is the exact inverse and is
// ASCII case-insensitive; it never allocates and never consults a locale.

namespace trxreg {
namespace {

/// Immutable association of one enumerator with its canonical rendering.
template <class Enum>
struct EnumNameEntry {
  std::string_view name;
  Enum value;
};

/// Rendering returned for every value that no enumerator claims.
constexpr std::string_view kUnknownName{"unknown"};

/// ASCII-only lowercasing: the canonical vocabulary is locale independent.
constexpr char to_lower_ascii(char value) noexcept {
  constexpr char kUpperFirst = 'A';
  constexpr char kUpperLast = 'Z';
  constexpr char kCaseOffset = static_cast<char>('a' - 'A');
  return (value >= kUpperFirst && value <= kUpperLast) ? static_cast<char>(value + kCaseOffset) : value;
}

bool equals_ascii_case_insensitive(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    if (to_lower_ascii(lhs[index]) != to_lower_ascii(rhs[index])) {
      return false;
    }
  }
  return true;
}

/// Canonical rendering of a value; "unknown" for anything out of range.
template <class Enum, std::size_t Count>
std::string_view canonical_name_of(const EnumNameEntry<Enum> (&table)[Count], Enum value) noexcept {
  for (std::size_t index = 0; index < Count; ++index) {
    if (table[index].value == value) {
      return table[index].name;
    }
  }
  return kUnknownName;
}

/// Parse an exact canonical name. `out` is written only on success.
template <class Enum, std::size_t Count>
bool enum_from_string(std::string_view text, Enum& out, const EnumNameEntry<Enum> (&table)[Count]) noexcept {
  if (text.empty()) {
    return false;
  }
  for (std::size_t index = 0; index < Count; ++index) {
    if (equals_ascii_case_insensitive(text, table[index].name)) {
      out = table[index].value;
      return true;
    }
  }
  return false;
}

constexpr EnumNameEntry<ModuleFamily> kModuleFamilyNames[] = {
  {"unknown", ModuleFamily::Unknown},
  {"optical_transceiver", ModuleFamily::OpticalTransceiver},
  {"active_optical_cable", ModuleFamily::ActiveOpticalCable},
  {"direct_attach_copper", ModuleFamily::DirectAttachCopper},
  {"passive_copper_cable", ModuleFamily::PassiveCopperCable},
  {"electrical_transceiver", ModuleFamily::ElectricalTransceiver},
  {"loopback_module", ModuleFamily::LoopbackModule},
  {"backplane_assembly", ModuleFamily::BackplaneAssembly},
  {"unsupported", ModuleFamily::Unsupported},
};

constexpr EnumNameEntry<MediaClass> kMediaClassNames[] = {
  {"unknown", MediaClass::Unknown},
  {"multimode_fiber", MediaClass::MultimodeFiber},
  {"single_mode_fiber", MediaClass::SingleModeFiber},
  {"twinaxial_copper", MediaClass::TwinaxialCopper},
  {"shielded_twisted_pair", MediaClass::ShieldedTwistedPair},
  {"backplane_copper", MediaClass::BackplaneCopper},
  {"unsupported", MediaClass::Unsupported},
};

constexpr EnumNameEntry<ConnectorClass> kConnectorClassNames[] = {
  {"unknown", ConnectorClass::Unknown},
  {"lc", ConnectorClass::Lc},
  {"sc", ConnectorClass::Sc},
  {"mpo12", ConnectorClass::Mpo12},
  {"mpo16", ConnectorClass::Mpo16},
  {"cs", ConnectorClass::Cs},
  {"sn", ConnectorClass::Sn},
  {"mdc", ConnectorClass::Mdc},
  {"rj45", ConnectorClass::Rj45},
  {"twinax", ConnectorClass::Twinax},
  {"backplane", ConnectorClass::Backplane},
  {"unsupported", ConnectorClass::Unsupported},
};

constexpr EnumNameEntry<SpeedClass> kSpeedClassNames[] = {
  {"unknown", SpeedClass::Unknown},
  {"mb100", SpeedClass::Mb100},
  {"gb1", SpeedClass::Gb1},
  {"gb10", SpeedClass::Gb10},
  {"gb25", SpeedClass::Gb25},
  {"gb40", SpeedClass::Gb40},
  {"gb50", SpeedClass::Gb50},
  {"gb100", SpeedClass::Gb100},
  {"gb200", SpeedClass::Gb200},
  {"gb400", SpeedClass::Gb400},
  {"gb800", SpeedClass::Gb800},
  {"gb1600", SpeedClass::Gb1600},
  {"unsupported", SpeedClass::Unsupported},
};

constexpr EnumNameEntry<EncodingClass> kEncodingClassNames[] = {
  {"unknown", EncodingClass::Unknown},
  {"nrz", EncodingClass::Nrz},
  {"pam4", EncodingClass::Pam4},
  {"unsupported", EncodingClass::Unsupported},
};

constexpr EnumNameEntry<FecClass> kFecClassNames[] = {
  {"unknown", FecClass::Unknown},
  {"none", FecClass::None},
  {"firecode", FecClass::Firecode},
  {"rs_fec528", FecClass::RsFec528},
  {"rs_fec544", FecClass::RsFec544},
  {"base_r", FecClass::BaseR},
  {"unsupported", FecClass::Unsupported},
};

constexpr EnumNameEntry<ReachClass> kReachClassNames[] = {
  {"unknown", ReachClass::Unknown},
  {"very_short_reach", ReachClass::VeryShortReach},
  {"short_reach", ReachClass::ShortReach},
  {"intermediate_reach", ReachClass::IntermediateReach},
  {"long_reach", ReachClass::LongReach},
  {"extended_reach", ReachClass::ExtendedReach},
  {"unsupported", ReachClass::Unsupported},
};

constexpr EnumNameEntry<PowerClass> kPowerClassNames[] = {
  {"unknown", PowerClass::Unknown},
  {"class1", PowerClass::Class1},
  {"class2", PowerClass::Class2},
  {"class3", PowerClass::Class3},
  {"class4", PowerClass::Class4},
  {"class5", PowerClass::Class5},
  {"class6", PowerClass::Class6},
  {"class7", PowerClass::Class7},
  {"class8", PowerClass::Class8},
  {"unsupported", PowerClass::Unsupported},
};

constexpr EnumNameEntry<WavelengthGrid> kWavelengthGridNames[] = {
  {"unknown", WavelengthGrid::Unknown},
  {"none", WavelengthGrid::None},
  {"cwdm4", WavelengthGrid::Cwdm4},
  {"lan_wdm", WavelengthGrid::LanWdm},
  {"dwdm", WavelengthGrid::Dwdm},
  {"swdm", WavelengthGrid::Swdm},
  {"unsupported", WavelengthGrid::Unsupported},
};

constexpr EnumNameEntry<HealthMetric> kHealthMetricNames[] = {
  {"unknown", HealthMetric::Unknown},
  {"temperature_celsius", HealthMetric::TemperatureCelsius},
  {"supply_voltage_volts", HealthMetric::SupplyVoltageVolts},
  {"tx_power_dbm", HealthMetric::TxPowerDbm},
  {"rx_power_dbm", HealthMetric::RxPowerDbm},
  {"tx_bias_current_milliamps", HealthMetric::TxBiasCurrentMilliamps},
  {"lane_skew_picoseconds", HealthMetric::LaneSkewPicoseconds},
  {"unsupported", HealthMetric::Unsupported},
};

constexpr EnumNameEntry<IdentityField> kIdentityFieldNames[] = {
  {"unknown", IdentityField::Unknown},
  {"vendor", IdentityField::Vendor},
  {"part_number", IdentityField::PartNumber},
  {"serial_number", IdentityField::SerialNumber},
  {"revision", IdentityField::Revision},
  {"vendor_oui", IdentityField::VendorOui},
  {"date_code", IdentityField::DateCode},
  {"firmware_version", IdentityField::FirmwareVersion},
  {"firmware_build", IdentityField::FirmwareBuild},
  {"eeprom_content_digest", IdentityField::EepromContentDigest},
  {"vendor_specific", IdentityField::VendorSpecific},
};

constexpr EnumNameEntry<CapabilityKey> kCapabilityKeyNames[] = {
  {"unknown", CapabilityKey::Unknown},
  {"module_family", CapabilityKey::ModuleFamily},
  {"media_class", CapabilityKey::MediaClass},
  {"connector_class", CapabilityKey::ConnectorClass},
  {"lane_count", CapabilityKey::LaneCount},
  {"speed_classes", CapabilityKey::SpeedClasses},
  {"encodings", CapabilityKey::Encodings},
  {"fec_modes", CapabilityKey::FecModes},
  {"wavelengths", CapabilityKey::Wavelengths},
  {"wavelength_grid", CapabilityKey::WavelengthGrid},
  {"wavelength_tunable", CapabilityKey::WavelengthTunable},
  {"reach_class", CapabilityKey::ReachClass},
  {"power_class", CapabilityKey::PowerClass},
  {"max_power_milli_watts", CapabilityKey::MaxPowerMilliWatts},
  {"operating_temperature_min_celsius", CapabilityKey::OperatingTemperatureMinCelsius},
  {"operating_temperature_max_celsius", CapabilityKey::OperatingTemperatureMaxCelsius},
  {"temperature_telemetry", CapabilityKey::TemperatureTelemetry},
  {"voltage_telemetry", CapabilityKey::VoltageTelemetry},
  {"tx_power_telemetry", CapabilityKey::TxPowerTelemetry},
  {"rx_power_telemetry", CapabilityKey::RxPowerTelemetry},
  {"bias_current_telemetry", CapabilityKey::BiasCurrentTelemetry},
  {"lane_skew_telemetry", CapabilityKey::LaneSkewTelemetry},
  {"digital_diagnostic_monitoring", CapabilityKey::DigitalDiagnosticMonitoring},
  {"vendor_specific", CapabilityKey::VendorSpecific},
  {"unsupported", CapabilityKey::Unsupported},
};

constexpr EnumNameEntry<CapabilityValueKind> kCapabilityValueKindNames[] = {
  {"none", CapabilityValueKind::None},
  {"boolean", CapabilityValueKind::Boolean},
  {"count", CapabilityValueKind::Count},
  {"real", CapabilityValueKind::Real},
  {"enum", CapabilityValueKind::Enum},
  {"enum_set", CapabilityValueKind::EnumSet},
  {"text", CapabilityValueKind::Text},
  {"text_set", CapabilityValueKind::TextSet},
  {"spectrum", CapabilityValueKind::Spectrum},
};

constexpr EnumNameEntry<RequirementSubject> kRequirementSubjectNames[] = {
  {"module", RequirementSubject::Module},
  {"port", RequirementSubject::Port},
};

constexpr EnumNameEntry<RequirementOp> kRequirementOpNames[] = {
  {"unknown", RequirementOp::Unknown},
  {"equals", RequirementOp::Equals},
  {"not_equals", RequirementOp::NotEquals},
  {"in", RequirementOp::In},
  {"not_in", RequirementOp::NotIn},
  {"superset_of", RequirementOp::SupersetOf},
  {"subset_of", RequirementOp::SubsetOf},
  {"overlaps", RequirementOp::Overlaps},
  {"disjoint_from", RequirementOp::DisjointFrom},
  {"at_most", RequirementOp::AtMost},
  {"at_least", RequirementOp::AtLeast},
};

constexpr EnumNameEntry<CompatVerdict> kCompatVerdictNames[] = {
  {"unknown", CompatVerdict::Unknown},
  {"compatible", CompatVerdict::Compatible},
  {"incompatible", CompatVerdict::Incompatible},
  {"unsupported", CompatVerdict::Unsupported},
};

constexpr EnumNameEntry<ConsensusOutcome> kConsensusOutcomeNames[] = {
  {"unknown", ConsensusOutcome::Unknown},
  {"single_source", ConsensusOutcome::SingleSource},
  {"agreed", ConsensusOutcome::Agreed},
  {"conflicting", ConsensusOutcome::Conflicting},
  {"superseded", ConsensusOutcome::Superseded},
};

constexpr EnumNameEntry<MetricState> kMetricStateNames[] = {
  {"unknown", MetricState::Unknown},
  {"ok", MetricState::Ok},
  {"degraded", MetricState::Degraded},
  {"critical", MetricState::Critical},
  {"stale", MetricState::Stale},
  {"conflicting", MetricState::Conflicting},
  {"unclassified", MetricState::Unclassified},
  {"fenced", MetricState::Fenced},
};

constexpr EnumNameEntry<HealthOutcome> kHealthOutcomeNames[] = {
  {"unknown", HealthOutcome::Unknown},
  {"fresh", HealthOutcome::Fresh},
  {"partial", HealthOutcome::Partial},
  {"stale", HealthOutcome::Stale},
  {"conflicting", HealthOutcome::Conflicting},
  {"fenced", HealthOutcome::Fenced},
};

constexpr EnumNameEntry<SamplePresence> kSamplePresenceNames[] = {
  {"present", SamplePresence::Present},
  {"not_available", SamplePresence::NotAvailable},
  {"read_error", SamplePresence::ReadError},
  {"not_supported", SamplePresence::NotSupported},
};

constexpr EnumNameEntry<EvidenceKind> kEvidenceKindNames[] = {
  {"real", EvidenceKind::Real},
  {"synthetic", EvidenceKind::Synthetic},
  {"unsupported", EvidenceKind::Unsupported},
};

constexpr EnumNameEntry<LifecycleState> kLifecycleStateNames[] = {
  {"discovered", LifecycleState::Discovered},
  {"registered", LifecycleState::Registered},
  {"attached", LifecycleState::Attached},
  {"active", LifecycleState::Active},
  {"degraded", LifecycleState::Degraded},
  {"quarantined", LifecycleState::Quarantined},
  {"removed", LifecycleState::Removed},
  {"retired", LifecycleState::Retired},
  {"replaced", LifecycleState::Replaced},
};

constexpr EnumNameEntry<MutationPolicy> kMutationPolicyNames[] = {
  {"require_generation", MutationPolicy::RequireGeneration},
  {"auto_retry", MutationPolicy::AutoRetry},
};

}  // namespace

std::string_view to_string(ModuleFamily value) noexcept { return canonical_name_of(kModuleFamilyNames, value); }
std::string_view to_string(MediaClass value) noexcept { return canonical_name_of(kMediaClassNames, value); }
std::string_view to_string(ConnectorClass value) noexcept { return canonical_name_of(kConnectorClassNames, value); }
std::string_view to_string(SpeedClass value) noexcept { return canonical_name_of(kSpeedClassNames, value); }
std::string_view to_string(EncodingClass value) noexcept { return canonical_name_of(kEncodingClassNames, value); }
std::string_view to_string(FecClass value) noexcept { return canonical_name_of(kFecClassNames, value); }
std::string_view to_string(ReachClass value) noexcept { return canonical_name_of(kReachClassNames, value); }
std::string_view to_string(PowerClass value) noexcept { return canonical_name_of(kPowerClassNames, value); }
std::string_view to_string(WavelengthGrid value) noexcept { return canonical_name_of(kWavelengthGridNames, value); }
std::string_view to_string(HealthMetric value) noexcept { return canonical_name_of(kHealthMetricNames, value); }
std::string_view to_string(IdentityField value) noexcept { return canonical_name_of(kIdentityFieldNames, value); }
std::string_view to_string(CapabilityKey value) noexcept { return canonical_name_of(kCapabilityKeyNames, value); }
std::string_view to_string(CapabilityValueKind value) noexcept { return canonical_name_of(kCapabilityValueKindNames, value); }
std::string_view to_string(RequirementSubject value) noexcept { return canonical_name_of(kRequirementSubjectNames, value); }
std::string_view to_string(RequirementOp value) noexcept { return canonical_name_of(kRequirementOpNames, value); }
std::string_view to_string(CompatVerdict value) noexcept { return canonical_name_of(kCompatVerdictNames, value); }
std::string_view to_string(ConsensusOutcome value) noexcept { return canonical_name_of(kConsensusOutcomeNames, value); }
std::string_view to_string(MetricState value) noexcept { return canonical_name_of(kMetricStateNames, value); }
std::string_view to_string(HealthOutcome value) noexcept { return canonical_name_of(kHealthOutcomeNames, value); }
std::string_view to_string(SamplePresence value) noexcept { return canonical_name_of(kSamplePresenceNames, value); }
std::string_view to_string(EvidenceKind value) noexcept { return canonical_name_of(kEvidenceKindNames, value); }
std::string_view to_string(LifecycleState value) noexcept { return canonical_name_of(kLifecycleStateNames, value); }
std::string_view to_string(MutationPolicy value) noexcept { return canonical_name_of(kMutationPolicyNames, value); }

bool module_family_from_string(std::string_view text, ModuleFamily& out) noexcept {
  return enum_from_string(text, out, kModuleFamilyNames);
}
bool media_class_from_string(std::string_view text, MediaClass& out) noexcept {
  return enum_from_string(text, out, kMediaClassNames);
}
bool connector_class_from_string(std::string_view text, ConnectorClass& out) noexcept {
  return enum_from_string(text, out, kConnectorClassNames);
}
bool speed_class_from_string(std::string_view text, SpeedClass& out) noexcept {
  return enum_from_string(text, out, kSpeedClassNames);
}
bool encoding_class_from_string(std::string_view text, EncodingClass& out) noexcept {
  return enum_from_string(text, out, kEncodingClassNames);
}
bool fec_class_from_string(std::string_view text, FecClass& out) noexcept {
  return enum_from_string(text, out, kFecClassNames);
}
bool reach_class_from_string(std::string_view text, ReachClass& out) noexcept {
  return enum_from_string(text, out, kReachClassNames);
}
bool power_class_from_string(std::string_view text, PowerClass& out) noexcept {
  return enum_from_string(text, out, kPowerClassNames);
}
bool wavelength_grid_from_string(std::string_view text, WavelengthGrid& out) noexcept {
  return enum_from_string(text, out, kWavelengthGridNames);
}
bool health_metric_from_string(std::string_view text, HealthMetric& out) noexcept {
  return enum_from_string(text, out, kHealthMetricNames);
}
bool identity_field_from_string(std::string_view text, IdentityField& out) noexcept {
  return enum_from_string(text, out, kIdentityFieldNames);
}
bool capability_key_from_string(std::string_view text, CapabilityKey& out) noexcept {
  return enum_from_string(text, out, kCapabilityKeyNames);
}
bool requirement_op_from_string(std::string_view text, RequirementOp& out) noexcept {
  return enum_from_string(text, out, kRequirementOpNames);
}
bool requirement_subject_from_string(std::string_view text, RequirementSubject& out) noexcept {
  return enum_from_string(text, out, kRequirementSubjectNames);
}
bool compat_verdict_from_string(std::string_view text, CompatVerdict& out) noexcept {
  return enum_from_string(text, out, kCompatVerdictNames);
}
bool evidence_kind_from_string(std::string_view text, EvidenceKind& out) noexcept {
  return enum_from_string(text, out, kEvidenceKindNames);
}
bool lifecycle_state_from_string(std::string_view text, LifecycleState& out) noexcept {
  return enum_from_string(text, out, kLifecycleStateNames);
}
bool sample_presence_from_string(std::string_view text, SamplePresence& out) noexcept {
  return enum_from_string(text, out, kSamplePresenceNames);
}
bool mutation_policy_from_string(std::string_view text, MutationPolicy& out) noexcept {
  return enum_from_string(text, out, kMutationPolicyNames);
}

CapabilityValueKind capability_value_kind(CapabilityKey key) noexcept {
  switch (key) {
    case CapabilityKey::ModuleFamily:
    case CapabilityKey::MediaClass:
    case CapabilityKey::ConnectorClass:
    case CapabilityKey::ReachClass:
    case CapabilityKey::PowerClass:
    case CapabilityKey::WavelengthGrid:
      return CapabilityValueKind::Enum;
    case CapabilityKey::LaneCount:
      return CapabilityValueKind::Count;
    case CapabilityKey::SpeedClasses:
    case CapabilityKey::Encodings:
    case CapabilityKey::FecModes:
      return CapabilityValueKind::EnumSet;
    case CapabilityKey::Wavelengths:
      return CapabilityValueKind::Spectrum;
    case CapabilityKey::WavelengthTunable:
    case CapabilityKey::TemperatureTelemetry:
    case CapabilityKey::VoltageTelemetry:
    case CapabilityKey::TxPowerTelemetry:
    case CapabilityKey::RxPowerTelemetry:
    case CapabilityKey::BiasCurrentTelemetry:
    case CapabilityKey::LaneSkewTelemetry:
    case CapabilityKey::DigitalDiagnosticMonitoring:
      return CapabilityValueKind::Boolean;
    case CapabilityKey::MaxPowerMilliWatts:
    case CapabilityKey::OperatingTemperatureMinCelsius:
    case CapabilityKey::OperatingTemperatureMaxCelsius:
      return CapabilityValueKind::Real;
    case CapabilityKey::VendorSpecific:
      return CapabilityValueKind::Text;
    case CapabilityKey::Unknown:
    case CapabilityKey::Unsupported:
      return CapabilityValueKind::None;
  }
  return CapabilityValueKind::None;
}

bool metric_plausible_range(HealthMetric metric, double& min_value, double& max_value) noexcept {
  switch (metric) {
    case HealthMetric::TemperatureCelsius:
      min_value = -40.0;
      max_value = 150.0;
      return true;
    case HealthMetric::SupplyVoltageVolts:
      min_value = 0.0;
      max_value = 5.0;
      return true;
    case HealthMetric::TxPowerDbm:
      min_value = -40.0;
      max_value = 20.0;
      return true;
    case HealthMetric::RxPowerDbm:
      min_value = -40.0;
      max_value = 20.0;
      return true;
    case HealthMetric::TxBiasCurrentMilliamps:
      min_value = 0.0;
      max_value = 500.0;
      return true;
    case HealthMetric::LaneSkewPicoseconds:
      min_value = 0.0;
      max_value = 10000000.0;
      return true;
    case HealthMetric::Unknown:
    case HealthMetric::Unsupported:
      return false;
  }
  return false;
}

std::uint64_t speed_class_bits_per_second(SpeedClass value) noexcept {
  switch (value) {
    case SpeedClass::Mb100:
      return 100'000'000ULL;
    case SpeedClass::Gb1:
      return 1'000'000'000ULL;
    case SpeedClass::Gb10:
      return 10'000'000'000ULL;
    case SpeedClass::Gb25:
      return 25'000'000'000ULL;
    case SpeedClass::Gb40:
      return 40'000'000'000ULL;
    case SpeedClass::Gb50:
      return 50'000'000'000ULL;
    case SpeedClass::Gb100:
      return 100'000'000'000ULL;
    case SpeedClass::Gb200:
      return 200'000'000'000ULL;
    case SpeedClass::Gb400:
      return 400'000'000'000ULL;
    case SpeedClass::Gb800:
      return 800'000'000'000ULL;
    case SpeedClass::Gb1600:
      return 1'600'000'000'000ULL;
    case SpeedClass::Unknown:
    case SpeedClass::Unsupported:
      return 0;
  }
  return 0;
}

int metric_state_severity(MetricState state) noexcept {
  switch (state) {
    case MetricState::Critical:
      return 5;
    case MetricState::Degraded:
      return 4;
    case MetricState::Conflicting:
      return 3;
    case MetricState::Stale:
      return 2;
    case MetricState::Fenced:
      return 2;
    case MetricState::Unknown:
      return 1;
    case MetricState::Unclassified:
      return 1;
    case MetricState::Ok:
      return 0;
  }
  // An unrecognised state carries no evidence, so it ranks with Unknown.
  return 1;
}

// ---------------------------------------------------------------------------
// Renderers for the enums declared outside this header
// ---------------------------------------------------------------------------

std::string_view to_string(HealthIssueKind kind) noexcept {
  switch (kind) {
    case HealthIssueKind::Missing:
      return "missing";
    case HealthIssueKind::Stale:
      return "stale";
    case HealthIssueKind::Fenced:
      return "fenced";
    case HealthIssueKind::SourceConflict:
      return "source_conflict";
    case HealthIssueKind::NoThreshold:
      return "no_threshold";
    case HealthIssueKind::NotAvailable:
      return "not_available";
    case HealthIssueKind::ReadError:
      return "read_error";
    case HealthIssueKind::NotSupported:
      return "not_supported";
    case HealthIssueKind::FutureTimestamp:
      return "future_timestamp";
    case HealthIssueKind::OutOfRange:
      return "out_of_range";
    case HealthIssueKind::SupersededThreshold:
      return "superseded_threshold";
  }
  return "unknown";
}

bool health_issue_kind_from_string(std::string_view text, HealthIssueKind& out) noexcept {
  static constexpr HealthIssueKind kAll[] = {
      HealthIssueKind::Missing,       HealthIssueKind::Stale,        HealthIssueKind::Fenced,
      HealthIssueKind::SourceConflict, HealthIssueKind::NoThreshold, HealthIssueKind::NotAvailable,
      HealthIssueKind::ReadError,     HealthIssueKind::NotSupported, HealthIssueKind::FutureTimestamp,
      HealthIssueKind::OutOfRange,    HealthIssueKind::SupersededThreshold};
  for (const HealthIssueKind candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(CompatOutcome outcome) noexcept {
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

bool compat_outcome_from_string(std::string_view text, CompatOutcome& out) noexcept {
  static constexpr CompatOutcome kAll[] = {CompatOutcome::Unknown, CompatOutcome::Compatible,
                                           CompatOutcome::Incompatible, CompatOutcome::Unsupported};
  for (const CompatOutcome candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(KnowledgeClosure closure) noexcept {
  switch (closure) {
    case KnowledgeClosure::Open:
      return "open";
    case KnowledgeClosure::Partial:
      return "partial";
    case KnowledgeClosure::Closed:
      return "closed";
  }
  return "open";
}

bool knowledge_closure_from_string(std::string_view text, KnowledgeClosure& out) noexcept {
  static constexpr KnowledgeClosure kAll[] = {KnowledgeClosure::Open, KnowledgeClosure::Partial,
                                              KnowledgeClosure::Closed};
  for (const KnowledgeClosure candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string_view to_string(RequirementState state) noexcept {
  switch (state) {
    case RequirementState::Satisfied:
      return "satisfied";
    case RequirementState::Violated:
      return "violated";
    case RequirementState::Indeterminate:
      return "indeterminate";
  }
  return "indeterminate";
}

bool requirement_state_from_string(std::string_view text, RequirementState& out) noexcept {
  static constexpr RequirementState kAll[] = {RequirementState::Satisfied, RequirementState::Violated,
                                              RequirementState::Indeterminate};
  for (const RequirementState candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

}  // namespace trxreg
