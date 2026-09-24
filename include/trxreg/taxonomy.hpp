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
#include <string_view>

#include "trxreg/ids.hpp"
#include "trxreg/result.hpp"

// Vendor-neutral vocabulary of the registry. Every enum is an open-ended
// classification with explicit sentinels:
//   Unknown      - the value has not been established by any source
//   Unsupported  - the registry model intentionally does not cover this value
// Neither sentinel is ever treated as a positive classification.

namespace trxreg {

enum class ModuleFamily : std::uint8_t {
  Unknown = 0,
  OpticalTransceiver,
  ActiveOpticalCable,
  DirectAttachCopper,
  PassiveCopperCable,
  ElectricalTransceiver,
  LoopbackModule,
  BackplaneAssembly,
  Unsupported,
};

enum class MediaClass : std::uint8_t {
  Unknown = 0,
  MultimodeFiber,
  SingleModeFiber,
  TwinaxialCopper,
  ShieldedTwistedPair,
  BackplaneCopper,
  Unsupported,
};

enum class ConnectorClass : std::uint8_t {
  Unknown = 0,
  Lc,
  Sc,
  Mpo12,
  Mpo16,
  Cs,
  Sn,
  Mdc,
  Rj45,
  Twinax,
  Backplane,
  Unsupported,
};

enum class SpeedClass : std::uint8_t {
  Unknown = 0,
  Mb100,
  Gb1,
  Gb10,
  Gb25,
  Gb40,
  Gb50,
  Gb100,
  Gb200,
  Gb400,
  Gb800,
  Gb1600,
  Unsupported,
};

enum class EncodingClass : std::uint8_t {
  Unknown = 0,
  Nrz,
  Pam4,
  Unsupported,
};

enum class FecClass : std::uint8_t {
  Unknown = 0,
  None,
  Firecode,
  RsFec528,
  RsFec544,
  BaseR,
  Unsupported,
};

enum class ReachClass : std::uint8_t {
  Unknown = 0,
  VeryShortReach,
  ShortReach,
  IntermediateReach,
  LongReach,
  ExtendedReach,
  Unsupported,
};

enum class PowerClass : std::uint8_t {
  Unknown = 0,
  Class1,
  Class2,
  Class3,
  Class4,
  Class5,
  Class6,
  Class7,
  Class8,
  Unsupported,
};

enum class WavelengthGrid : std::uint8_t {
  Unknown = 0,
  None,
  Cwdm4,
  LanWdm,
  Dwdm,
  Swdm,
  Unsupported,
};

/// Physical quantity a health sample carries.
enum class HealthMetric : std::uint8_t {
  Unknown = 0,
  TemperatureCelsius,
  SupplyVoltageVolts,
  TxPowerDbm,
  RxPowerDbm,
  TxBiasCurrentMilliamps,
  LaneSkewPicoseconds,
  Unsupported,
};

/// Established identity fields of a module. Identity is what the module *is*,
/// as claimed by a source; it is never mixed with declared capability.
enum class IdentityField : std::uint8_t {
  Unknown = 0,
  Vendor,
  PartNumber,
  SerialNumber,
  Revision,
  VendorOui,
  DateCode,
  FirmwareVersion,
  FirmwareBuild,
  EepromContentDigest,
  VendorSpecific,
};

/// Vendor-neutral capability attributes published about a module or a host port.
enum class CapabilityKey : std::uint8_t {
  Unknown = 0,
  ModuleFamily,
  MediaClass,
  ConnectorClass,
  LaneCount,
  SpeedClasses,
  Encodings,
  FecModes,
  Wavelengths,
  WavelengthGrid,
  WavelengthTunable,
  ReachClass,
  PowerClass,
  MaxPowerMilliWatts,
  OperatingTemperatureMinCelsius,
  OperatingTemperatureMaxCelsius,
  TemperatureTelemetry,
  VoltageTelemetry,
  TxPowerTelemetry,
  RxPowerTelemetry,
  BiasCurrentTelemetry,
  LaneSkewTelemetry,
  DigitalDiagnosticMonitoring,
  VendorSpecific,
  Unsupported,
};

/// Shape of the value a capability key accepts.
enum class CapabilityValueKind : std::uint8_t {
  None = 0,
  Boolean,
  Count,
  Real,
  Enum,
  EnumSet,
  Text,
  TextSet,
  Spectrum,
};

/// Which side of a compatibility query a requirement reads.
enum class RequirementSubject : std::uint8_t {
  Module = 0,
  Port,
};

enum class RequirementOp : std::uint8_t {
  Unknown = 0,
  Equals,
  NotEquals,
  In,
  NotIn,
  SupersetOf,
  SubsetOf,
  Overlaps,
  DisjointFrom,
  AtMost,
  AtLeast,
};

/// The verdict a compatibility rule asserts when its requirements hold.
enum class CompatVerdict : std::uint8_t {
  Unknown = 0,
  Compatible,
  Incompatible,
  Unsupported,
};

/// Result of comparing the live declarations of one attribute.
enum class ConsensusOutcome : std::uint8_t {
  /// No live declaration carries this attribute.
  Unknown = 0,
  /// Exactly one live source declares the attribute.
  SingleSource,
  /// Two or more live sources agree.
  Agreed,
  /// Two or more live sources disagree; every claim stays visible.
  Conflicting,
  /// Only declarations from retired source epochs or fenced incarnations exist.
  Superseded,
};

/// Health classification of one metric series.
enum class MetricState : std::uint8_t {
  /// No usable evidence: nothing sampled, nothing declared, or telemetry absent.
  Unknown = 0,
  Ok,
  Degraded,
  Critical,
  /// Evidence exists but is older than the published freshness bound.
  Stale,
  /// Two live sources disagree beyond the published tolerance.
  Conflicting,
  /// Fresh evidence exists but no threshold is published for this metric.
  Unclassified,
  /// Every sample belongs to a fenced module incarnation.
  Fenced,
};

/// Overall quality of the evidence supporting a health report.
enum class HealthOutcome : std::uint8_t {
  Unknown = 0,
  Fresh,
  Partial,
  Stale,
  Conflicting,
  Fenced,
};

/// What a sample says about a metric.
enum class SamplePresence : std::uint8_t {
  /// A measurement is present in `value`.
  Present = 0,
  /// The module reports the metric as not available right now (for example DDM
  /// not ready). This is evidence of absence, never a zero measurement.
  NotAvailable,
  /// The read failed. This is evidence of a fault, never a healthy measurement.
  ReadError,
  /// The module or the collection path does not support the metric at all.
  NotSupported,
};

/// How the evidence was obtained. The distinction is load-bearing: only Real
/// evidence describes a physical device.
enum class EvidenceKind : std::uint8_t {
  /// Captured from a real device or real transport by an external agent.
  Real = 0,
  /// Produced by a simulator, test fixture, or replay of synthetic input.
  Synthetic,
  /// The registry explicitly does not obtain this evidence in this configuration.
  Unsupported,
};

/// Lifecycle state of one module incarnation.
enum class LifecycleState : std::uint8_t {
  Discovered = 0,
  Registered,
  Attached,
  Active,
  Degraded,
  Quarantined,
  Removed,
  Retired,
  Replaced,
};

/// How a mutation fences itself against concurrent publishers.
enum class MutationPolicy : std::uint8_t {
  /// The caller supplies the generation it observed; a mismatch is refused.
  RequireGeneration = 0,
  /// The registry retries internally against the latest generation, bounded by
  /// the configured retry budget, so independent publishers all land.
  AutoRetry,
};

std::string_view to_string(ModuleFamily value) noexcept;
std::string_view to_string(MediaClass value) noexcept;
std::string_view to_string(ConnectorClass value) noexcept;
std::string_view to_string(SpeedClass value) noexcept;
std::string_view to_string(EncodingClass value) noexcept;
std::string_view to_string(FecClass value) noexcept;
std::string_view to_string(ReachClass value) noexcept;
std::string_view to_string(PowerClass value) noexcept;
std::string_view to_string(WavelengthGrid value) noexcept;
std::string_view to_string(HealthMetric value) noexcept;
std::string_view to_string(IdentityField value) noexcept;
std::string_view to_string(CapabilityKey value) noexcept;
std::string_view to_string(CapabilityValueKind value) noexcept;
std::string_view to_string(RequirementSubject value) noexcept;
std::string_view to_string(RequirementOp value) noexcept;
std::string_view to_string(CompatVerdict value) noexcept;
std::string_view to_string(ConsensusOutcome value) noexcept;
std::string_view to_string(MetricState value) noexcept;
std::string_view to_string(HealthOutcome value) noexcept;
std::string_view to_string(SamplePresence value) noexcept;
std::string_view to_string(EvidenceKind value) noexcept;
std::string_view to_string(LifecycleState value) noexcept;
std::string_view to_string(MutationPolicy value) noexcept;


bool module_family_from_string(std::string_view text, ModuleFamily& out) noexcept;
bool media_class_from_string(std::string_view text, MediaClass& out) noexcept;
bool connector_class_from_string(std::string_view text, ConnectorClass& out) noexcept;
bool speed_class_from_string(std::string_view text, SpeedClass& out) noexcept;
bool encoding_class_from_string(std::string_view text, EncodingClass& out) noexcept;
bool fec_class_from_string(std::string_view text, FecClass& out) noexcept;
bool reach_class_from_string(std::string_view text, ReachClass& out) noexcept;
bool power_class_from_string(std::string_view text, PowerClass& out) noexcept;
bool wavelength_grid_from_string(std::string_view text, WavelengthGrid& out) noexcept;
bool health_metric_from_string(std::string_view text, HealthMetric& out) noexcept;
bool identity_field_from_string(std::string_view text, IdentityField& out) noexcept;
bool capability_key_from_string(std::string_view text, CapabilityKey& out) noexcept;
bool requirement_op_from_string(std::string_view text, RequirementOp& out) noexcept;
bool requirement_subject_from_string(std::string_view text, RequirementSubject& out) noexcept;
bool compat_verdict_from_string(std::string_view text, CompatVerdict& out) noexcept;
bool evidence_kind_from_string(std::string_view text, EvidenceKind& out) noexcept;
bool lifecycle_state_from_string(std::string_view text, LifecycleState& out) noexcept;
bool sample_presence_from_string(std::string_view text, SamplePresence& out) noexcept;
bool mutation_policy_from_string(std::string_view text, MutationPolicy& out) noexcept;

/// Value kind a capability key requires, or None for unknown keys.
CapabilityValueKind capability_value_kind(CapabilityKey key) noexcept;

/// Plausible measurement range for a metric, used to reject telemetry that
/// cannot describe this hardware. Returns false when the metric is not modelled.
bool metric_plausible_range(HealthMetric metric, double& min_value, double& max_value) noexcept;

/// Number of bits per second implied by a speed class, for ordering and display.
/// Returns 0 for Unknown/Unsupported.
std::uint64_t speed_class_bits_per_second(SpeedClass value) noexcept;

/// Relative severity of a metric state for aggregation. Higher is worse.
/// Unknown/Stale/Conflicting/Fenced rank above Ok so that absence of evidence
/// can never dominate a report as if it were health.
int metric_state_severity(MetricState state) noexcept;

}  // namespace trxreg
