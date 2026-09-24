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

#include "trxreg/capability.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <map>
#include <span>
#include <string>
#include <utility>

#include "domain.hpp"
#include "value_fields.hpp"

namespace trxreg {
namespace {

int compare_bytes(std::string_view lhs, std::string_view rhs) noexcept {
  const std::size_t common = lhs.size() < rhs.size() ? lhs.size() : rhs.size();
  for (std::size_t i = 0; i < common; ++i) {
    const auto left = static_cast<unsigned char>(lhs[i]);
    const auto right = static_cast<unsigned char>(rhs[i]);
    if (left != right) {
      return left < right ? -1 : 1;
    }
  }
  if (lhs.size() == rhs.size()) {
    return 0;
  }
  return lhs.size() < rhs.size() ? -1 : 1;
}

CapabilityValue::EnumSet canonical_enum_set(CapabilityValue::EnumSet values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values;
}

CapabilityValue::TextSet canonical_text_set(CapabilityValue::TextSet values) {
  std::sort(values.begin(), values.end(),
            [](const std::string& lhs, const std::string& rhs) { return compare_bytes(lhs, rhs) < 0; });
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values;
}

CapabilityValue::Spectrum canonical_spectrum(CapabilityValue::Spectrum values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0) {
      out.append(separator);
    }
    out.append(parts[i]);
  }
  return out;
}

/// Human-readable rendering of one enum-valued member of a capability set.
std::string describe_enum_value(CapabilityKey key, std::int64_t value) {
  const auto raw = static_cast<std::uint8_t>(value < 0 ? 0 : (value > 255 ? 255 : value));
  switch (key) {
    case CapabilityKey::ModuleFamily:
      return std::string(to_string(static_cast<ModuleFamily>(raw)));
    case CapabilityKey::MediaClass:
      return std::string(to_string(static_cast<MediaClass>(raw)));
    case CapabilityKey::ConnectorClass:
      return std::string(to_string(static_cast<ConnectorClass>(raw)));
    case CapabilityKey::SpeedClasses:
      return std::string(to_string(static_cast<SpeedClass>(raw)));
    case CapabilityKey::Encodings:
      return std::string(to_string(static_cast<EncodingClass>(raw)));
    case CapabilityKey::FecModes:
      return std::string(to_string(static_cast<FecClass>(raw)));
    case CapabilityKey::ReachClass:
      return std::string(to_string(static_cast<ReachClass>(raw)));
    case CapabilityKey::PowerClass:
      return std::string(to_string(static_cast<PowerClass>(raw)));
    case CapabilityKey::WavelengthGrid:
      return std::string(to_string(static_cast<WavelengthGrid>(raw)));
    default:
      return std::to_string(value);
  }
}
void write_spectrum(CanonicalWriter& writer, const std::vector<SpectrumDescriptor>& spectrum) {
  writer.begin_array(static_cast<std::uint64_t>(spectrum.size()));
  for (const SpectrumDescriptor& descriptor : spectrum) {
    writer.begin_object(5);
    writer.field("center_nm");
    writer.real(descriptor.center_nm);
    writer.field("channel");
    writer.text(descriptor.channel);
    writer.field("frequency_thz");
    writer.real(descriptor.frequency_thz);
    writer.field("grid");
    writer.integer(static_cast<std::int64_t>(descriptor.grid));
    writer.field("lane");
    writer.integer(static_cast<std::int64_t>(descriptor.lane));
    writer.end_object();
  }
  writer.end_array();
}

Result<SpectrumDescriptor> read_spectrum_descriptor(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, detail::as_object(encoded, "spectrum entry"));
  SpectrumDescriptor descriptor;
  TRXREG_TRY_ASSIGN(lane, detail::get_integer(*object, "lane"));
  if (lane < 0 || lane > 65535) {
    return make_error(StatusCode::Malformed, "spectrum lane is out of range");
  }
  descriptor.lane = static_cast<std::uint16_t>(lane);
  TRXREG_TRY_ASSIGN(center_nm, detail::get_real(*object, "center_nm"));
  TRXREG_TRY_ASSIGN(frequency_thz, detail::get_real(*object, "frequency_thz"));
  if (!std::isfinite(center_nm) || !std::isfinite(frequency_thz)) {
    return make_error(StatusCode::Malformed, "spectrum descriptor must be finite");
  }
  if (center_nm < 0.0 || frequency_thz < 0.0) {
    return make_error(StatusCode::Malformed, "spectrum descriptor must not be negative");
  }
  descriptor.center_nm = center_nm;
  descriptor.frequency_thz = frequency_thz;
  TRXREG_TRY_ASSIGN(grid_raw, detail::get_integer(*object, "grid"));
  if (grid_raw < 0 || grid_raw > static_cast<std::int64_t>(WavelengthGrid::Unsupported)) {
    return make_error(StatusCode::Malformed, "spectrum grid is not a known wavelength grid");
  }
  descriptor.grid = static_cast<WavelengthGrid>(grid_raw);
  TRXREG_TRY_ASSIGN(channel, detail::get_text(*object, "channel"));
  descriptor.channel = std::move(channel);
  return descriptor;
}

}  // namespace

CapabilityValue CapabilityValue::none() { return CapabilityValue{}; }

CapabilityValue CapabilityValue::boolean(bool value) {
  CapabilityValue out;
  out.storage_ = value;
  return out;
}

CapabilityValue CapabilityValue::count(std::int64_t value) {
  CapabilityValue out;
  out.storage_ = value;
  return out;
}

CapabilityValue CapabilityValue::real(double value) {
  CapabilityValue out;
  out.storage_ = value;
  return out;
}

CapabilityValue CapabilityValue::text(std::string value) {
  CapabilityValue out;
  out.storage_ = std::move(value);
  return out;
}

CapabilityValue CapabilityValue::enumeration(std::int64_t value) {
  CapabilityValue out;
  out.storage_ = EnumValue{value};
  return out;
}

CapabilityValue CapabilityValue::enumeration(EnumValue value) {
  CapabilityValue out;
  out.storage_ = value;
  return out;
}

CapabilityValue CapabilityValue::enum_set(EnumSet values) {
  CapabilityValue out;
  out.storage_ = canonical_enum_set(std::move(values));
  return out;
}

CapabilityValue CapabilityValue::text_set(TextSet values) {
  CapabilityValue out;
  out.storage_ = canonical_text_set(std::move(values));
  return out;
}

CapabilityValue CapabilityValue::spectrum(Spectrum values) {
  CapabilityValue out;
  out.storage_ = canonical_spectrum(std::move(values));
  return out;
}

CapabilityValue CapabilityValue::of(ModuleFamily value) {
  return enumeration(static_cast<std::int64_t>(value));
}
CapabilityValue CapabilityValue::of(MediaClass value) {
  return enumeration(static_cast<std::int64_t>(value));
}
CapabilityValue CapabilityValue::of(ConnectorClass value) {
  return enumeration(static_cast<std::int64_t>(value));
}
CapabilityValue CapabilityValue::of(ReachClass value) {
  return enumeration(static_cast<std::int64_t>(value));
}
CapabilityValue CapabilityValue::of(PowerClass value) {
  return enumeration(static_cast<std::int64_t>(value));
}
CapabilityValue CapabilityValue::of(WavelengthGrid value) {
  return enumeration(static_cast<std::int64_t>(value));
}

CapabilityValue CapabilityValue::of_speed_classes(std::vector<SpeedClass> values) {
  EnumSet encoded;
  encoded.reserve(values.size());
  for (const SpeedClass value : values) {
    encoded.push_back(static_cast<std::int64_t>(value));
  }
  return enum_set(std::move(encoded));
}

CapabilityValue CapabilityValue::of_encodings(std::vector<EncodingClass> values) {
  EnumSet encoded;
  encoded.reserve(values.size());
  for (const EncodingClass value : values) {
    encoded.push_back(static_cast<std::int64_t>(value));
  }
  return enum_set(std::move(encoded));
}

CapabilityValue CapabilityValue::of_fec_modes(std::vector<FecClass> values) {
  EnumSet encoded;
  encoded.reserve(values.size());
  for (const FecClass value : values) {
    encoded.push_back(static_cast<std::int64_t>(value));
  }
  return enum_set(std::move(encoded));
}

CapabilityValueKind CapabilityValue::kind() const noexcept {
  // Queried by type rather than by variant index so that adding a storage
  // alternative can never silently reclassify an existing kind.
  if (std::holds_alternative<std::monostate>(storage_)) {
    return CapabilityValueKind::None;
  }
  if (std::holds_alternative<bool>(storage_)) {
    return CapabilityValueKind::Boolean;
  }
  if (std::holds_alternative<std::int64_t>(storage_)) {
    return CapabilityValueKind::Count;
  }
  if (std::holds_alternative<EnumValue>(storage_)) {
    return CapabilityValueKind::Enum;
  }
  if (std::holds_alternative<double>(storage_)) {
    return CapabilityValueKind::Real;
  }
  if (std::holds_alternative<std::string>(storage_)) {
    return CapabilityValueKind::Text;
  }
  if (std::holds_alternative<EnumSet>(storage_)) {
    return CapabilityValueKind::EnumSet;
  }
  if (std::holds_alternative<TextSet>(storage_)) {
    return CapabilityValueKind::TextSet;
  }
  return CapabilityValueKind::Spectrum;
}

bool CapabilityValue::as_boolean(bool& out) const noexcept {
  if (const auto* value = std::get_if<bool>(&storage_)) {
    out = *value;
    return true;
  }
  return false;
}

bool CapabilityValue::as_count(std::int64_t& out) const noexcept {
  if (const auto* value = std::get_if<std::int64_t>(&storage_)) {
    out = *value;
    return true;
  }
  return false;
}

bool CapabilityValue::as_enumeration(std::int64_t& out) const noexcept {
  if (const auto* value = std::get_if<EnumValue>(&storage_)) {
    out = value->value;
    return true;
  }
  return false;
}

bool CapabilityValue::number_as_double(double& out) const noexcept {
  if (const auto* integer = std::get_if<std::int64_t>(&storage_)) {
    out = static_cast<double>(*integer);
    return true;
  }
  if (const auto* real = std::get_if<double>(&storage_)) {
    out = *real;
    return true;
  }
  return false;
}

bool CapabilityValue::as_real(double& out) const noexcept {
  if (const auto* value = std::get_if<double>(&storage_)) {
    out = *value;
    return true;
  }
  return false;
}

const std::string* CapabilityValue::as_text() const noexcept { return std::get_if<std::string>(&storage_); }

const CapabilityValue::EnumSet* CapabilityValue::as_enum_set() const noexcept {
  return std::get_if<EnumSet>(&storage_);
}

const CapabilityValue::TextSet* CapabilityValue::as_text_set() const noexcept {
  return std::get_if<TextSet>(&storage_);
}

const CapabilityValue::Spectrum* CapabilityValue::as_spectrum() const noexcept {
  return std::get_if<Spectrum>(&storage_);
}

bool CapabilityValue::as_family(ModuleFamily& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(ModuleFamily::Unsupported)) {
    return false;
  }
  out = static_cast<ModuleFamily>(raw);
  return true;
}

bool CapabilityValue::as_media_class(MediaClass& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(MediaClass::Unsupported)) {
    return false;
  }
  out = static_cast<MediaClass>(raw);
  return true;
}

bool CapabilityValue::as_connector_class(ConnectorClass& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(ConnectorClass::Unsupported)) {
    return false;
  }
  out = static_cast<ConnectorClass>(raw);
  return true;
}

bool CapabilityValue::as_reach_class(ReachClass& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(ReachClass::Unsupported)) {
    return false;
  }
  out = static_cast<ReachClass>(raw);
  return true;
}

bool CapabilityValue::as_power_class(PowerClass& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(PowerClass::Unsupported)) {
    return false;
  }
  out = static_cast<PowerClass>(raw);
  return true;
}

bool CapabilityValue::as_wavelength_grid(WavelengthGrid& out) const noexcept {
  std::int64_t raw = 0;
  if (!as_enumeration(raw) || raw < 0 || raw > static_cast<std::int64_t>(WavelengthGrid::Unsupported)) {
    return false;
  }
  out = static_cast<WavelengthGrid>(raw);
  return true;
}

namespace {

bool enum_set_to_vector(const CapabilityValue::EnumSet& raw, std::uint8_t max_value, std::vector<std::int64_t>& out) {
  for (const std::int64_t value : raw) {
    if (value < 0 || value > static_cast<std::int64_t>(max_value)) {
      return false;
    }
  }
  out.assign(raw.begin(), raw.end());
  return true;
}

}  // namespace

bool CapabilityValue::as_speed_classes(std::vector<SpeedClass>& out) const noexcept {
  const EnumSet* raw = as_enum_set();
  if (raw == nullptr) {
    return false;
  }
  std::vector<std::int64_t> values;
  if (!enum_set_to_vector(*raw, static_cast<std::uint8_t>(SpeedClass::Unsupported), values)) {
    return false;
  }
  out.clear();
  out.reserve(values.size());
  for (const std::int64_t value : values) {
    out.push_back(static_cast<SpeedClass>(value));
  }
  return true;
}

bool CapabilityValue::as_encodings(std::vector<EncodingClass>& out) const noexcept {
  const EnumSet* raw = as_enum_set();
  if (raw == nullptr) {
    return false;
  }
  std::vector<std::int64_t> values;
  if (!enum_set_to_vector(*raw, static_cast<std::uint8_t>(EncodingClass::Unsupported), values)) {
    return false;
  }
  out.clear();
  out.reserve(values.size());
  for (const std::int64_t value : values) {
    out.push_back(static_cast<EncodingClass>(value));
  }
  return true;
}

bool CapabilityValue::as_fec_modes(std::vector<FecClass>& out) const noexcept {
  const EnumSet* raw = as_enum_set();
  if (raw == nullptr) {
    return false;
  }
  std::vector<std::int64_t> values;
  if (!enum_set_to_vector(*raw, static_cast<std::uint8_t>(FecClass::Unsupported), values)) {
    return false;
  }
  out.clear();
  out.reserve(values.size());
  for (const std::int64_t value : values) {
    out.push_back(static_cast<FecClass>(value));
  }
  return true;
}

Status CapabilityValue::validate_for(CapabilityKey key) const {
  const CapabilityValueKind expected = capability_value_kind(key);
  if (expected == CapabilityValueKind::None) {
    return Status(StatusCode::Unsupported, "capability key is not modelled by this runtime");
  }
  if (kind() != expected) {
    return Status(StatusCode::InvalidArgument, std::string("capability value shape does not match key ") +
                                                   std::string(to_string(key)));
  }
  switch (expected) {
    case CapabilityValueKind::Count: {
      std::int64_t value = 0;
      static_cast<void>(as_count(value));
      if (value < 0) {
        return Status(StatusCode::InvalidArgument, "count capability must not be negative");
      }
      break;
    }
    case CapabilityValueKind::Real: {
      double value = 0.0;
      static_cast<void>(as_real(value));
      if (!std::isfinite(value)) {
        return Status(StatusCode::InvalidArgument, "real capability must be finite");
      }
      break;
    }
    case CapabilityValueKind::Enum: {
      std::int64_t raw = 0;
      static_cast<void>(as_enumeration(raw));
      if (raw < 0 || raw > 255) {
        return Status(StatusCode::InvalidArgument, "enum capability is out of range");
      }
      break;
    }
    case CapabilityValueKind::Boolean:
    case CapabilityValueKind::Text:
    case CapabilityValueKind::TextSet:
      break;
    case CapabilityValueKind::EnumSet: {
      const EnumSet* values = as_enum_set();
      for (const std::int64_t value : *values) {
        if (value < 0 || value > 255) {
          return Status(StatusCode::InvalidArgument, "enum set capability contains an out-of-range value");
        }
      }
      break;
    }
    case CapabilityValueKind::Spectrum: {
      const Spectrum* values = as_spectrum();
      for (const SpectrumDescriptor& descriptor : *values) {
        if (!std::isfinite(descriptor.center_nm) || !std::isfinite(descriptor.frequency_thz)) {
          return Status(StatusCode::InvalidArgument, "spectrum descriptor must be finite");
        }
        if (descriptor.center_nm < 0.0 || descriptor.frequency_thz < 0.0) {
          return Status(StatusCode::InvalidArgument, "spectrum descriptor must not be negative");
        }
      }
      break;
    }
    case CapabilityValueKind::None:
      break;
  }
  return ok_status();
}

std::string CapabilityValue::describe(CapabilityKey key) const {
  switch (kind()) {
    case CapabilityValueKind::None:
      return "unset";
    case CapabilityValueKind::Boolean:
      return std::get<bool>(storage_) ? "true" : "false";
    case CapabilityValueKind::Count:
      return std::to_string(std::get<std::int64_t>(storage_));
    case CapabilityValueKind::Enum:
      // Render the enumerator name so explanations stay readable.
      return describe_enum_value(key, std::get<EnumValue>(storage_).value);
    case CapabilityValueKind::Real: {
      const double value = std::get<double>(storage_);
      char buffer[40];
      const int written = std::snprintf(buffer, sizeof(buffer), "%.6g", value);
      return written > 0 ? std::string(buffer, static_cast<std::size_t>(written)) : std::string("nan");
    }
    case CapabilityValueKind::Text:
      return std::get<std::string>(storage_);
    case CapabilityValueKind::EnumSet: {
      const EnumSet& values = std::get<EnumSet>(storage_);
      std::vector<std::string> parts;
      parts.reserve(values.size());
      for (const std::int64_t value : values) {
        parts.push_back(describe_enum_value(key, value));
      }
      return join(parts, ",");
    }
    case CapabilityValueKind::TextSet: {
      const TextSet& values = std::get<TextSet>(storage_);
      return join(values, ",");
    }
    case CapabilityValueKind::Spectrum: {
      const Spectrum& values = std::get<Spectrum>(storage_);
      std::vector<std::string> parts;
      parts.reserve(values.size());
      for (const SpectrumDescriptor& entry : values) {
        char buffer[128];
        const int written = std::snprintf(buffer, sizeof(buffer), "%s%.3g nm/%s", entry.lane == kModuleLane ? "" : "lane:",
                                          entry.center_nm, std::string(to_string(entry.grid)).c_str());
        parts.push_back(written > 0 ? std::string(buffer, static_cast<std::size_t>(written)) : std::string("?"));
      }
      return join(parts, ",");
    }
  }
  return "unset";
}

// ---------------------------------------------------------------------------
// Canonical encoding of capability values
// ---------------------------------------------------------------------------

void write_canonical(CanonicalWriter& writer, const CapabilityValue& value) {
  switch (value.kind()) {
    case CapabilityValueKind::None:
      writer.begin_object(1);
      writer.field("k");
      writer.text("none");
      writer.end_object();
      return;
    case CapabilityValueKind::Boolean: {
      bool raw = false;
      static_cast<void>(value.as_boolean(raw));
      writer.begin_object(2);
      writer.field("b");
      writer.boolean(raw);
      writer.field("k");
      writer.text("boolean");
      writer.end_object();
      return;
    }
    case CapabilityValueKind::Count: {
      std::int64_t raw = 0;
      static_cast<void>(value.as_count(raw));
      writer.begin_object(2);
      writer.field("i");
      writer.integer(raw);
      writer.field("k");
      writer.text("count");
      writer.end_object();
      return;
    }
    case CapabilityValueKind::Enum: {
      std::int64_t raw = 0;
      static_cast<void>(value.as_enumeration(raw));
      writer.begin_object(2);
      writer.field("i");
      writer.integer(raw);
      writer.field("k");
      writer.text("enum");
      writer.end_object();
      return;
    }
    case CapabilityValueKind::Real: {
      double raw = 0.0;
      static_cast<void>(value.as_real(raw));
      writer.begin_object(2);
      writer.field("k");
      writer.text("real");
      writer.field("r");
      writer.real(raw);
      writer.end_object();
      return;
    }
    case CapabilityValueKind::Text: {
      writer.begin_object(2);
      writer.field("k");
      writer.text("text");
      writer.field("t");
      writer.text(value.as_text() != nullptr ? *value.as_text() : std::string_view{});
      writer.end_object();
      return;
    }
    case CapabilityValueKind::EnumSet: {
      const CapabilityValue::EnumSet* values = value.as_enum_set();
      writer.begin_object(2);
      writer.field("k");
      writer.text("enum_set");
      writer.field("s");
      writer.begin_array(static_cast<std::uint64_t>(values->size()));
      for (const std::int64_t entry : *values) {
        writer.integer(entry);
      }
      writer.end_array();
      writer.end_object();
      return;
    }
    case CapabilityValueKind::TextSet: {
      const CapabilityValue::TextSet* values = value.as_text_set();
      writer.begin_object(2);
      writer.field("k");
      writer.text("text_set");
      writer.field("s");
      writer.begin_array(static_cast<std::uint64_t>(values->size()));
      for (const std::string& entry : *values) {
        writer.text(entry);
      }
      writer.end_array();
      writer.end_object();
      return;
    }
    case CapabilityValueKind::Spectrum: {
      const CapabilityValue::Spectrum* values = value.as_spectrum();
      writer.begin_object(2);
      writer.field("k");
      writer.text("spectrum");
      writer.field("s");
      write_spectrum(writer, *values);
      writer.end_object();
      return;
    }
  }
}

Result<CapabilityValue> read_canonical(const Value& encoded, CapabilityValue& value) {
  TRXREG_TRY_ASSIGN(object, detail::as_object(encoded, "capability value"));
  TRXREG_TRY_ASSIGN(kind_text, detail::get_text(*object, "k"));
  if (kind_text == "none") {
    value = CapabilityValue::none();
    return value;
  }
  if (kind_text == "boolean") {
    TRXREG_TRY_ASSIGN(raw, detail::get_boolean(*object, "b"));
    value = CapabilityValue::boolean(raw);
    return value;
  }
  if (kind_text == "count") {
    TRXREG_TRY_ASSIGN(raw, detail::get_integer(*object, "i"));
    if (raw < 0) {
      return make_error(StatusCode::Malformed, "capability count must not be negative");
    }
    value = CapabilityValue::count(raw);
    return value;
  }
  if (kind_text == "enum") {
    TRXREG_TRY_ASSIGN(raw, detail::get_integer(*object, "i"));
    if (raw < 0 || raw > 255) {
      return make_error(StatusCode::Malformed, "capability enum value is out of range");
    }
    value = CapabilityValue::enumeration(raw);
    return value;
  }
  if (kind_text == "real") {
    TRXREG_TRY_ASSIGN(raw, detail::get_real(*object, "r"));
    if (!std::isfinite(raw)) {
      return make_error(StatusCode::Malformed, "capability real must be finite");
    }
    value = CapabilityValue::real(raw);
    return value;
  }
  if (kind_text == "text") {
    TRXREG_TRY_ASSIGN(raw, detail::get_text(*object, "t"));
    value = CapabilityValue::text(std::move(raw));
    return value;
  }
  if (kind_text == "enum_set") {
    TRXREG_TRY_ASSIGN(array, detail::get_array(*object, "s"));
    CapabilityValue::EnumSet values;
    values.reserve(array->size());
    for (const Value& entry : *array) {
      if (!entry.is_integer()) {
        return make_error(StatusCode::Malformed, "enum set entry must be an integer");
      }
      values.push_back(entry.as_integer());
    }
    value = CapabilityValue::enum_set(std::move(values));
    return value;
  }
  if (kind_text == "text_set") {
    TRXREG_TRY_ASSIGN(array, detail::get_array(*object, "s"));
    CapabilityValue::TextSet values;
    values.reserve(array->size());
    for (const Value& entry : *array) {
      if (!entry.is_text()) {
        return make_error(StatusCode::Malformed, "text set entry must be text");
      }
      values.push_back(entry.as_text());
    }
    value = CapabilityValue::text_set(std::move(values));
    return value;
  }
  if (kind_text == "spectrum") {
    TRXREG_TRY_ASSIGN(array, detail::get_array(*object, "s"));
    CapabilityValue::Spectrum values;
    values.reserve(array->size());
    for (const Value& entry : *array) {
      TRXREG_TRY_ASSIGN(descriptor, read_spectrum_descriptor(entry));
      values.push_back(std::move(descriptor));
    }
    value = CapabilityValue::spectrum(std::move(values));
    return value;
  }
  return make_error(StatusCode::Malformed, "unknown capability value kind");
}

// ---------------------------------------------------------------------------
// Consensus
// ---------------------------------------------------------------------------

namespace detail {

bool capability_values_equal(const CapabilityValue& lhs, const CapabilityValue& rhs) noexcept {
  if (lhs.kind() != rhs.kind()) {
    return false;
  }
  switch (lhs.kind()) {
    case CapabilityValueKind::None:
      return true;
    case CapabilityValueKind::Boolean: {
      bool left = false;
      bool right = false;
      static_cast<void>(lhs.as_boolean(left));
      static_cast<void>(rhs.as_boolean(right));
      return left == right;
    }
    case CapabilityValueKind::Count: {
      std::int64_t left = 0;
      std::int64_t right = 0;
      static_cast<void>(lhs.as_count(left));
      static_cast<void>(rhs.as_count(right));
      return left == right;
    }
    case CapabilityValueKind::Enum: {
      std::int64_t left = 0;
      std::int64_t right = 0;
      static_cast<void>(lhs.as_enumeration(left));
      static_cast<void>(rhs.as_enumeration(right));
      return left == right;
    }
    case CapabilityValueKind::Real: {
      double left = 0.0;
      double right = 0.0;
      static_cast<void>(lhs.as_real(left));
      static_cast<void>(rhs.as_real(right));
      return left == right;
    }
    case CapabilityValueKind::Text:
      return *lhs.as_text() == *rhs.as_text();
    case CapabilityValueKind::EnumSet:
      return *lhs.as_enum_set() == *rhs.as_enum_set();
    case CapabilityValueKind::TextSet:
      return *lhs.as_text_set() == *rhs.as_text_set();
    case CapabilityValueKind::Spectrum:
      return *lhs.as_spectrum() == *rhs.as_spectrum();
  }
  return false;
}

namespace {

void write_declaration_canonical(CanonicalWriter& writer, const CapabilityDeclaration& declaration) {
  writer.begin_object(7);
  writer.field("declared_at");
  writer.integer(declaration.observed_at_wall_ns);
  writer.field("generation");
  writer.integer(static_cast<std::int64_t>(declaration.generation.value()));
  writer.field("key");
  writer.integer(static_cast<std::int64_t>(declaration.key));
  writer.field("sequence");
  writer.integer(static_cast<std::int64_t>(declaration.sequence.value()));
  writer.field("source");
  writer.integer(static_cast<std::int64_t>(declaration.source.value()));
  writer.field("source_epoch");
  writer.integer(static_cast<std::int64_t>(declaration.source_epoch.value()));
  writer.field("subkey");
  writer.text(declaration.subkey);
  writer.field("value");
  write_canonical(writer, declaration.value);
  writer.end_object();
}

std::vector<const CapabilityDeclaration*> sorted_live_declarations(
    const std::vector<CapabilityDeclaration>& declarations) {
  std::vector<const CapabilityDeclaration*> live;
  for (const CapabilityDeclaration& declaration : declarations) {
    if (declaration.live) {
      live.push_back(&declaration);
    }
  }
  std::sort(live.begin(), live.end(), [](const auto* lhs, const auto* rhs) {
    if (lhs->source != rhs->source) {
      return lhs->source < rhs->source;
    }
    if (lhs->source_epoch != rhs->source_epoch) {
      return lhs->source_epoch < rhs->source_epoch;
    }
    return lhs->sequence < rhs->sequence;
  });
  return live;
}

}  // namespace

std::vector<CapabilityConsensus> build_capability_consensus(std::vector<CapabilityDeclaration> declarations) {
  // Group by (key, subkey) without relying on the caller's ordering.
  std::map<std::pair<std::uint8_t, std::string>, std::vector<CapabilityDeclaration>> grouped;
  for (CapabilityDeclaration& declaration : declarations) {
    grouped[{static_cast<std::uint8_t>(declaration.key), declaration.subkey}].push_back(std::move(declaration));
  }

  std::vector<CapabilityConsensus> result;
  result.reserve(grouped.size());
  for (auto& entry : grouped) {
    CapabilityConsensus consensus;
    consensus.key = static_cast<CapabilityKey>(entry.first.first);
    consensus.subkey = entry.first.second;

    std::vector<CapabilityDeclaration> live;
    std::vector<CapabilityDeclaration> superseded;
    for (CapabilityDeclaration& declaration : entry.second) {
      if (declaration.live) {
        live.push_back(std::move(declaration));
      } else {
        superseded.push_back(std::move(declaration));
      }
    }

    const auto by_sequence = [](const CapabilityDeclaration& lhs, const CapabilityDeclaration& rhs) {
      return lhs.sequence < rhs.sequence;
    };
    std::stable_sort(live.begin(), live.end(), by_sequence);
    std::stable_sort(superseded.begin(), superseded.end(), by_sequence);

    // A source revising its own declaration supersedes its earlier one; only
    // declarations from different sources are compared.
    std::vector<CapabilityDeclaration> newest_per_source;
    for (CapabilityDeclaration& declaration : live) {
      const auto existing = std::find_if(newest_per_source.begin(), newest_per_source.end(),
                                         [&declaration](const CapabilityDeclaration& other) {
                                           return other.source == declaration.source &&
                                                  other.source_epoch == declaration.source_epoch;
                                         });
      if (existing == newest_per_source.end()) {
        newest_per_source.push_back(std::move(declaration));
      } else {
        superseded.push_back(std::move(*existing));
        *existing = std::move(declaration);
      }
    }
    std::stable_sort(superseded.begin(), superseded.end(), by_sequence);
    live = std::move(newest_per_source);

    if (live.empty()) {
      consensus.outcome = superseded.empty() ? ConsensusOutcome::Unknown : ConsensusOutcome::Superseded;
    } else if (live.size() == 1) {
      consensus.outcome = ConsensusOutcome::SingleSource;
      consensus.has_value = true;
      consensus.value = live.front().value;
    } else {
      bool agrees = true;
      for (std::size_t i = 1; i < live.size(); ++i) {
        if (!capability_values_equal(live.front().value, live[i].value)) {
          agrees = false;
          break;
        }
      }
      consensus.outcome = agrees ? ConsensusOutcome::Agreed : ConsensusOutcome::Conflicting;
      if (agrees) {
        consensus.has_value = true;
        consensus.value = live.front().value;
      }
    }

    consensus.declarations = std::move(live);
    consensus.superseded = std::move(superseded);

    CanonicalWriter writer;
    writer.begin_object(4);
    writer.field("key");
    writer.integer(static_cast<std::int64_t>(consensus.key));
    writer.field("outcome");
    writer.integer(static_cast<std::int64_t>(consensus.outcome));
    writer.field("subkey");
    writer.text(consensus.subkey);
    writer.field("value");
    if (consensus.has_value) {
      write_canonical(writer, consensus.value);
    } else {
      writer.null_value();
    }
    writer.end_object();
    consensus.digest = writer.digest();

    result.push_back(std::move(consensus));
  }
  return result;
}

}  // namespace detail

const CapabilityConsensus* CapabilityView::find(CapabilityKey key, std::string_view subkey) const noexcept {
  for (const CapabilityConsensus& attribute : attributes) {
    if (attribute.key == key && attribute.subkey == subkey) {
      return &attribute;
    }
  }
  return nullptr;
}

Digest digest_capability_attributes(const std::vector<CapabilityConsensus>& attributes) {
  CanonicalWriter writer;
  writer.begin_array(static_cast<std::uint64_t>(attributes.size()));
  for (const CapabilityConsensus& attribute : attributes) {
    writer.begin_object(4);
    writer.field("digest");
    writer.binary(std::as_bytes(std::span<const std::uint8_t>(attribute.digest.bytes.data(), attribute.digest.bytes.size())));
    writer.field("key");
    writer.integer(static_cast<std::int64_t>(attribute.key));
    writer.field("outcome");
    writer.integer(static_cast<std::int64_t>(attribute.outcome));
    writer.field("subkey");
    writer.text(attribute.subkey);
    writer.end_object();
  }
  writer.end_array();
  return writer.digest();
}

}  // namespace trxreg
