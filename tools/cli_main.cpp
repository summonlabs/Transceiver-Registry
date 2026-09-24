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

// trxreg_cli: inspection and mutation utility for the Transceiver Registry.
//
// Two modes, one request vocabulary. Every subcommand is turned into the same
// canonical request document the loopback protocol carries; in-process mode
// feeds it to wire::dispatch against the local registry, remote mode sends it
// with wire::Client. The printed document is therefore identical in both modes
// and is always rendered by Value::to_json.
//
// Several subcommands may be given in one invocation; they run in order and a
// module handle learned by one of them is reused by the next, which is what
// lets a registration and an inspection share one source authority.

#include <charconv>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/snapshot.hpp"
#include "trxreg/taxonomy.hpp"
#include "trxreg/version.hpp"
#include "trxreg/wire.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

using trxreg::CapabilityKey;
using trxreg::CapabilityValueKind;
using trxreg::EvidenceKind;
using trxreg::RequirementOp;
using trxreg::RequirementSubject;
using trxreg::StatusCode;
using trxreg::Value;

// ---------------------------------------------------------------------------
// Scalar parsing
// ---------------------------------------------------------------------------

bool parse_signed(std::string_view text, std::int64_t& out) {
  if (text.empty()) {
    return false;
  }
  const char* first = text.data();
  const char* last = text.data() + text.size();
  const std::from_chars_result result = std::from_chars(first, last, out);
  return result.ec == std::errc{} && result.ptr == last;
}

bool parse_double(std::string_view text, double& out) {
  if (text.empty()) {
    return false;
  }
  const char* first = text.data();
  const char* last = text.data() + text.size();
  const std::from_chars_result result = std::from_chars(first, last, out);
  return result.ec == std::errc{} && result.ptr == last;
}

bool parse_unsigned(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  const char* first = text.data();
  const char* last = text.data() + text.size();
  const std::from_chars_result result = std::from_chars(first, last, out);
  return result.ec == std::errc{} && result.ptr == last;
}

bool parse_u32(std::string_view text, std::uint32_t& out) {
  std::uint64_t parsed = 0;
  if (!parse_unsigned(text, parsed) || parsed > 0xFFFFFFFFull) {
    return false;
  }
  out = static_cast<std::uint32_t>(parsed);
  return true;
}

bool parse_u16(std::string_view text, std::uint16_t& out) {
  std::uint64_t parsed = 0;
  if (!parse_unsigned(text, parsed) || parsed > 0xFFFFull) {
    return false;
  }
  out = static_cast<std::uint16_t>(parsed);
  return true;
}

std::vector<std::string_view> split_commas(std::string_view text) {
  std::vector<std::string_view> parts;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::size_t end = comma == std::string_view::npos ? text.size() : comma;
    std::string_view part = text.substr(start, end - start);
    while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) {
      part.remove_prefix(1);
    }
    while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) {
      part.remove_suffix(1);
    }
    parts.push_back(part);
    if (comma == std::string_view::npos) {
      break;
    }
    start = comma + 1;
  }
  return parts;
}

std::uint64_t file_size(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return 0;
  }
  std::uint64_t size = 0;
  if (std::fseek(file, 0, SEEK_END) == 0) {
    const long end = std::ftell(file);
    if (end > 0) {
      size = static_cast<std::uint64_t>(end);
    }
  }
  std::fclose(file);
  return size;
}

bool file_exists(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return false;
  }
  std::fclose(file);
  return true;
}

std::int64_t current_pid() {
#ifdef _WIN32
  return static_cast<std::int64_t>(::_getpid());
#else
  return static_cast<std::int64_t>(::getpid());
#endif
}

/// Directory used for a self test snapshot when --out is not supplied.
std::string temporary_directory() {
  for (const char* name : {"TEMP", "TMP", "TMPDIR"}) {
    const char* value = std::getenv(name);
    if (value != nullptr && value[0] != '\0') {
      return std::string(value);
    }
  }
  return std::string(".");
}

std::string join_path(const std::string& directory, const std::string& leaf) {
  if (directory.empty()) {
    return leaf;
  }
  const char last = directory.back();
  if (last == '/' || last == '\\') {
    return directory + leaf;
  }
#ifdef _WIN32
  return directory + "\\" + leaf;
#else
  return directory + "/" + leaf;
#endif
}

bool parse_digest_hex(std::string_view text, trxreg::Digest& out) {
  const trxreg::Result<trxreg::Digest> parsed = trxreg::Digest::from_hex(text);
  if (!parsed.ok()) {
    return false;
  }
  out = parsed.value();
  return true;
}

// ---------------------------------------------------------------------------
// Canonical request documents
// ---------------------------------------------------------------------------

Value provenance_document(EvidenceKind kind, const std::string& origin, const std::string& method) {
  return Value::object({
      {"capture_ref", Value::text("")},
      {"content_digest", Value::text(trxreg::Digest::zero().to_hex())},
      {"kind", Value::integer(static_cast<std::int64_t>(kind))},
      {"method", Value::text(method)},
      {"origin", Value::text(origin)},
  });
}

Value authority_document(const trxreg::AuthorityToken& authority) {
  return Value::object({{"epoch", Value::integer(static_cast<std::int64_t>(authority.epoch.value()))},
                        {"source", Value::integer(static_cast<std::int64_t>(authority.source.value()))}});
}

Value module_handle_document(const trxreg::ModuleHandle& handle) {
  return Value::object({
      {"generation", Value::integer(static_cast<std::int64_t>(handle.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(handle.incarnation.value()))},
      {"key", Value::text(handle.key.str())},
      {"uid", Value::integer(static_cast<std::int64_t>(handle.uid.value()))},
  });
}

Value module_reference_document(const trxreg::ModuleHandle& handle) {
  return Value::object({
      {"generation", Value::integer(static_cast<std::int64_t>(handle.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(handle.incarnation.value()))},
      {"uid", Value::integer(static_cast<std::int64_t>(handle.uid.value()))},
  });
}

/// Decode the module handle a `module.register` response carries.
bool read_module_handle_document(const Value& document, trxreg::ModuleHandle& out) {
  const Value* uid = document.find("uid");
  const Value* incarnation = document.find("incarnation");
  const Value* generation = document.find("generation");
  const Value* key = document.find("key");
  if (uid == nullptr || incarnation == nullptr || generation == nullptr || key == nullptr) {
    return false;
  }
  if (!uid->is_integer() || !incarnation->is_integer() || !generation->is_integer() || !key->is_text()) {
    return false;
  }
  if (uid->as_integer() <= 0 || incarnation->as_integer() <= 0) {
    return false;
  }
  const trxreg::Result<trxreg::ModuleKey> parsed = trxreg::ModuleKey::parse(key->as_text(), "module key");
  if (!parsed.ok()) {
    return false;
  }
  out.uid = trxreg::ModuleUid{static_cast<std::uint64_t>(uid->as_integer())};
  out.incarnation = trxreg::IncarnationId{static_cast<std::uint32_t>(incarnation->as_integer())};
  out.generation = trxreg::Generation{static_cast<std::uint64_t>(generation->as_integer())};
  out.key = parsed.value();
  return true;
}

bool parse_enum_value(CapabilityKey key, std::string_view text, std::int64_t& out, std::string& error) {
  switch (key) {
    case CapabilityKey::ModuleFamily: {
      trxreg::ModuleFamily value{};
      if (trxreg::module_family_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::MediaClass: {
      trxreg::MediaClass value{};
      if (trxreg::media_class_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::ConnectorClass: {
      trxreg::ConnectorClass value{};
      if (trxreg::connector_class_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::ReachClass: {
      trxreg::ReachClass value{};
      if (trxreg::reach_class_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::PowerClass: {
      trxreg::PowerClass value{};
      if (trxreg::power_class_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::WavelengthGrid: {
      trxreg::WavelengthGrid value{};
      if (trxreg::wavelength_grid_from_string(text, value)) {
        out = static_cast<std::int64_t>(value);
        return true;
      }
      break;
    }
    case CapabilityKey::SpeedClasses:
    case CapabilityKey::Encodings:
    case CapabilityKey::FecModes: {
      // The set-valued keys share one enumerator vocabulary per key.
      if (key == CapabilityKey::SpeedClasses) {
        trxreg::SpeedClass value{};
        if (trxreg::speed_class_from_string(text, value)) {
          out = static_cast<std::int64_t>(value);
          return true;
        }
      } else if (key == CapabilityKey::Encodings) {
        trxreg::EncodingClass value{};
        if (trxreg::encoding_class_from_string(text, value)) {
          out = static_cast<std::int64_t>(value);
          return true;
        }
      } else {
        trxreg::FecClass value{};
        if (trxreg::fec_class_from_string(text, value)) {
          out = static_cast<std::int64_t>(value);
          return true;
        }
      }
      break;
    }
    default:
      error = "capability key " + std::string(trxreg::to_string(key)) + " does not take enumerated names";
      return false;
  }
  error = "unknown " + std::string(trxreg::to_string(key)) + " enumerator '" + std::string(text) + "'";
  return false;
}

bool parse_enum_set_value(CapabilityKey key, std::string_view text, std::vector<std::int64_t>& out,
                          std::string& error) {
  out.clear();
  for (const std::string_view part : split_commas(text)) {
    if (part.empty()) {
      error = "empty enumerator in '" + std::string(text) + "'";
      return false;
    }
    std::int64_t value = 0;
    if (!parse_enum_value(key, part, value, error)) {
      return false;
    }
    out.push_back(value);
  }
  if (out.empty()) {
    error = "--value needs at least one enumerator";
    return false;
  }
  return true;
}

/// Build the canonical capability value a key accepts from its text form. The
/// shape follows CapabilityValue::kind(): an enumeration is carried as an enum
/// value, exactly as CapabilityValue::of() produces it.
bool capability_value_document(CapabilityKey key, std::string_view text, Value& out, std::string& error) {
  const std::string key_name(trxreg::to_string(key));
  switch (trxreg::capability_value_kind(key)) {
    case CapabilityValueKind::Boolean: {
      if (text == "true") {
        out = Value::object({{"b", Value::boolean(true)}, {"k", Value::text("boolean")}});
        return true;
      }
      if (text == "false") {
        out = Value::object({{"b", Value::boolean(false)}, {"k", Value::text("boolean")}});
        return true;
      }
      error = "capability " + key_name + " takes true or false";
      return false;
    }
    case CapabilityValueKind::Count: {
      std::int64_t value = 0;
      if (!parse_signed(text, value) || value < 0) {
        error = "capability " + key_name + " takes a non-negative integer";
        return false;
      }
      out = Value::object({{"i", Value::integer(value)}, {"k", Value::text("count")}});
      return true;
    }
    case CapabilityValueKind::Real: {
      double value = 0.0;
      if (!parse_double(text, value)) {
        error = "capability " + key_name + " takes a real number";
        return false;
      }
      out = Value::object({{"k", Value::text("real")}, {"r", Value::real(value)}});
      return true;
    }
    case CapabilityValueKind::Text: {
      out = Value::object({{"k", Value::text("text")}, {"t", Value::text(std::string(text))}});
      return true;
    }
    case CapabilityValueKind::Enum: {
      std::int64_t value = 0;
      if (!parse_enum_value(key, text, value, error)) {
        return false;
      }
      out = Value::object({{"i", Value::integer(value)}, {"k", Value::text("enum")}});
      return true;
    }
    case CapabilityValueKind::EnumSet: {
      std::vector<std::int64_t> values;
      if (!parse_enum_set_value(key, text, values, error)) {
        return false;
      }
      Value::Array entries;
      entries.reserve(values.size());
      for (const std::int64_t value : values) {
        entries.push_back(Value::integer(value));
      }
      out = Value::object({{"k", Value::text("enum_set")}, {"s", Value::array(std::move(entries))}});
      return true;
    }
    case CapabilityValueKind::TextSet: {
      Value::Array entries;
      for (const std::string_view part : split_commas(text)) {
        entries.push_back(Value::text(std::string(part)));
      }
      out = Value::object({{"k", Value::text("text_set")}, {"s", Value::array(std::move(entries))}});
      return true;
    }
    case CapabilityValueKind::Spectrum:
      error = "capability " + key_name + " carries a spectrum and cannot be given on the command line";
      return false;
    case CapabilityValueKind::None:
      break;
  }
  error = "capability key " + key_name + " is not modelled by this runtime";
  return false;
}

/// Parse one `subject:key:op:operand` compatibility requirement.
bool requirement_document(std::string_view spec, Value& out, std::string& error) {
  const std::size_t first = spec.find(':');
  const std::size_t second = first == std::string_view::npos ? std::string_view::npos : spec.find(':', first + 1);
  const std::size_t third = second == std::string_view::npos ? std::string_view::npos : spec.find(':', second + 1);
  if (third == std::string_view::npos) {
    error = "requirement '" + std::string(spec) + "' must read subject:key:op:operand";
    return false;
  }
  const std::string_view subject_text = spec.substr(0, first);
  const std::string_view key_text = spec.substr(first + 1, second - first - 1);
  const std::string_view op_text = spec.substr(second + 1, third - second - 1);
  const std::string_view operand_text = spec.substr(third + 1);

  RequirementSubject subject{};
  if (!trxreg::requirement_subject_from_string(subject_text, subject)) {
    error = "requirement subject '" + std::string(subject_text) + "' must be module or port";
    return false;
  }
  CapabilityKey key = CapabilityKey::Unknown;
  if (!trxreg::capability_key_from_string(key_text, key) ||
      trxreg::capability_value_kind(key) == CapabilityValueKind::None) {
    error = "requirement key '" + std::string(key_text) + "' is not a modelled capability";
    return false;
  }
  RequirementOp op = RequirementOp::Unknown;
  if (!trxreg::requirement_op_from_string(op_text, op) || op == RequirementOp::Unknown) {
    error = "requirement operator '" + std::string(op_text) + "' is not modelled";
    return false;
  }

  const bool set_operator = op == RequirementOp::In || op == RequirementOp::NotIn ||
                            op == RequirementOp::SupersetOf || op == RequirementOp::SubsetOf ||
                            op == RequirementOp::Overlaps || op == RequirementOp::DisjointFrom;
  Value operand;
  if (set_operator && trxreg::capability_value_kind(key) == CapabilityValueKind::Enum) {
    // A single-valued key may satisfy a set operator through a one-element set.
    std::vector<std::int64_t> values;
    if (!parse_enum_set_value(key, operand_text, values, error)) {
      return false;
    }
    Value::Array entries;
    for (const std::int64_t value : values) {
      entries.push_back(Value::integer(value));
    }
    operand = Value::object({{"k", Value::text("enum_set")}, {"s", Value::array(std::move(entries))}});
  } else if (!capability_value_document(key, operand_text, operand, error)) {
    return false;
  }

  out = Value::object({
      {"key", Value::integer(static_cast<std::int64_t>(key))},
      {"note", Value::text("")},
      {"op", Value::integer(static_cast<std::int64_t>(op))},
      {"operand", std::move(operand)},
      {"subject", Value::integer(static_cast<std::int64_t>(subject))},
      {"subkey", Value::text("")},
  });
  return true;
}

/// Render a stored capability value the way the wire codec does.
Value capability_value_to_value(const trxreg::CapabilityValue& value) {
  switch (value.kind()) {
    case CapabilityValueKind::None:
      return Value::object({{"k", Value::text("none")}});
    case CapabilityValueKind::Boolean: {
      bool raw = false;
      static_cast<void>(value.as_boolean(raw));
      return Value::object({{"b", Value::boolean(raw)}, {"k", Value::text("boolean")}});
    }
    case CapabilityValueKind::Count: {
      std::int64_t raw = 0;
      static_cast<void>(value.as_count(raw));
      return Value::object({{"i", Value::integer(raw)}, {"k", Value::text("count")}});
    }
    case CapabilityValueKind::Real: {
      double raw = 0.0;
      static_cast<void>(value.as_real(raw));
      return Value::object({{"k", Value::text("real")}, {"r", Value::real(raw)}});
    }
    case CapabilityValueKind::Text: {
      const std::string* raw = value.as_text();
      return Value::object({{"k", Value::text("text")}, {"t", Value::text(raw != nullptr ? *raw : std::string())}});
    }
    case CapabilityValueKind::EnumSet: {
      const trxreg::CapabilityValue::EnumSet* values = value.as_enum_set();
      Value::Array entries;
      if (values != nullptr) {
        for (const std::int64_t entry : *values) {
          entries.push_back(Value::integer(entry));
        }
      }
      return Value::object({{"k", Value::text("enum_set")}, {"s", Value::array(std::move(entries))}});
    }
    case CapabilityValueKind::TextSet: {
      const trxreg::CapabilityValue::TextSet* values = value.as_text_set();
      Value::Array entries;
      if (values != nullptr) {
        for (const std::string& entry : *values) {
          entries.push_back(Value::text(entry));
        }
      }
      return Value::object({{"k", Value::text("text_set")}, {"s", Value::array(std::move(entries))}});
    }
    case CapabilityValueKind::Spectrum: {
      const trxreg::CapabilityValue::Spectrum* values = value.as_spectrum();
      Value::Array entries;
      if (values != nullptr) {
        for (const trxreg::SpectrumDescriptor& descriptor : *values) {
          entries.push_back(Value::object({{"center_nm", Value::real(descriptor.center_nm)},
                                           {"channel", Value::text(descriptor.channel)},
                                           {"frequency_thz", Value::real(descriptor.frequency_thz)},
                                           {"grid", Value::integer(static_cast<std::int64_t>(descriptor.grid))},
                                           {"lane", Value::integer(static_cast<std::int64_t>(descriptor.lane))}}));
        }
      }
      return Value::object({{"k", Value::text("spectrum")}, {"s", Value::array(std::move(entries))}});
    }
  }
  return Value::object({{"k", Value::text("none")}});
}

Value requirement_to_value(const trxreg::Requirement& requirement) {
  return Value::object({
      {"key", Value::integer(static_cast<std::int64_t>(requirement.key))},
      {"note", Value::text(requirement.note)},
      {"op", Value::integer(static_cast<std::int64_t>(requirement.op))},
      {"operand", capability_value_to_value(requirement.operand)},
      {"subject", Value::integer(static_cast<std::int64_t>(requirement.subject))},
      {"subkey", Value::text(requirement.subkey)},
  });
}

Value compat_rule_to_value(const trxreg::CompatRule& rule) {
  Value::Array requirements;
  requirements.reserve(rule.requirements.size());
  for (const trxreg::Requirement& requirement : rule.requirements) {
    requirements.push_back(requirement_to_value(requirement));
  }
  return Value::object({
      {"enabled", Value::boolean(rule.enabled)},
      {"name", Value::text(rule.name)},
      {"priority", Value::integer(static_cast<std::int64_t>(rule.priority))},
      {"provenance", provenance_document(rule.provenance.kind, rule.provenance.origin, rule.provenance.method)},
      {"rationale", Value::text(rule.rationale)},
      {"requirements", Value::array(std::move(requirements))},
      {"verdict", Value::integer(static_cast<std::int64_t>(rule.verdict))},
  });
}

Value compat_rule_record_to_value(const trxreg::CompatRuleRecord& record) {
  return Value::object({
      {"generation", Value::integer(static_cast<std::int64_t>(record.generation.value()))},
      {"id", Value::integer(static_cast<std::int64_t>(record.id.value()))},
      {"live", Value::boolean(record.live)},
      {"rule", compat_rule_to_value(record.rule)},
      {"sequence", Value::integer(static_cast<std::int64_t>(record.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(record.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(record.source_epoch.value()))},
  });
}

Value load_report_document(const trxreg::LoadReport& report, const std::string& path, std::uint64_t bytes) {
  return Value::object({
      {"bytes", Value::integer(static_cast<std::int64_t>(bytes))},
      {"claims", Value::integer(static_cast<std::int64_t>(report.claims))},
      {"content_digest", Value::text(report.content_digest.to_hex())},
      {"declarations", Value::integer(static_cast<std::int64_t>(report.declarations))},
      {"dropped_tail_bytes", Value::integer(static_cast<std::int64_t>(report.dropped_tail_bytes))},
      {"evidence_invalidated_on_load", Value::integer(static_cast<std::int64_t>(report.evidence_invalidated_on_load))},
      {"fenced_incarnations", Value::integer(static_cast<std::int64_t>(report.fenced_incarnations))},
      {"format_version", Value::integer(static_cast<std::int64_t>(report.format_version))},
      {"generation", Value::integer(static_cast<std::int64_t>(report.generation.value()))},
      {"incarnations", Value::integer(static_cast<std::int64_t>(report.incarnations))},
      {"loaded_at_wall_ns", Value::integer(report.loaded_at_wall_ns)},
      {"modules", Value::integer(static_cast<std::int64_t>(report.modules))},
      {"path", Value::text(path)},
      {"ports", Value::integer(static_cast<std::int64_t>(report.ports))},
      {"recovery_note", Value::text(report.recovery_note)},
      {"registry_incarnation", Value::integer(static_cast<std::int64_t>(report.registry_incarnation))},
      {"rules", Value::integer(static_cast<std::int64_t>(report.rules))},
      {"samples", Value::integer(static_cast<std::int64_t>(report.samples))},
      {"sources", Value::integer(static_cast<std::int64_t>(report.sources))},
      {"tail_recovered", Value::boolean(report.tail_recovered)},
      {"thresholds", Value::integer(static_cast<std::int64_t>(report.thresholds))},
  });
}

// ---------------------------------------------------------------------------
// Command line shape
// ---------------------------------------------------------------------------

struct Option {
  std::string name;
  std::string value;
  mutable bool used{false};
};

struct Args {
  std::vector<Option> options;

  const std::string* find(std::string_view name) const {
    for (const Option& option : options) {
      if (option.name == name) {
        option.used = true;
        return &option.value;
      }
    }
    return nullptr;
  }

  bool take(std::string_view name, std::string& out) const {
    const std::string* value = find(name);
    if (value == nullptr) {
      return false;
    }
    out = *value;
    return true;
  }

  std::vector<std::string> all(std::string_view name) const {
    std::vector<std::string> out;
    for (const Option& option : options) {
      if (option.name == name) {
        option.used = true;
        out.push_back(option.value);
      }
    }
    return out;
  }

  bool first_unused(std::string& name) const {
    for (const Option& option : options) {
      if (!option.used) {
        name = option.name;
        return true;
      }
    }
    return false;
  }
};

struct Command {
  std::string name;
  Args args;
};

void print_usage(std::FILE* out) {
  std::fprintf(out,
               "usage: trxreg_cli [--server HOST:PORT] [--snapshot FILE] <subcommand> [options]"
               " [<subcommand> [options]]...\n"
               "  --server HOST:PORT   send every subcommand over the loopback transport\n"
               "  --snapshot FILE      in-process mode: load FILE when it exists; remote mode: use it"
               " to resolve module keys\n"
               "subcommands:\n"
               "  stats | info | save --out FILE | inspect [--snapshot FILE]\n"
               "  source-register --name N [--kind real|synthetic] [--instance ID]\n"
               "  module-register --key K --intent current|new_incarnation [--vendor V] [--part P]"
               " [--serial S] [--revision R] [--firmware F]\n"
               "                  [--origin O] [--method M] [--kind real|synthetic]"
               " [--source-id N --source-epoch N]\n"
               "  identity|capabilities|evidence|health --key K\n"
               "  capability-publish --key K --attr KEY --value V [--subkey S]"
               " (or --port P for a host port)\n"
               "  attach --key K --slot S [--port-index N] | detach --slot S\n"
               "  health-threshold --metric M --max-age-ms N [--degraded-enter X --degraded-exit Y]\n"
               "                   [--critical-enter X --critical-exit Y] [--direction above|below]"
               " [--escalate N] [--recover N] [--tolerance X]\n"
               "  health-ingest --key K --metric M --value X [--lane N]"
               " [--presence present|not_available|read_error|not_supported] [--observed-offset-ms N]\n"
               "  compat-rule --name N --verdict compatible|incompatible|unsupported [--priority N]"
               " [--require SPEC]...\n"
               "  compat-query --port P --key K | compat-rules\n"
               "  transition --key K --state STATE --reason TEXT | reconcile --key K\n"
               "  selftest [--out FILE]\n"
               "  (--key/--uid/--incarnation name a module; SPEC is subject:key:op:operand)\n");
}

int usage_error(const std::string& message) {
  std::fprintf(stderr, "trxreg_cli: %s\n", message.c_str());
  print_usage(stderr);
  return kExitUsage;
}

int operation_error(StatusCode code, const std::string& message) {
  std::fprintf(stderr, "error: %s: %s\n", std::string(trxreg::to_string(code)).c_str(), message.c_str());
  return kExitFailure;
}

void print_document(const Value& document) {
  const std::string json = document.to_json();
  std::printf("%s\n", json.c_str());
  std::fflush(stdout);
}

/// Consume the shared global prefix and split the rest into subcommands.
bool parse_arguments(int argc, char** argv, std::string& server, std::string& snapshot,
                     std::vector<Command>& commands, std::string& error) {
  int index = 1;
  while (index < argc) {
    const std::string_view token(argv[index]);
    if (token == "--server") {
      if (index + 1 >= argc) {
        error = "--server requires HOST:PORT";
        return false;
      }
      server = argv[index + 1];
      index += 2;
      continue;
    }
    if (token == "--snapshot") {
      if (index + 1 >= argc) {
        error = "--snapshot requires a path";
        return false;
      }
      snapshot = argv[index + 1];
      index += 2;
      continue;
    }
    break;
  }
  while (index < argc) {
    const std::string name(argv[index]);
    if (name.rfind("--", 0) == 0) {
      error = "expected a subcommand but found option '" + name + "'";
      return false;
    }
    ++index;
    Command command;
    command.name = name;
    while (index < argc) {
      const std::string_view token(argv[index]);
      if (token.rfind("--", 0) != 0) {
        break;
      }
      if (index + 1 >= argc) {
        error = "option '" + std::string(token) + "' requires a value";
        return false;
      }
      const std::string_view value(argv[index + 1]);
      if (value.rfind("--", 0) == 0) {
        error = "option '" + std::string(token) + "' requires a value";
        return false;
      }
      Option option;
      option.name = std::string(token);
      option.value = std::string(value);
      command.args.options.push_back(std::move(option));
      index += 2;
    }
    commands.push_back(std::move(command));
  }
  if (commands.empty()) {
    error = "no subcommand was given";
    return false;
  }
  return true;
}


// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct Outcome {
  bool ok{false};
  StatusCode code{StatusCode::Internal};
  std::string message;
  Value document;
};

struct Session {
  bool remote{false};
  std::string endpoint{"in-process"};
  std::string snapshot;
  trxreg::ClockPtr clock{trxreg::make_system_clock()};
  std::unique_ptr<trxreg::Registry> registry;
  std::unique_ptr<trxreg::wire::Client> client;
  bool source_ready{false};
  trxreg::SourceHandle source{};
  std::map<std::string, trxreg::ModuleHandle> modules;
  std::unique_ptr<trxreg::Registry> scratch;
  bool scratch_ready{false};
};

Outcome perform(Session& session, std::string_view op, Value parameters) {
  Outcome outcome;
  if (!session.remote) {
    Value request = Value::object({{"id", Value::integer(1)},
                                   {"op", Value::text(std::string(op))},
                                   {"params", std::move(parameters)}});
    const trxreg::wire::RequestOutcome dispatched =
        trxreg::wire::dispatch(*session.registry, request, trxreg::CanonicalLimits::request());
    const Value* failure = dispatched.body.find("error");
    if (dispatched.type == trxreg::wire::MessageType::Failure || failure != nullptr) {
      outcome.message = "the request failed without a classification";
      if (failure != nullptr) {
        const Value* code = failure->find("code");
        const Value* message = failure->find("message");
        if (code != nullptr && code->is_text()) {
          StatusCode parsed = StatusCode::Internal;
          if (trxreg::status_code_from_string(code->as_text(), parsed)) {
            outcome.code = parsed;
          }
        }
        if (message != nullptr && message->is_text()) {
          outcome.message = message->as_text();
        }
      }
      return outcome;
    }
    const Value* result = dispatched.body.find("result");
    if (result == nullptr) {
      outcome.message = "the response carries neither a result nor an error";
      return outcome;
    }
    outcome.ok = true;
    outcome.code = StatusCode::Ok;
    outcome.document = *result;
    return outcome;
  }
  trxreg::Result<Value> result = session.client->call(op, std::move(parameters));
  if (!result.ok()) {
    outcome.code = result.error().code;
    outcome.message = result.error().message;
    return outcome;
  }
  outcome.ok = true;
  outcome.code = StatusCode::Ok;
  outcome.document = result.value();
  return outcome;
}

int report(const Outcome& outcome) { return operation_error(outcome.code, outcome.message); }

/// Register the single source this run speaks as, once.
bool ensure_source(Session& session, trxreg::AuthorityToken& authority, StatusCode& code, std::string& message) {
  if (session.source_ready) {
    authority = session.source.authority();
    return true;
  }
  Value parameters = Value::object({
      {"description", Value::text("Transceiver Registry command line utility")},
      {"instance_id", Value::text("trxreg-cli")},
      {"kind", Value::text("synthetic")},
      {"name", Value::text("trxreg-cli")},
  });
  const Outcome outcome = perform(session, "source.register", std::move(parameters));
  if (!outcome.ok) {
    code = outcome.code;
    message = outcome.message;
    return false;
  }
  const Value* id = outcome.document.find("id");
  const Value* epoch = outcome.document.find("epoch");
  if (id == nullptr || epoch == nullptr || !id->is_integer() || !epoch->is_integer() || id->as_integer() <= 0) {
    code = StatusCode::Internal;
    message = "the source registration response carries no usable handle";
    return false;
  }
  session.source.id = trxreg::SourceId{static_cast<std::uint32_t>(id->as_integer())};
  session.source.epoch = trxreg::SourceEpoch{static_cast<std::uint32_t>(epoch->as_integer())};
  session.source.generation = trxreg::Generation{0};
  session.source_ready = true;
  authority = session.source.authority();
  return true;
}

struct Lookup {
  bool ok{false};
  bool argument_error{false};
  StatusCode code{StatusCode::NotFound};
  std::string message;
  trxreg::ModuleHandle handle{};
};

/// Load the local mirror used to resolve module keys in remote mode.
bool ensure_scratch(Session& session, std::string& message) {
  if (session.scratch_ready) {
    return session.scratch != nullptr;
  }
  session.scratch_ready = true;
  if (session.snapshot.empty() || !file_exists(session.snapshot)) {
    return false;
  }
  session.scratch = std::make_unique<trxreg::Registry>(trxreg::RegistryConfig{}, session.clock);
  const trxreg::Result<trxreg::LoadReport> report_value = session.scratch->load(session.snapshot);
  if (!report_value.ok()) {
    session.scratch.reset();
    message = "cannot resolve keys from '" + session.snapshot + "': " +
              std::string(trxreg::to_string(report_value.error().code)) + ": " + report_value.error().message;
    return false;
  }
  return true;
}

/// Resolve a module key to the handle the wire vocabulary needs.
Lookup resolve_module(Session& session, Args& args, const std::string& key) {
  Lookup lookup;
  if (key.empty()) {
    lookup.argument_error = true;
    lookup.message = "--key requires a module key";
    return lookup;
  }
  const auto cached = session.modules.find(key);
  if (cached != session.modules.end()) {
    lookup.ok = true;
    lookup.handle = cached->second;
    return lookup;
  }

  std::string value;
  std::uint64_t uid = 0;
  std::uint64_t incarnation = 0;
  const bool has_uid = args.take("--uid", value) && parse_unsigned(value, uid);
  const bool has_incarnation = args.take("--incarnation", value) && parse_unsigned(value, incarnation);
  if (has_uid || has_incarnation || args.find("--uid") != nullptr || args.find("--incarnation") != nullptr) {
    if (!has_uid || !has_incarnation || uid == 0 || incarnation == 0 || incarnation > 0xFFFFFFFFull) {
      lookup.argument_error = true;
      lookup.message = "--uid and --incarnation must be given together and be non-zero";
      return lookup;
    }
    const trxreg::Result<trxreg::ModuleKey> parsed = trxreg::ModuleKey::parse(key, "module key");
    if (!parsed.ok()) {
      lookup.argument_error = true;
      lookup.message = "invalid module key: " + parsed.error().message;
      return lookup;
    }
    lookup.ok = true;
    lookup.handle.uid = trxreg::ModuleUid{uid};
    lookup.handle.incarnation = trxreg::IncarnationId{static_cast<std::uint32_t>(incarnation)};
    lookup.handle.key = parsed.value();
    return lookup;
  }

  if (!session.remote) {
    const trxreg::Result<trxreg::IdentityView> view = session.registry->identity_by_key(key);
    if (!view.ok()) {
      lookup.code = view.error().code;
      lookup.message = view.error().message;
      return lookup;
    }
    lookup.ok = true;
    lookup.handle.uid = view.value().uid;
    lookup.handle.incarnation = view.value().incarnation;
    lookup.handle.generation = view.value().generation;
    lookup.handle.key = view.value().key;
    return lookup;
  }

  // Remote mode: a locally visible snapshot resolves the key without touching
  // the server, otherwise the registration path is the only key to handle map
  // the loopback vocabulary exposes.
  std::string scratch_message;
  if (ensure_scratch(session, scratch_message) && session.scratch != nullptr) {
    const trxreg::Result<trxreg::IdentityView> view = session.scratch->identity_by_key(key);
    if (view.ok()) {
      lookup.ok = true;
      lookup.handle.uid = view.value().uid;
      lookup.handle.incarnation = view.value().incarnation;
      lookup.handle.generation = view.value().generation;
      lookup.handle.key = view.value().key;
      return lookup;
    }
  }
  trxreg::AuthorityToken authority;
  StatusCode code = StatusCode::Internal;
  std::string message;
  if (!ensure_source(session, authority, code, message)) {
    lookup.code = code;
    lookup.message = message;
    return lookup;
  }
  const trxreg::Result<trxreg::ModuleKey> parsed = trxreg::ModuleKey::parse(key, "module key");
  if (!parsed.ok()) {
    lookup.argument_error = true;
    lookup.message = "invalid module key: " + parsed.error().message;
    return lookup;
  }
  Value parameters = Value::object({
      {"authority", authority_document(authority)},
      {"expected_generation", Value::integer(0)},
      {"identity", Value::array({})},
      {"intent", Value::text("current")},
      {"key", Value::text(key)},
      {"policy", Value::text("auto_retry")},
      {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "key-resolution")},
  });
  const Outcome outcome = perform(session, "module.register", std::move(parameters));
  if (!outcome.ok) {
    lookup.code = outcome.code;
    lookup.message = outcome.message;
    return lookup;
  }
  trxreg::ModuleHandle handle;
  if (!read_module_handle_document(outcome.document, handle)) {
    lookup.code = StatusCode::Internal;
    lookup.message = "the module registration response carries no usable handle";
    return lookup;
  }
  std::fprintf(stderr, "note: module key '%s' was resolved through module.register (intent=current)\n", key.c_str());
  session.modules[key] = handle;
  lookup.ok = true;
  lookup.handle = handle;
  return lookup;
}

/// Compatibility outcomes and knowledge closure have no canonical taxonomy
/// rendering, so the CLI names them the way the library documents them.
std::string_view compat_outcome_text(std::int64_t raw) {
  switch (raw) {
    case 1:
      return "compatible";
    case 2:
      return "incompatible";
    case 3:
      return "unsupported";
    default:
      return "unknown";
  }
}

std::string_view knowledge_closure_text(std::int64_t raw) {
  switch (raw) {
    case 1:
      return "partial";
    case 2:
      return "closed";
    default:
      return "open";
  }
}

std::int64_t integer_field(const Value& document, std::string_view key, std::int64_t fallback) {
  const Value* field = document.find(key);
  if (field != nullptr && field->is_integer()) {
    return field->as_integer();
  }
  return fallback;
}

bool parse_evidence_kind(const std::string& text, EvidenceKind& out) {
  if (text == "real") {
    out = EvidenceKind::Real;
    return true;
  }
  if (text == "synthetic") {
    out = EvidenceKind::Synthetic;
    return true;
  }
  return false;
}

/// Registry introspection, persistence, and local inspection.
int run_query_command(Session& session, const std::string& name, Args& args, bool& handled) {
  handled = true;
  if (name == "stats") {
    const Outcome outcome = perform(session, "registry.stats", Value::object({}));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }
  if (name == "info") {
    const Outcome hello = perform(session, "hello", Value::object({}));
    if (!hello.ok) {
      return report(hello);
    }
    const Outcome stats = perform(session, "registry.stats", Value::object({}));
    if (!stats.ok) {
      return report(stats);
    }
    Value document = Value::object({});
    static_cast<void>(document.set("mode", Value::text(session.remote ? "remote" : "in-process")));
    static_cast<void>(document.set("endpoint", Value::text(session.endpoint)));
    static_cast<void>(document.set("version", Value::text(std::string(trxreg::version_string()))));
    static_cast<void>(document.set("snapshot_format_version",
                                   Value::integer(static_cast<std::int64_t>(trxreg::kSnapshotFormatVersion))));
    static_cast<void>(document.set("wire_protocol_version", Value::integer(integer_field(hello.document, "protocol", 0))));
    static_cast<void>(
        document.set("registry_incarnation", Value::integer(integer_field(hello.document, "registry_incarnation", 0))));
    for (const char* field : {"attachments", "claims", "declarations", "generation", "live_attachments", "modules",
                              "mutations", "ports", "queries", "refusals", "rules", "samples", "sources",
                              "thresholds", "state_digest"}) {
      const Value* value = stats.document.find(field);
      if (value != nullptr) {
        static_cast<void>(document.set(field, *value));
      }
    }
    print_document(document);
    return kExitOk;
  }
  if (name == "save") {
    std::string path;
    if (!args.take("--out", path) || path.empty()) {
      return usage_error("save requires --out FILE");
    }
    const Outcome outcome =
        perform(session, "registry.save", Value::object({{"path", Value::text(path)}}));
    if (!outcome.ok) {
      return report(outcome);
    }
    Value document = outcome.document;
    static_cast<void>(document.set("bytes", Value::integer(static_cast<std::int64_t>(file_size(path)))));
    static_cast<void>(document.set("path", Value::text(path)));
    print_document(document);
    return kExitOk;
  }
  if (name == "inspect") {
    std::string path;
    if (!args.take("--snapshot", path)) {
      path = session.snapshot;
    }
    if (path.empty()) {
      return usage_error("inspect requires --snapshot FILE");
    }
    const trxreg::Result<trxreg::LoadReport> inspected =
        trxreg::inspect_snapshot(path, trxreg::LoadOptions{});
    if (!inspected.ok()) {
      return operation_error(inspected.error().code, inspected.error().message);
    }
    print_document(load_report_document(inspected.value(), path, file_size(path)));
    return kExitOk;
  }
  if (name == "compat-rules") {
    trxreg::Registry* source = nullptr;
    if (!session.remote) {
      source = session.registry.get();
    } else {
      std::string message;
      if (ensure_scratch(session, message) && session.scratch != nullptr) {
        source = session.scratch.get();
      } else {
        return operation_error(StatusCode::Unsupported,
                               "the loopback vocabulary has no operation that lists compatibility rules; "
                               "run compat-rules in-process or pass --snapshot FILE");
      }
    }
    const std::vector<trxreg::CompatRuleRecord> rules = source->rules();
    Value::Array entries;
    entries.reserve(rules.size());
    for (const trxreg::CompatRuleRecord& rule : rules) {
      entries.push_back(compat_rule_record_to_value(rule));
    }
    print_document(Value::object({{"count", Value::integer(static_cast<std::int64_t>(entries.size()))},
                                  {"rules", Value::array(std::move(entries))}}));
    return kExitOk;
  }
  handled = false;
  return kExitOk;
}

/// Source and module registration.
int run_registration_command(Session& session, const std::string& name, Args& args, bool& handled) {
  handled = true;
  if (name == "source-register") {
    std::string source_name;
    if (!args.take("--name", source_name) || source_name.empty()) {
      return usage_error("source-register requires --name N");
    }
    std::string kind_text = "synthetic";
    static_cast<void>(args.take("--kind", kind_text));
    EvidenceKind kind = EvidenceKind::Synthetic;
    if (!parse_evidence_kind(kind_text, kind)) {
      return usage_error("--kind must be real or synthetic");
    }
    std::string instance;
    static_cast<void>(args.take("--instance", instance));
    Value parameters = Value::object({
        {"description", Value::text("registered by trxreg_cli")},
        {"instance_id", Value::text(instance)},
        {"kind", Value::text(kind_text)},
        {"name", Value::text(source_name)},
    });
    const Outcome outcome = perform(session, "source.register", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }
  if (name == "module-register") {
    std::string key;
    if (!args.take("--key", key) || key.empty()) {
      return usage_error("module-register requires --key K");
    }
    const trxreg::Result<trxreg::ModuleKey> parsed_key = trxreg::ModuleKey::parse(key, "module key");
    if (!parsed_key.ok()) {
      return usage_error("invalid module key: " + parsed_key.error().message);
    }
    std::string intent_text = "current";
    static_cast<void>(args.take("--intent", intent_text));
    trxreg::RegisterIntent intent = trxreg::RegisterIntent::EnsureCurrent;
    if (!trxreg::register_intent_from_string(intent_text, intent)) {
      return usage_error("--intent must be current or new_incarnation");
    }
    std::string kind_text = "synthetic";
    static_cast<void>(args.take("--kind", kind_text));
    EvidenceKind kind = EvidenceKind::Synthetic;
    if (!parse_evidence_kind(kind_text, kind)) {
      return usage_error("--kind must be real or synthetic");
    }
    std::string origin = "trxreg-cli";
    std::string method = "declared";
    static_cast<void>(args.take("--origin", origin));
    static_cast<void>(args.take("--method", method));

    Value::Array identity;
    const std::pair<const char*, trxreg::IdentityField> fields[] = {
        {"--vendor", trxreg::IdentityField::Vendor},
        {"--part", trxreg::IdentityField::PartNumber},
        {"--serial", trxreg::IdentityField::SerialNumber},
        {"--revision", trxreg::IdentityField::Revision},
        {"--firmware", trxreg::IdentityField::FirmwareVersion},
    };
    for (const auto& entry : fields) {
      std::string text;
      if (!args.take(entry.first, text)) {
        continue;
      }
      identity.push_back(Value::object({{"field", Value::integer(static_cast<std::int64_t>(entry.second))},
                                        {"subkey", Value::text("")},
                                        {"value", Value::text(text)}}));
    }

    trxreg::AuthorityToken authority;
    std::string source_id_text;
    std::string source_epoch_text;
    const bool has_source_id = args.take("--source-id", source_id_text);
    const bool has_source_epoch = args.take("--source-epoch", source_epoch_text);
    if (has_source_id || has_source_epoch) {
      std::uint32_t source_id = 0;
      std::uint32_t source_epoch = 0;
      if (!has_source_id || !has_source_epoch || !parse_u32(source_id_text, source_id) ||
          !parse_u32(source_epoch_text, source_epoch) || source_id == 0 || source_epoch == 0) {
        return usage_error("--source-id and --source-epoch must be given together and be non-zero");
      }
      authority.source = trxreg::SourceId{source_id};
      authority.epoch = trxreg::SourceEpoch{source_epoch};
    } else {
      StatusCode code = StatusCode::Internal;
      std::string message;
      if (!ensure_source(session, authority, code, message)) {
        return operation_error(code, message);
      }
    }

    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"expected_generation", Value::integer(0)},
        {"identity", Value::array(std::move(identity))},
        {"intent", Value::text(intent_text)},
        {"key", Value::text(key)},
        {"policy", Value::text("auto_retry")},
        {"provenance", provenance_document(kind, origin, method)},
    });
    const Outcome outcome = perform(session, "module.register", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    trxreg::ModuleHandle handle;
    if (read_module_handle_document(outcome.document, handle)) {
      session.modules[key] = handle;
    }
    print_document(outcome.document);
    return kExitOk;
  }
  handled = false;
  return kExitOk;
}

/// Commands addressed by a module key.
int run_module_command(Session& session, const std::string& name, Args& args, bool& handled) {
  handled = true;
  const bool is_read = name == "identity" || name == "capabilities" || name == "evidence" || name == "health";
  const bool is_publish = name == "capability-publish";
  const bool is_attachment = name == "attach" || name == "detach";
  const bool is_health = name == "health-ingest";
  const bool is_lifecycle = name == "transition" || name == "reconcile";
  const bool is_compat = name == "compat-query";
  if (!is_read && !is_publish && !is_attachment && !is_health && !is_lifecycle && !is_compat) {
    handled = false;
    return kExitOk;
  }

  if (name == "detach") {
    std::string slot;
    if (!args.take("--slot", slot) || slot.empty()) {
      return usage_error("detach requires --slot S");
    }
    trxreg::AuthorityToken authority;
    StatusCode code = StatusCode::Internal;
    std::string message;
    if (!ensure_source(session, authority, code, message)) {
      return operation_error(code, message);
    }
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"policy", Value::text("auto_retry")},
        {"slot", Value::text(slot)},
    });
    const Outcome outcome = perform(session, "attachment.detach", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  if (is_publish && args.find("--port") != nullptr) {
    // A port subject carries no module handle; the same value syntax applies.
    std::string port;
    static_cast<void>(args.take("--port", port));
    std::string attribute;
    std::string text;
    if (port.empty()) {
      return usage_error("capability-publish --port needs a port key");
    }
    if (!args.take("--attr", attribute) || attribute.empty()) {
      return usage_error("capability-publish requires --attr KEY");
    }
    if (!args.take("--value", text)) {
      return usage_error("capability-publish requires --value V");
    }
    CapabilityKey capability = CapabilityKey::Unknown;
    if (!trxreg::capability_key_from_string(attribute, capability)) {
      return usage_error("unknown capability key '" + attribute + "'");
    }
    std::string subkey;
    static_cast<void>(args.take("--subkey", subkey));
    Value value;
    std::string message;
    if (!capability_value_document(capability, text, value, message)) {
      return usage_error(message);
    }
    trxreg::AuthorityToken authority;
    StatusCode code = StatusCode::Internal;
    if (!ensure_source(session, authority, code, message)) {
      return operation_error(code, message);
    }
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"key", Value::text(attribute)},
        {"policy", Value::text("auto_retry")},
        {"port", Value::text(port)},
        {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "declared")},
        {"subkey", Value::text(subkey)},
        {"value", std::move(value)},
    });
    const Outcome outcome = perform(session, "port.capability.publish", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  std::string key;
  if (!args.take("--key", key)) {
    return usage_error(name + " requires --key K");
  }
  const Lookup lookup = resolve_module(session, args, key);
  if (!lookup.ok) {
    return lookup.argument_error ? usage_error(lookup.message) : operation_error(lookup.code, lookup.message);
  }

  if (is_read) {
    const char* op = "module.identity";
    if (name == "capabilities") {
      op = "module.capabilities";
    } else if (name == "evidence") {
      op = "evidence.summary";
    } else if (name == "health") {
      op = "health.report";
    }
    const Outcome outcome = perform(session, op, module_reference_document(lookup.handle));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  trxreg::AuthorityToken authority;
  StatusCode code = StatusCode::Internal;
  std::string message;
  if (!ensure_source(session, authority, code, message)) {
    return operation_error(code, message);
  }

  if (is_publish) {
    std::string attribute;
    std::string text;
    if (!args.take("--attr", attribute) || attribute.empty()) {
      return usage_error("capability-publish requires --attr KEY");
    }
    if (!args.take("--value", text)) {
      return usage_error("capability-publish requires --value V");
    }
    CapabilityKey capability = CapabilityKey::Unknown;
    if (!trxreg::capability_key_from_string(attribute, capability)) {
      return usage_error("unknown capability key '" + attribute + "'");
    }
    std::string subkey;
    static_cast<void>(args.take("--subkey", subkey));
    Value value;
    if (!capability_value_document(capability, text, value, message)) {
      return usage_error(message);
    }
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"key", Value::text(attribute)},
        {"module", module_handle_document(lookup.handle)},
        {"policy", Value::text("auto_retry")},
        {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "declared")},
        {"subkey", Value::text(subkey)},
        {"value", std::move(value)},
    });
    const Outcome outcome = perform(session, "capability.publish", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  if (name == "attach") {
    std::string slot;
    if (!args.take("--slot", slot) || slot.empty()) {
      return usage_error("attach requires --slot S");
    }
    std::uint32_t port_index = 0;
    std::string port_index_text;
    if (args.take("--port-index", port_index_text) && !parse_u32(port_index_text, port_index)) {
      return usage_error("--port-index must be a non-negative integer");
    }
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"module", module_handle_document(lookup.handle)},
        {"policy", Value::text("auto_retry")},
        {"port_index", Value::integer(static_cast<std::int64_t>(port_index))},
        {"slot", Value::text(slot)},
    });
    const Outcome outcome = perform(session, "attachment.attach", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  if (name == "compat-query") {
    std::string port;
    if (!args.take("--port", port) || port.empty()) {
      return usage_error("compat-query requires --port P");
    }
    Value parameters = Value::object({
        {"explain", Value::boolean(true)},
        {"expected_generation", Value::integer(0)},
        {"incarnation", Value::integer(static_cast<std::int64_t>(lookup.handle.incarnation.value()))},
        {"port", Value::text(port)},
        {"require_latest_generation", Value::boolean(false)},
        {"uid", Value::integer(static_cast<std::int64_t>(lookup.handle.uid.value()))},
    });
    const Outcome outcome = perform(session, "compat.query", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  if (is_lifecycle) {
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"module", module_handle_document(lookup.handle)},
        {"policy", Value::text("auto_retry")},
    });
    if (name == "transition") {
      std::string state;
      std::string reason;
      if (!args.take("--state", state) || state.empty()) {
        return usage_error("transition requires --state STATE");
      }
      if (!args.take("--reason", reason)) {
        return usage_error("transition requires --reason TEXT");
      }
      trxreg::LifecycleState parsed = trxreg::LifecycleState::Registered;
      if (!trxreg::lifecycle_state_from_string(state, parsed)) {
        return usage_error("unknown lifecycle state '" + state + "'");
      }
      static_cast<void>(parameters.set("reason", Value::text(reason)));
      static_cast<void>(parameters.set("state", Value::text(state)));
    }
    const Outcome outcome =
        perform(session, name == "transition" ? "lifecycle.transition" : "lifecycle.reconcile", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  if (is_health) {
    std::string metric_text;
    std::string value_text;
    if (!args.take("--metric", metric_text) || metric_text.empty()) {
      return usage_error("health-ingest requires --metric M");
    }
    if (!args.take("--value", value_text)) {
      return usage_error("health-ingest requires --value X");
    }
    trxreg::HealthMetric metric = trxreg::HealthMetric::Unknown;
    if (!trxreg::health_metric_from_string(metric_text, metric) || metric == trxreg::HealthMetric::Unknown ||
        metric == trxreg::HealthMetric::Unsupported) {
      return usage_error("unknown health metric '" + metric_text + "'");
    }
    double measured = 0.0;
    if (!parse_double(value_text, measured)) {
      return usage_error("--value must be a real number");
    }
    std::uint16_t lane = trxreg::kModuleLane;
    std::string lane_text;
    if (args.take("--lane", lane_text) && !parse_u16(lane_text, lane)) {
      return usage_error("--lane must be an integer in [0, 65535]");
    }
    std::string presence_text = "present";
    static_cast<void>(args.take("--presence", presence_text));
    trxreg::SamplePresence presence = trxreg::SamplePresence::Present;
    if (!trxreg::sample_presence_from_string(presence_text, presence)) {
      return usage_error("--presence must be present, not_available, read_error, or not_supported");
    }
    std::int64_t offset_ms = 0;
    std::string offset_text;
    if (args.take("--observed-offset-ms", offset_text) && !parse_signed(offset_text, offset_ms)) {
      return usage_error("--observed-offset-ms must be an integer number of milliseconds");
    }
    const trxreg::WallNs observed = session.clock->wall_now_ns() + offset_ms * 1000000;
    Value sample = Value::object({
        {"clock_domain", Value::integer(0)},
        {"lane", Value::integer(static_cast<std::int64_t>(lane))},
        {"metric", Value::integer(static_cast<std::int64_t>(metric))},
        {"observed_at_monotonic_ns", Value::integer(0)},
        {"observed_at_wall_ns", Value::integer(observed)},
        {"presence", Value::integer(static_cast<std::int64_t>(presence))},
        {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "sampled")},
        {"value", Value::real(measured)},
    });
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"module", module_handle_document(lookup.handle)},
        {"policy", Value::text("auto_retry")},
        {"sample", std::move(sample)},
    });
    const Outcome outcome = perform(session, "health.ingest", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  handled = false;
  return kExitOk;
}

/// Health policy and compatibility rule publication.
int run_policy_command(Session& session, const std::string& name, Args& args, bool& handled) {
  handled = true;
  if (name != "health-threshold" && name != "compat-rule") {
    handled = false;
    return kExitOk;
  }
  trxreg::AuthorityToken authority;
  StatusCode code = StatusCode::Internal;
  std::string message;
  if (!ensure_source(session, authority, code, message)) {
    return operation_error(code, message);
  }

  if (name == "health-threshold") {
    std::string metric_text;
    std::string max_age_text;
    if (!args.take("--metric", metric_text) || metric_text.empty()) {
      return usage_error("health-threshold requires --metric M");
    }
    if (!args.take("--max-age-ms", max_age_text)) {
      return usage_error("health-threshold requires --max-age-ms N");
    }
    trxreg::HealthMetric metric = trxreg::HealthMetric::Unknown;
    if (!trxreg::health_metric_from_string(metric_text, metric) || metric == trxreg::HealthMetric::Unknown ||
        metric == trxreg::HealthMetric::Unsupported) {
      return usage_error("unknown health metric '" + metric_text + "'");
    }
    std::int64_t max_age_ms = 0;
    if (!parse_signed(max_age_text, max_age_ms) || max_age_ms <= 0) {
      return usage_error("--max-age-ms must be a positive integer");
    }
    std::string direction_text = "above";
    static_cast<void>(args.take("--direction", direction_text));
    trxreg::ThresholdDirection direction = trxreg::ThresholdDirection::Above;
    if (direction_text == "above") {
      direction = trxreg::ThresholdDirection::Above;
    } else if (direction_text == "below") {
      direction = trxreg::ThresholdDirection::Below;
    } else {
      return usage_error("--direction must be above or below");
    }
    std::string text;
    bool has_degraded = false;
    double degraded_enter = 0.0;
    double degraded_exit = 0.0;
    const bool degraded_enter_given = args.take("--degraded-enter", text);
    if (degraded_enter_given && !parse_double(text, degraded_enter)) {
      return usage_error("--degraded-enter must be a real number");
    }
    const bool degraded_exit_given = args.take("--degraded-exit", text);
    if (degraded_exit_given && !parse_double(text, degraded_exit)) {
      return usage_error("--degraded-exit must be a real number");
    }
    if (degraded_enter_given || degraded_exit_given) {
      if (!degraded_enter_given || !degraded_exit_given) {
        return usage_error("--degraded-enter and --degraded-exit must be given together");
      }
      has_degraded = true;
    }
    bool has_critical = false;
    double critical_enter = 0.0;
    double critical_exit = 0.0;
    const bool critical_enter_given = args.take("--critical-enter", text);
    if (critical_enter_given && !parse_double(text, critical_enter)) {
      return usage_error("--critical-enter must be a real number");
    }
    const bool critical_exit_given = args.take("--critical-exit", text);
    if (critical_exit_given && !parse_double(text, critical_exit)) {
      return usage_error("--critical-exit must be a real number");
    }
    if (critical_enter_given || critical_exit_given) {
      if (!critical_enter_given || !critical_exit_given) {
        return usage_error("--critical-enter and --critical-exit must be given together");
      }
      has_critical = true;
    }
    if (!has_degraded && !has_critical) {
      return usage_error("health-threshold needs at least one band (--degraded-* or --critical-*)");
    }
    std::uint32_t escalate = 1;
    std::uint32_t recover = 1;
    if (args.take("--escalate", text) && (!parse_u32(text, escalate) || escalate == 0)) {
      return usage_error("--escalate must be a positive integer");
    }
    if (args.take("--recover", text) && (!parse_u32(text, recover) || recover == 0)) {
      return usage_error("--recover must be a positive integer");
    }
    double tolerance = 0.0;
    if (args.take("--tolerance", text) && !parse_double(text, tolerance)) {
      return usage_error("--tolerance must be a real number");
    }
    Value threshold = Value::object({
        {"critical_enter", Value::real(critical_enter)},
        {"critical_exit", Value::real(critical_exit)},
        {"degraded_enter", Value::real(degraded_enter)},
        {"degraded_exit", Value::real(degraded_exit)},
        {"direction", Value::integer(static_cast<std::int64_t>(direction))},
        {"disagreement_tolerance", Value::real(tolerance)},
        {"escalate_after", Value::integer(static_cast<std::int64_t>(escalate))},
        {"generation", Value::integer(0)},
        {"has_critical", Value::boolean(has_critical)},
        {"has_degraded", Value::boolean(has_degraded)},
        {"lane", Value::integer(static_cast<std::int64_t>(trxreg::kModuleLane))},
        {"live", Value::boolean(true)},
        {"max_age_ns", Value::integer(max_age_ms * 1000000)},
        {"metric", Value::integer(static_cast<std::int64_t>(metric))},
        {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "declared")},
        {"recover_after", Value::integer(static_cast<std::int64_t>(recover))},
        {"sequence", Value::integer(0)},
        {"source", Value::integer(0)},
        {"source_epoch", Value::integer(0)},
    });
    Value parameters = Value::object({
        {"authority", authority_document(authority)},
        {"policy", Value::text("auto_retry")},
        {"threshold", std::move(threshold)},
    });
    const Outcome outcome = perform(session, "health.threshold.publish", std::move(parameters));
    if (!outcome.ok) {
      return report(outcome);
    }
    print_document(outcome.document);
    return kExitOk;
  }

  std::string rule_name;
  std::string verdict_text;
  if (!args.take("--name", rule_name) || rule_name.empty()) {
    return usage_error("compat-rule requires --name N");
  }
  if (!args.take("--verdict", verdict_text)) {
    return usage_error("compat-rule requires --verdict compatible|incompatible|unsupported");
  }
  trxreg::CompatVerdict verdict = trxreg::CompatVerdict::Unknown;
  if (!trxreg::compat_verdict_from_string(verdict_text, verdict) || verdict == trxreg::CompatVerdict::Unknown) {
    return usage_error("--verdict must be compatible, incompatible, or unsupported");
  }
  std::int32_t priority = 0;
  std::string text;
  if (args.take("--priority", text)) {
    std::int64_t parsed = 0;
    if (!parse_signed(text, parsed) || parsed < -2147483648LL || parsed > 2147483647LL) {
      return usage_error("--priority must be a 32-bit integer");
    }
    priority = static_cast<std::int32_t>(parsed);
  }
  const std::vector<std::string> specs = args.all("--require");
  if (specs.empty()) {
    return usage_error("compat-rule requires at least one --require SPEC");
  }
  Value::Array requirements;
  requirements.reserve(specs.size());
  for (const std::string& spec : specs) {
    Value requirement;
    if (!requirement_document(spec, requirement, message)) {
      return usage_error(message);
    }
    requirements.push_back(std::move(requirement));
  }
  Value rule = Value::object({
      {"enabled", Value::boolean(true)},
      {"name", Value::text(rule_name)},
      {"priority", Value::integer(static_cast<std::int64_t>(priority))},
      {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "declared")},
      {"rationale", Value::text("published by trxreg_cli")},
      {"requirements", Value::array(std::move(requirements))},
      {"verdict", Value::integer(static_cast<std::int64_t>(verdict))},
  });
  Value parameters = Value::object({
      {"authority", authority_document(authority)},
      {"policy", Value::text("auto_retry")},
      {"rule", std::move(rule)},
  });
  const Outcome outcome = perform(session, "compat.rule.publish", std::move(parameters));
  if (!outcome.ok) {
    return report(outcome);
  }
  print_document(outcome.document);
  return kExitOk;
}

/// A deterministic end to end demonstration that runs in both modes: the same
/// request sequence is dispatched in-process or sent to a server, then the
/// snapshot it wrote is reloaded and compared with the live registry.
int run_selftest(Session& session, Args& args) {
  std::string out_path;
  static_cast<void>(args.take("--out", out_path));
  if (out_path.empty()) {
    out_path = join_path(temporary_directory(),
                         "trxreg-cli-selftest-" + std::to_string(current_pid()) + ".trxr");
  }

  const Outcome source = perform(
      session, "source.register",
      Value::object({{"description", Value::text("Transceiver Registry self test")},
                     {"instance_id", Value::text("trxreg-cli-selftest")},
                     {"kind", Value::text("synthetic")},
                     {"name", Value::text("trxreg-cli-selftest")}}));
  if (!source.ok) {
    return report(source);
  }
  trxreg::AuthorityToken authority;
  authority.source = trxreg::SourceId{static_cast<std::uint32_t>(integer_field(source.document, "id", 0))};
  authority.epoch = trxreg::SourceEpoch{static_cast<std::uint32_t>(integer_field(source.document, "epoch", 0))};
  if (!authority.source.valid() || !authority.epoch.valid()) {
    return operation_error(StatusCode::Internal, "the self test source registration returned no usable authority");
  }

  const std::string module_key = "selftest/module-1";
  Value::Array identity;
  identity.push_back(Value::object({{"field", Value::integer(static_cast<std::int64_t>(trxreg::IdentityField::Vendor))},
                                    {"subkey", Value::text("")},
                                    {"value", Value::text("Summon Software Labs")}}));
  identity.push_back(Value::object({{"field", Value::integer(static_cast<std::int64_t>(trxreg::IdentityField::PartNumber))},
                                    {"subkey", Value::text("")},
                                    {"value", Value::text("TRX-SELFTEST-1")}}));
  identity.push_back(Value::object({{"field", Value::integer(static_cast<std::int64_t>(trxreg::IdentityField::SerialNumber))},
                                    {"subkey", Value::text("")},
                                    {"value", Value::text("SN00000001")}}));
  const Outcome module = perform(
      session, "module.register",
      Value::object({{"authority", authority_document(authority)},
                     {"expected_generation", Value::integer(0)},
                     {"identity", Value::array(std::move(identity))},
                     {"intent", Value::text("current")},
                     {"key", Value::text(module_key)},
                     {"policy", Value::text("auto_retry")},
                     {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")}}));
  if (!module.ok) {
    return report(module);
  }
  trxreg::ModuleHandle handle;
  if (!read_module_handle_document(module.document, handle)) {
    return operation_error(StatusCode::Internal, "the self test module registration returned no usable handle");
  }
  session.modules[module_key] = handle;

  struct CapabilityStep {
    CapabilityKey key;
    const char* value;
    const char* subkey;
  };
  const CapabilityStep steps[] = {
      {CapabilityKey::SpeedClasses, "gb100,gb400", ""},
      {CapabilityKey::LaneCount, "4", ""},
      {CapabilityKey::MaxPowerMilliWatts, "3.5", ""},
      {CapabilityKey::TemperatureTelemetry, "true", ""},
      {CapabilityKey::VendorSpecific, "selftest-fixture", "selftest"},
  };
  std::int64_t published = 0;
  for (const CapabilityStep& step : steps) {
    std::string message;
    Value value;
    if (!capability_value_document(step.key, step.value, value, message)) {
      return operation_error(StatusCode::Internal, "self test capability rejected: " + message);
    }
    const Outcome outcome = perform(
        session, "capability.publish",
        Value::object({{"authority", authority_document(authority)},
                       {"key", Value::text(std::string(trxreg::to_string(step.key)))},
                       {"module", module_handle_document(handle)},
                       {"policy", Value::text("auto_retry")},
                       {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")},
                       {"subkey", Value::text(step.subkey)},
                       {"value", std::move(value)}}));
    if (!outcome.ok) {
      return report(outcome);
    }
    ++published;
  }

  const std::string port_key = "selftest/port-1";
  Value port_value;
  std::string port_message;
  if (!capability_value_document(CapabilityKey::LaneCount, "4", port_value, port_message)) {
    return operation_error(StatusCode::Internal, "self test port capability rejected: " + port_message);
  }
  const Outcome port = perform(
      session, "port.capability.publish",
      Value::object({{"authority", authority_document(authority)},
                     {"key", Value::text("lane_count")},
                     {"policy", Value::text("auto_retry")},
                     {"port", Value::text(port_key)},
                     {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")},
                     {"subkey", Value::text("")},
                     {"value", std::move(port_value)}}));
  if (!port.ok) {
    return report(port);
  }

  Value threshold = Value::object({
      {"critical_enter", Value::real(80.0)},
      {"critical_exit", Value::real(75.0)},
      {"degraded_enter", Value::real(70.0)},
      {"degraded_exit", Value::real(65.0)},
      {"direction", Value::integer(static_cast<std::int64_t>(trxreg::ThresholdDirection::Above))},
      {"disagreement_tolerance", Value::real(0.5)},
      {"escalate_after", Value::integer(1)},
      {"generation", Value::integer(0)},
      {"has_critical", Value::boolean(true)},
      {"has_degraded", Value::boolean(true)},
      {"lane", Value::integer(static_cast<std::int64_t>(trxreg::kModuleLane))},
      {"live", Value::boolean(true)},
      {"max_age_ns", Value::integer(60000000000LL)},
      {"metric", Value::integer(static_cast<std::int64_t>(trxreg::HealthMetric::TemperatureCelsius))},
      {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")},
      {"recover_after", Value::integer(1)},
      {"sequence", Value::integer(0)},
      {"source", Value::integer(0)},
      {"source_epoch", Value::integer(0)},
  });
  const Outcome threshold_outcome = perform(
      session, "health.threshold.publish",
      Value::object({{"authority", authority_document(authority)},
                     {"policy", Value::text("auto_retry")},
                     {"threshold", std::move(threshold)}}));
  if (!threshold_outcome.ok) {
    return report(threshold_outcome);
  }

  const double measured = 55.25;
  Value sample = Value::object({
      {"clock_domain", Value::integer(0)},
      {"lane", Value::integer(static_cast<std::int64_t>(trxreg::kModuleLane))},
      {"metric", Value::integer(static_cast<std::int64_t>(trxreg::HealthMetric::TemperatureCelsius))},
      {"observed_at_monotonic_ns", Value::integer(0)},
      {"observed_at_wall_ns", Value::integer(session.clock->wall_now_ns())},
      {"presence", Value::integer(static_cast<std::int64_t>(trxreg::SamplePresence::Present))},
      {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")},
      {"value", Value::real(measured)},
  });
  const Outcome ingest = perform(
      session, "health.ingest",
      Value::object({{"authority", authority_document(authority)},
                     {"module", module_handle_document(handle)},
                     {"policy", Value::text("auto_retry")},
                     {"sample", std::move(sample)}}));
  if (!ingest.ok) {
    return report(ingest);
  }

  const Outcome health = perform(session, "health.report", module_reference_document(handle));
  if (!health.ok) {
    return report(health);
  }

  Value::Array requirements;
  {
    Value first;
    std::string message;
    if (!requirement_document("module:speed_classes:superset_of:gb100", first, message)) {
      return operation_error(StatusCode::Internal, "self test requirement rejected: " + message);
    }
    Value second;
    if (!requirement_document("port:lane_count:at_least:4", second, message)) {
      return operation_error(StatusCode::Internal, "self test requirement rejected: " + message);
    }
    requirements.push_back(std::move(first));
    requirements.push_back(std::move(second));
  }
  const std::string rule_name = "selftest.gb100-and-four-lanes";
  const Outcome rule = perform(
      session, "compat.rule.publish",
      Value::object({{"authority", authority_document(authority)},
                     {"policy", Value::text("auto_retry")},
                     {"rule", Value::object({
                                  {"enabled", Value::boolean(true)},
                                  {"name", Value::text(rule_name)},
                                  {"priority", Value::integer(10)},
                                  {"provenance", provenance_document(EvidenceKind::Synthetic, "trxreg-cli", "selftest")},
                                  {"rationale", Value::text("self test rule")},
                                  {"requirements", Value::array(std::move(requirements))},
                                  {"verdict", Value::integer(static_cast<std::int64_t>(trxreg::CompatVerdict::Compatible))},
                              })}}));
  if (!rule.ok) {
    return report(rule);
  }

  Value query = Value::object({
      {"explain", Value::boolean(true)},
      {"expected_generation", Value::integer(0)},
      {"incarnation", Value::integer(static_cast<std::int64_t>(handle.incarnation.value()))},
      {"port", Value::text(port_key)},
      {"require_latest_generation", Value::boolean(false)},
      {"uid", Value::integer(static_cast<std::int64_t>(handle.uid.value()))},
  });
  const Outcome decision = perform(session, "compat.query", std::move(query));
  if (!decision.ok) {
    return report(decision);
  }

  const Outcome saved = perform(session, "registry.save", Value::object({{"path", Value::text(out_path)}}));
  if (!saved.ok) {
    return report(saved);
  }
  const Outcome generation = perform(session, "registry.generation", Value::object({}));

  trxreg::Registry reloaded{trxreg::RegistryConfig{}, session.clock};
  const trxreg::Result<trxreg::LoadReport> report_value = reloaded.load(out_path);
  if (!report_value.ok()) {
    return operation_error(report_value.error().code, report_value.error().message);
  }

  const Value* metrics = health.document.find("metrics");
  const Value* first_metric = metrics != nullptr && metrics->is_array() && !metrics->as_array().empty()
                                  ? &metrics->as_array().front()
                                  : nullptr;
  const std::int64_t metric_state = first_metric != nullptr ? integer_field(*first_metric, "state", 0) : 0;
  const auto outcome_text = [](std::int64_t raw) { return std::string(compat_outcome_text(raw)); };
  const auto closure_text = [](std::int64_t raw) { return std::string(knowledge_closure_text(raw)); };
  const Value* matched = decision.document.find("matched_rules");
  const std::int64_t matched_count =
      matched != nullptr && matched->is_array() ? static_cast<std::int64_t>(matched->as_array().size()) : 0;

  const Outcome stats = perform(session, "registry.stats", Value::object({}));
  if (!stats.ok) {
    return report(stats);
  }
  const trxreg::LoadReport& loaded = report_value.value();
  const std::int64_t live_generation = integer_field(generation.document, "generation", 0);
  const std::int64_t loaded_generation = static_cast<std::int64_t>(loaded.generation.value());
  const bool counters_match =
      integer_field(stats.document, "modules", -1) == static_cast<std::int64_t>(loaded.modules) &&
      integer_field(stats.document, "claims", -1) == static_cast<std::int64_t>(loaded.claims) &&
      integer_field(stats.document, "declarations", -1) == static_cast<std::int64_t>(loaded.declarations) &&
      integer_field(stats.document, "samples", -1) == static_cast<std::int64_t>(loaded.samples) &&
      integer_field(stats.document, "rules", -1) == static_cast<std::int64_t>(loaded.rules) &&
      integer_field(stats.document, "thresholds", -1) == static_cast<std::int64_t>(loaded.thresholds) &&
      integer_field(stats.document, "sources", -1) == static_cast<std::int64_t>(loaded.sources) &&
      integer_field(stats.document, "ports", -1) == static_cast<std::int64_t>(loaded.ports);
  // Loading is a new registry incarnation: the reloaded generation is the saved
  // generation plus one, by design.
  const bool generation_matches = loaded_generation == live_generation + 1;

  Value summary = Value::object({
      {"capabilities_published", Value::integer(published)},
      {"decision",
       Value::object({{"closure", Value::text(closure_text(integer_field(decision.document, "closure", 0)))},
                      {"matched_rules", Value::integer(matched_count)},
                      {"outcome", Value::text(outcome_text(integer_field(decision.document, "outcome", 0)))}})},
      {"matches", Value::boolean(counters_match && generation_matches)},
      {"mode", Value::text(session.remote ? "remote" : "in-process")},
      {"module",
       Value::object({{"incarnation", Value::integer(static_cast<std::int64_t>(handle.incarnation.value()))},
                      {"key", Value::text(module_key)},
                      {"uid", Value::integer(static_cast<std::int64_t>(handle.uid.value()))}})},
      {"port_capabilities_published", Value::integer(1)},
      {"registry_generation", Value::integer(live_generation)},
      {"reloaded",
       Value::object({{"claims", Value::integer(static_cast<std::int64_t>(report_value.value().claims))},
                      {"declarations", Value::integer(static_cast<std::int64_t>(report_value.value().declarations))},
                      {"generation", Value::integer(loaded_generation)},
                      {"modules", Value::integer(static_cast<std::int64_t>(report_value.value().modules))},
                      {"ports", Value::integer(static_cast<std::int64_t>(report_value.value().ports))},
                      {"rules", Value::integer(static_cast<std::int64_t>(report_value.value().rules))},
                      {"samples", Value::integer(static_cast<std::int64_t>(report_value.value().samples))},
                      {"sources", Value::integer(static_cast<std::int64_t>(report_value.value().sources))},
                      {"thresholds", Value::integer(static_cast<std::int64_t>(report_value.value().thresholds))}})},
      {"rule",
       Value::object({{"generation", Value::integer(integer_field(rule.document, "generation", 0))},
                      {"id", Value::integer(integer_field(rule.document, "id", 0))},
                      {"name", Value::text(rule_name)}})},
      {"sample",
       Value::object({{"metric", Value::text("temperature_celsius")},
                      {"state", Value::text(std::string(trxreg::to_string(static_cast<trxreg::MetricState>(metric_state))))},
                      {"value", Value::real(measured)}})},
      {"saved",
       Value::object({{"bytes", Value::integer(static_cast<std::int64_t>(file_size(out_path)))},
                      {"path", Value::text(out_path)}})},
      {"source",
       Value::object({{"epoch", Value::integer(static_cast<std::int64_t>(authority.epoch.value()))},
                      {"id", Value::integer(static_cast<std::int64_t>(authority.source.value()))}})},
      {"threshold", Value::object({{"max_age_ns", Value::integer(60000000000LL)},
                                   {"metric", Value::text("temperature_celsius")}})},
  });
  print_document(summary);
  return kExitOk;
}

int run_command(Session& session, const std::string& name, Args& args, bool& handled) {
  if (name == "selftest") {
    handled = true;
    return run_selftest(session, args);
  }
  int code = run_query_command(session, name, args, handled);
  if (handled) {
    return code;
  }
  code = run_registration_command(session, name, args, handled);
  if (handled) {
    return code;
  }
  code = run_module_command(session, name, args, handled);
  if (handled) {
    return code;
  }
  code = run_policy_command(session, name, args, handled);
  if (handled) {
    return code;
  }
  return kExitOk;
}

int run(int argc, char** argv) {
  if (argc >= 2) {
    const std::string_view first(argv[1]);
    if (first == "--help" || first == "-h") {
      print_usage(stdout);
      return kExitOk;
    }
  }
  std::string server;
  std::string snapshot;
  std::vector<Command> commands;
  std::string error;
  if (!parse_arguments(argc, argv, server, snapshot, commands, error)) {
    return usage_error(error);
  }

  Session session;
  session.snapshot = snapshot;
  session.clock = trxreg::make_system_clock();
  if (!server.empty()) {
    const std::size_t colon = server.rfind(':');
    if (colon == std::string::npos || colon == 0) {
      return usage_error("--server must read HOST:PORT");
    }
    const std::string host = server.substr(0, colon);
    std::uint32_t port = 0;
    if (!parse_u32(server.substr(colon + 1), port) || port == 0 || port > 65535) {
      return usage_error("--server must read HOST:PORT with a port in [1, 65535]");
    }
    trxreg::Result<trxreg::wire::Client> connected =
        trxreg::wire::Client::connect(host, static_cast<std::uint16_t>(port));
    if (!connected.ok()) {
      return operation_error(connected.error().code, connected.error().message);
    }
    session.client = std::make_unique<trxreg::wire::Client>(std::move(connected.value()));
    session.remote = true;
    session.endpoint = server;
  } else {
    session.registry = std::make_unique<trxreg::Registry>(trxreg::RegistryConfig{}, session.clock);
    session.endpoint = "in-process";
    if (!snapshot.empty() && file_exists(snapshot)) {
      const trxreg::Result<trxreg::LoadReport> loaded = session.registry->load(snapshot);
      if (!loaded.ok()) {
        return operation_error(loaded.error().code, loaded.error().message);
      }
    }
  }

  for (Command& command : commands) {
    bool handled = false;
    const int code = run_command(session, command.name, command.args, handled);
    if (!handled) {
      return usage_error("unknown subcommand '" + command.name + "'");
    }
    if (code != kExitOk) {
      return code;
    }
    std::string unused;
    if (command.args.first_unused(unused)) {
      return usage_error("unknown option '" + unused + "' for subcommand " + command.name);
    }
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "error: internal: %s\n", error.what());
    return kExitFailure;
  } catch (...) {
    std::fprintf(stderr, "error: internal: an unknown exception escaped the client\n");
    return kExitFailure;
  }
}










