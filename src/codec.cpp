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

#include "codec.hpp"

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/result.hpp"
#include "value_fields.hpp"

// Canonical codecs for every persisted / transported record.
//
// Encoding always produces a canonical object, so the member order is fixed by
// Value::object and never by the encoder. Decoding re-validates presence, type,
// range, and enum domain for every field before the record is constructed: a
// malformed document can never be turned into a plausible-looking record, and a
// field that decode cannot reconstruct is never omitted from the encoding.
//
// Unknown members are ignored on decode (a newer writer may add fields that an
// older reader does not understand); every member this file writes is required
// on decode, so a missing member is Malformed rather than defaulted.

namespace trxreg::codec {

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

Value object(std::vector<Value::Member> members) { return Value::object(std::move(members)); }

Value text_array(const std::vector<std::string>& values) {
  Value::Array entries;
  entries.reserve(values.size());
  for (const std::string& value : values) {
    entries.push_back(Value::text(value));
  }
  return Value::array(std::move(entries));
}

Result<const Value::Object*> as_object(const Value& value, std::string_view what) {
  TRXREG_TRY_ASSIGN(record, detail::as_object(value, what));
  if (!record->is_object()) {
    return make_error(StatusCode::Malformed, std::string(what) + " must be a canonical object");
  }
  return &record->as_object();
}

Result<std::int64_t> get_integer(const Value& encoded, std::string_view key) {
  return detail::get_integer(encoded, key);
}

Result<std::uint64_t> get_unsigned(const Value& encoded, std::string_view key) {
  return detail::get_unsigned(encoded, key);
}

Result<bool> get_boolean(const Value& encoded, std::string_view key) {
  return detail::get_boolean(encoded, key);
}

Result<double> get_real(const Value& encoded, std::string_view key) {
  return detail::get_real(encoded, key);
}

Result<std::string> get_text(const Value& encoded, std::string_view key) {
  return detail::get_text(encoded, key);
}

Result<Digest> get_digest(const Value& encoded, std::string_view key) {
  return detail::get_digest(encoded, key);
}

Result<const Value::Array*> get_array(const Value& encoded, std::string_view key) {
  return detail::get_array(encoded, key);
}

std::int64_t get_integer_or(const Value& encoded, std::string_view key, std::int64_t fallback) {
  return detail::get_integer_or(encoded, key, fallback);
}

std::uint64_t get_unsigned_or(const Value& encoded, std::string_view key, std::uint64_t fallback) {
  return detail::get_unsigned_or(encoded, key, fallback);
}

bool get_boolean_or(const Value& encoded, std::string_view key, bool fallback) {
  return detail::get_boolean_or(encoded, key, fallback);
}

double get_real_or(const Value& encoded, std::string_view key, double fallback) {
  return detail::get_real_or(encoded, key, fallback);
}

std::string get_text_or(const Value& encoded, std::string_view key, std::string_view fallback) {
  return detail::get_text_or(encoded, key, fallback);
}

Digest get_digest_or(const Value& encoded, std::string_view key) { return detail::get_digest_or(encoded, key); }

const Value::Array* get_array_or(const Value& encoded, std::string_view key) {
  return detail::get_array_or(encoded, key);
}

// ---------------------------------------------------------------------------
// Repeated decode patterns
// ---------------------------------------------------------------------------

namespace {

/// Enum field: the domain is validated against the last declared enumerator.
template <class Enum>
Result<Enum> get_enum_field(const Value& record, std::string_view key, Enum last, std::string_view what) {
  return detail::get_enum<Enum>(record, key, static_cast<std::uint8_t>(last), what);
}

/// Unsigned integer fields narrower than uint64 are range checked, never truncated.
Result<std::uint16_t> get_u16(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(raw, detail::get_unsigned(record, key));
  if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::uint16_t>::max())) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " is out of range");
  }
  return static_cast<std::uint16_t>(raw);
}

Result<std::uint32_t> get_u32(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(raw, detail::get_unsigned(record, key));
  if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " is out of range");
  }
  return static_cast<std::uint32_t>(raw);
}

Result<std::int32_t> get_i32(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(raw, detail::get_integer(record, key));
  if (raw < static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()) ||
      raw > static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max())) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " is out of range");
  }
  return static_cast<std::int32_t>(raw);
}

/// A measurement is never NaN or infinite: neither can be compared or aged.
Result<double> get_finite_real(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(raw, detail::get_real(record, key));
  if (!std::isfinite(raw)) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be finite");
  }
  return raw;
}

/// Nested record field, decoded by the nested type's own codec.
template <class T>
Result<T> get_record(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, detail::require_field(record, key));
  return Codec<T>::decode(*field);
}

/// Array of nested records. The decoded array is walked rather than sized from
/// an externally supplied count.
template <class T>
Result<std::vector<T>> get_record_array(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(array, detail::get_array(record, key));
  std::vector<T> out;
  for (const Value& entry : *array) {
    TRXREG_TRY_ASSIGN(item, Codec<T>::decode(entry));
    out.push_back(std::move(item));
  }
  return out;
}

/// Encode an array of nested records.
template <class T>
Value encode_record_array(const std::vector<T>& values) {
  Value::Array entries;
  entries.reserve(values.size());
  for (const T& value : values) {
    entries.push_back(Codec<T>::encode(value));
  }
  return Value::array(std::move(entries));
}

std::int64_t as_integer(std::uint64_t value) noexcept { return static_cast<std::int64_t>(value); }

/// Digest field. Digest::from_hex classifies a bad hex string as
/// InvalidArgument, but the offending text came from the document rather than
/// from a caller argument, so the codec reports Malformed.
Result<Digest> get_digest_field(const Value& record, std::string_view key) {
  TRXREG_TRY_ASSIGN(text, detail::get_text(record, key));
  const Result<Digest> parsed = Digest::from_hex(text);
  if (!parsed.ok()) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be SHA-256 hex text");
  }
  return parsed;
}

/// Textual key field. An empty key is a legitimate record state (a module
/// subject declaration carries no port, an unattached module has no slot) and
/// TextKey::parse refuses empty text, so the default-constructed key is the
/// faithful representation of an empty key. A non-empty key is always validated.
template <class Key>
Result<Key> get_key(const Value& record, std::string_view key, std::string_view what) {
  TRXREG_TRY_ASSIGN(text, detail::get_text(record, key));
  if (text.empty()) {
    return Key{};
  }
  return Key::parse(text, what);
}

}  // namespace

// ---------------------------------------------------------------------------
// Provenance and source identity
// ---------------------------------------------------------------------------

Value Codec<Provenance>::encode(const Provenance& value) {
  return object({
      {"capture_ref", Value::text(value.capture_ref)},
      {"content_digest", Value::text(value.content_digest.to_hex())},
      {"kind", Value::integer(static_cast<std::int64_t>(value.kind))},
      {"method", Value::text(value.method)},
      {"origin", Value::text(value.origin)},
  });
}

Result<Provenance> Codec<Provenance>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "provenance"));
  Provenance out;
  TRXREG_TRY_ASSIGN(kind, get_enum_field(encoded, "kind", EvidenceKind::Unsupported, "provenance kind"));
  out.kind = kind;
  TRXREG_TRY_ASSIGN(origin, detail::get_text(encoded, "origin"));
  out.origin = std::move(origin);
  TRXREG_TRY_ASSIGN(method, detail::get_text(encoded, "method"));
  out.method = std::move(method);
  TRXREG_TRY_ASSIGN(content_digest, get_digest_field(encoded, "content_digest"));
  out.content_digest = content_digest;
  TRXREG_TRY_ASSIGN(capture_ref, detail::get_text(encoded, "capture_ref"));
  out.capture_ref = std::move(capture_ref);
  return out;
}

Value Codec<SourceDescriptor>::encode(const SourceDescriptor& value) {
  return object({
      {"declared_kind", Value::integer(static_cast<std::int64_t>(value.declared_kind))},
      {"description", Value::text(value.description)},
      {"instance_id", Value::text(value.instance_id)},
      {"name", Value::text(value.name)},
  });
}

Result<SourceDescriptor> Codec<SourceDescriptor>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "source descriptor"));
  SourceDescriptor out;
  TRXREG_TRY_ASSIGN(name, detail::get_text(encoded, "name"));
  out.name = std::move(name);
  TRXREG_TRY_ASSIGN(description, detail::get_text(encoded, "description"));
  out.description = std::move(description);
  TRXREG_TRY_ASSIGN(declared_kind, get_enum_field(encoded, "declared_kind", EvidenceKind::Unsupported,
                                                  "source descriptor declared kind"));
  out.declared_kind = declared_kind;
  TRXREG_TRY_ASSIGN(instance_id, detail::get_text(encoded, "instance_id"));
  out.instance_id = std::move(instance_id);
  return out;
}

Value Codec<SourceHandle>::encode(const SourceHandle& value) {
  return object({
      {"epoch", Value::integer(static_cast<std::int64_t>(value.epoch.value()))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"id", Value::integer(static_cast<std::int64_t>(value.id.value()))},
  });
}

Result<SourceHandle> Codec<SourceHandle>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "source handle"));
  SourceHandle out;
  TRXREG_TRY_ASSIGN(id, get_u32(encoded, "id"));
  out.id = SourceId{id};
  TRXREG_TRY_ASSIGN(epoch, get_u32(encoded, "epoch"));
  out.epoch = SourceEpoch{epoch};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  return out;
}

Value Codec<ModuleHandle>::encode(const ModuleHandle& value) {
  return object({
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"key", Value::text(value.key.str())},
      {"uid", Value::integer(as_integer(value.uid.value()))},
  });
}

Result<ModuleHandle> Codec<ModuleHandle>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "module handle"));
  ModuleHandle out;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(parsed_key, get_key<ModuleKey>(encoded, "key", "module handle key"));
  out.key = parsed_key;
  return out;
}

Value Codec<AuthorityToken>::encode(const AuthorityToken& value) {
  return object({
      {"epoch", Value::integer(static_cast<std::int64_t>(value.epoch.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
  });
}

Result<AuthorityToken> Codec<AuthorityToken>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "authority token"));
  AuthorityToken out;
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(epoch, get_u32(encoded, "epoch"));
  out.epoch = SourceEpoch{epoch};
  return out;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

Value Codec<IdentityFieldValue>::encode(const IdentityFieldValue& value) {
  return object({
      {"field", Value::integer(static_cast<std::int64_t>(value.field))},
      {"subkey", Value::text(value.subkey)},
      {"value", Value::text(value.value)},
  });
}

Result<IdentityFieldValue> Codec<IdentityFieldValue>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "identity field value"));
  IdentityFieldValue out;
  TRXREG_TRY_ASSIGN(field, get_enum_field(encoded, "field", IdentityField::VendorSpecific, "identity field"));
  out.field = field;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(value, detail::get_text(encoded, "value"));
  out.value = std::move(value);
  return out;
}

Value Codec<IdentityClaim>::encode(const IdentityClaim& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"field", Value::integer(static_cast<std::int64_t>(value.field))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"live", Value::boolean(value.live)},
      {"module", Value::integer(as_integer(value.module.value()))},
      {"observed_at_wall_ns", Value::integer(value.observed_at_wall_ns)},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
      {"subkey", Value::text(value.subkey)},
      {"value", Value::text(value.value)},
  });
}

Result<IdentityClaim> Codec<IdentityClaim>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "identity claim"));
  IdentityClaim out;
  TRXREG_TRY_ASSIGN(field, get_enum_field(encoded, "field", IdentityField::VendorSpecific, "identity claim field"));
  out.field = field;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(value, detail::get_text(encoded, "value"));
  out.value = std::move(value);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(module, detail::get_unsigned(encoded, "module"));
  out.module = ModuleUid{module};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(observed_at_wall_ns, detail::get_integer(encoded, "observed_at_wall_ns"));
  out.observed_at_wall_ns = observed_at_wall_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  return out;
}

Value Codec<FieldConsensus>::encode(const FieldConsensus& value) {
  return object({
      {"claims", encode_record_array(value.claims)},
      {"digest", Value::text(value.digest.to_hex())},
      {"field", Value::integer(static_cast<std::int64_t>(value.field))},
      {"has_value", Value::boolean(value.has_value)},
      {"outcome", Value::integer(static_cast<std::int64_t>(value.outcome))},
      {"subkey", Value::text(value.subkey)},
      {"superseded_claims", encode_record_array(value.superseded_claims)},
      {"value", Value::text(value.value)},
  });
}

Result<FieldConsensus> Codec<FieldConsensus>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "field consensus"));
  FieldConsensus out;
  TRXREG_TRY_ASSIGN(field, get_enum_field(encoded, "field", IdentityField::VendorSpecific, "consensus field"));
  out.field = field;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(outcome, get_enum_field(encoded, "outcome", ConsensusOutcome::Superseded, "consensus outcome"));
  out.outcome = outcome;
  TRXREG_TRY_ASSIGN(has_value, detail::get_boolean(encoded, "has_value"));
  out.has_value = has_value;
  TRXREG_TRY_ASSIGN(value, detail::get_text(encoded, "value"));
  out.value = std::move(value);
  TRXREG_TRY_ASSIGN(decoded_claims, get_record_array<IdentityClaim>(encoded, "claims"));
  out.claims = std::move(decoded_claims);
  TRXREG_TRY_ASSIGN(decoded_superseded_claims, get_record_array<IdentityClaim>(encoded, "superseded_claims"));
  out.superseded_claims = std::move(decoded_superseded_claims);
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  return out;
}

Value Codec<IdentityView>::encode(const IdentityView& value) {
  return object({
      {"conflicting_fields", Value::integer(static_cast<std::int64_t>(value.conflicting_fields))},
      {"digest", Value::text(value.digest.to_hex())},
      {"fields", encode_record_array(value.fields)},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"key", Value::text(value.key.str())},
      {"lifecycle", Value::integer(static_cast<std::int64_t>(value.lifecycle))},
      {"superseded_fields", Value::integer(static_cast<std::int64_t>(value.superseded_fields))},
      {"uid", Value::integer(as_integer(value.uid.value()))},
  });
}

Result<IdentityView> Codec<IdentityView>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "identity view"));
  IdentityView out;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(parsed_key, get_key<ModuleKey>(encoded, "key", "identity view key"));
  out.key = parsed_key;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(lifecycle, get_enum_field(encoded, "lifecycle", LifecycleState::Replaced, "lifecycle state"));
  out.lifecycle = lifecycle;
  TRXREG_TRY_ASSIGN(decoded_fields, get_record_array<FieldConsensus>(encoded, "fields"));
  out.fields = std::move(decoded_fields);
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  TRXREG_TRY_ASSIGN(conflicting_fields, get_u32(encoded, "conflicting_fields"));
  out.conflicting_fields = conflicting_fields;
  TRXREG_TRY_ASSIGN(superseded_fields, get_u32(encoded, "superseded_fields"));
  out.superseded_fields = superseded_fields;
  return out;
}

Value Codec<ModuleRegistration>::encode(const ModuleRegistration& value) {
  return object({
      {"expected_generation", Value::integer(as_integer(value.expected_generation.value()))},
      {"identity", encode_record_array(value.identity)},
      {"intent", Value::integer(static_cast<std::int64_t>(value.intent))},
      {"key", Value::text(value.key.str())},
      {"policy", Value::integer(static_cast<std::int64_t>(value.policy))},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
  });
}

Result<ModuleRegistration> Codec<ModuleRegistration>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "module registration"));
  ModuleRegistration out;
  TRXREG_TRY_ASSIGN(parsed_key, get_key<ModuleKey>(encoded, "key", "module registration key"));
  out.key = parsed_key;
  TRXREG_TRY_ASSIGN(decoded_identity, get_record_array<IdentityFieldValue>(encoded, "identity"));
  out.identity = std::move(decoded_identity);
  TRXREG_TRY_ASSIGN(intent, get_enum_field(encoded, "intent", RegisterIntent::NewIncarnation, "register intent"));
  out.intent = intent;
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(policy, get_enum_field(encoded, "policy", MutationPolicy::AutoRetry, "mutation policy"));
  out.policy = policy;
  TRXREG_TRY_ASSIGN(expected_generation, detail::get_unsigned(encoded, "expected_generation"));
  out.expected_generation = Generation{expected_generation};
  return out;
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

Value Codec<SpectrumDescriptor>::encode(const SpectrumDescriptor& value) {
  return object({
      {"center_nm", Value::real(value.center_nm)},
      {"channel", Value::text(value.channel)},
      {"frequency_thz", Value::real(value.frequency_thz)},
      {"grid", Value::integer(static_cast<std::int64_t>(value.grid))},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
  });
}

Result<SpectrumDescriptor> Codec<SpectrumDescriptor>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "spectrum descriptor"));
  SpectrumDescriptor out;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(center_nm, get_finite_real(encoded, "center_nm"));
  out.center_nm = center_nm;
  TRXREG_TRY_ASSIGN(frequency_thz, get_finite_real(encoded, "frequency_thz"));
  out.frequency_thz = frequency_thz;
  TRXREG_TRY_ASSIGN(grid, get_enum_field(encoded, "grid", WavelengthGrid::Unsupported, "wavelength grid"));
  out.grid = grid;
  TRXREG_TRY_ASSIGN(channel, detail::get_text(encoded, "channel"));
  out.channel = std::move(channel);
  return out;
}

Value Codec<CapabilityValue>::encode(const CapabilityValue& value) {
  switch (value.kind()) {
    case CapabilityValueKind::None:
      return object({{"k", Value::text("none")}});
    case CapabilityValueKind::Boolean: {
      bool raw = false;
      static_cast<void>(value.as_boolean(raw));
      return object({
          {"b", Value::boolean(raw)},
          {"k", Value::text("boolean")},
      });
    }
    case CapabilityValueKind::Count: {
      std::int64_t raw = 0;
      static_cast<void>(value.as_count(raw));
      return object({
          {"i", Value::integer(raw)},
          {"k", Value::text("count")},
      });
    }
    case CapabilityValueKind::Enum: {
      std::int64_t raw = 0;
      static_cast<void>(value.as_enumeration(raw));
      return object({
          {"i", Value::integer(raw)},
          {"k", Value::text("enum")},
      });
    }
    case CapabilityValueKind::Real: {
      double raw = 0.0;
      static_cast<void>(value.as_real(raw));
      return object({
          {"k", Value::text("real")},
          {"r", Value::real(raw)},
      });
    }
    case CapabilityValueKind::Text: {
      const std::string* raw = value.as_text();
      const std::string empty;
      return object({
          {"k", Value::text("text")},
          {"t", Value::text(raw != nullptr ? *raw : empty)},
      });
    }
    case CapabilityValueKind::EnumSet: {
      const CapabilityValue::EnumSet* values = value.as_enum_set();
      Value::Array entries;
      if (values != nullptr) {
        entries.reserve(values->size());
        for (const std::int64_t entry : *values) {
          entries.push_back(Value::integer(entry));
        }
      }
      return object({
          {"k", Value::text("enum_set")},
          {"s", Value::array(std::move(entries))},
      });
    }
    case CapabilityValueKind::TextSet: {
      const CapabilityValue::TextSet* values = value.as_text_set();
      Value::Array entries;
      if (values != nullptr) {
        entries.reserve(values->size());
        for (const std::string& entry : *values) {
          entries.push_back(Value::text(entry));
        }
      }
      return object({
          {"k", Value::text("text_set")},
          {"s", Value::array(std::move(entries))},
      });
    }
    case CapabilityValueKind::Spectrum: {
      const CapabilityValue::Spectrum* values = value.as_spectrum();
      Value::Array entries;
      if (values != nullptr) {
        entries.reserve(values->size());
        for (const SpectrumDescriptor& entry : *values) {
          entries.push_back(Codec<SpectrumDescriptor>::encode(entry));
        }
      }
      return object({
          {"k", Value::text("spectrum")},
          {"s", Value::array(std::move(entries))},
      });
    }
  }
  return object({{"k", Value::text("none")}});
}

Result<CapabilityValue> Codec<CapabilityValue>::decode(const Value& encoded) {
  CapabilityValue out;
  TRXREG_TRY(read_canonical(encoded, out));
  return out;
}

Value Codec<CapabilityDeclaration>::encode(const CapabilityDeclaration& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"key", Value::integer(static_cast<std::int64_t>(value.key))},
      {"live", Value::boolean(value.live)},
      {"module", Value::integer(as_integer(value.module.value()))},
      {"module_subject", Value::boolean(value.module_subject)},
      {"observed_at_wall_ns", Value::integer(value.observed_at_wall_ns)},
      {"port", Value::text(value.port.str())},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
      {"subkey", Value::text(value.subkey)},
      {"value", Codec<CapabilityValue>::encode(value.value)},
  });
}

Result<CapabilityDeclaration> Codec<CapabilityDeclaration>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "capability declaration"));
  CapabilityDeclaration out;
  TRXREG_TRY_ASSIGN(key, get_enum_field(encoded, "key", CapabilityKey::Unsupported, "capability key"));
  out.key = key;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(decoded_value, get_record<CapabilityValue>(encoded, "value"));
  out.value = std::move(decoded_value);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(module, detail::get_unsigned(encoded, "module"));
  out.module = ModuleUid{module};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(parsed_port, get_key<PortKey>(encoded, "port", "capability declaration port"));
  out.port = parsed_port;
  TRXREG_TRY_ASSIGN(module_subject, detail::get_boolean(encoded, "module_subject"));
  out.module_subject = module_subject;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(observed_at_wall_ns, detail::get_integer(encoded, "observed_at_wall_ns"));
  out.observed_at_wall_ns = observed_at_wall_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  return out;
}

Value Codec<CapabilityConsensus>::encode(const CapabilityConsensus& value) {
  return object({
      {"declarations", encode_record_array(value.declarations)},
      {"digest", Value::text(value.digest.to_hex())},
      {"has_value", Value::boolean(value.has_value)},
      {"key", Value::integer(static_cast<std::int64_t>(value.key))},
      {"outcome", Value::integer(static_cast<std::int64_t>(value.outcome))},
      {"subkey", Value::text(value.subkey)},
      {"superseded", encode_record_array(value.superseded)},
      {"value", Codec<CapabilityValue>::encode(value.value)},
  });
}

Result<CapabilityConsensus> Codec<CapabilityConsensus>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "capability consensus"));
  CapabilityConsensus out;
  TRXREG_TRY_ASSIGN(key, get_enum_field(encoded, "key", CapabilityKey::Unsupported, "capability consensus key"));
  out.key = key;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(outcome, get_enum_field(encoded, "outcome", ConsensusOutcome::Superseded, "consensus outcome"));
  out.outcome = outcome;
  TRXREG_TRY_ASSIGN(has_value, detail::get_boolean(encoded, "has_value"));
  out.has_value = has_value;
  TRXREG_TRY_ASSIGN(decoded_value, get_record<CapabilityValue>(encoded, "value"));
  out.value = std::move(decoded_value);
  TRXREG_TRY_ASSIGN(decoded_declarations, get_record_array<CapabilityDeclaration>(encoded, "declarations"));
  out.declarations = std::move(decoded_declarations);
  TRXREG_TRY_ASSIGN(decoded_superseded, get_record_array<CapabilityDeclaration>(encoded, "superseded"));
  out.superseded = std::move(decoded_superseded);
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  return out;
}

Value Codec<CapabilityView>::encode(const CapabilityView& value) {
  return object({
      {"attributes", encode_record_array(value.attributes)},
      {"conflicting_attributes", Value::integer(static_cast<std::int64_t>(value.conflicting_attributes))},
      {"digest", Value::text(value.digest.to_hex())},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"module_subject", Value::boolean(value.module_subject)},
      {"port", Value::text(value.port.str())},
      {"uid", Value::integer(as_integer(value.uid.value()))},
      {"unestablished_attributes", Value::integer(static_cast<std::int64_t>(value.unestablished_attributes))},
  });
}

Result<CapabilityView> Codec<CapabilityView>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "capability view"));
  CapabilityView out;
  TRXREG_TRY_ASSIGN(module_subject, detail::get_boolean(encoded, "module_subject"));
  out.module_subject = module_subject;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(parsed_port, get_key<PortKey>(encoded, "port", "capability view port"));
  out.port = parsed_port;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(decoded_attributes, get_record_array<CapabilityConsensus>(encoded, "attributes"));
  out.attributes = std::move(decoded_attributes);
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  TRXREG_TRY_ASSIGN(conflicting_attributes, get_u32(encoded, "conflicting_attributes"));
  out.conflicting_attributes = conflicting_attributes;
  TRXREG_TRY_ASSIGN(unestablished_attributes, get_u32(encoded, "unestablished_attributes"));
  out.unestablished_attributes = unestablished_attributes;
  return out;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

Value Codec<HealthSampleInput>::encode(const HealthSampleInput& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
      {"metric", Value::integer(static_cast<std::int64_t>(value.metric))},
      {"observed_at_monotonic_ns", Value::integer(as_integer(value.observed_at_monotonic_ns))},
      {"observed_at_wall_ns", Value::integer(value.observed_at_wall_ns)},
      {"presence", Value::integer(static_cast<std::int64_t>(value.presence))},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"value", Value::real(value.value)},
  });
}

Result<HealthSampleInput> Codec<HealthSampleInput>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health sample input"));
  HealthSampleInput out;
  TRXREG_TRY_ASSIGN(metric, get_enum_field(encoded, "metric", HealthMetric::Unsupported, "health metric"));
  out.metric = metric;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(presence, get_enum_field(encoded, "presence", SamplePresence::NotSupported, "sample presence"));
  out.presence = presence;
  TRXREG_TRY_ASSIGN(value, get_finite_real(encoded, "value"));
  out.value = value;
  TRXREG_TRY_ASSIGN(observed_at_wall_ns, detail::get_integer(encoded, "observed_at_wall_ns"));
  out.observed_at_wall_ns = observed_at_wall_ns;
  TRXREG_TRY_ASSIGN(observed_at_monotonic_ns, detail::get_unsigned(encoded, "observed_at_monotonic_ns"));
  out.observed_at_monotonic_ns = observed_at_monotonic_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  return out;
}

Value Codec<HealthSample>::encode(const HealthSample& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
      {"live", Value::boolean(value.live)},
      {"metric", Value::integer(static_cast<std::int64_t>(value.metric))},
      {"module", Value::integer(as_integer(value.module.value()))},
      {"observed_at_monotonic_ns", Value::integer(as_integer(value.observed_at_monotonic_ns))},
      {"observed_at_wall_ns", Value::integer(value.observed_at_wall_ns)},
      {"presence", Value::integer(static_cast<std::int64_t>(value.presence))},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
      {"value", Value::real(value.value)},
  });
}

Result<HealthSample> Codec<HealthSample>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health sample"));
  HealthSample out;
  TRXREG_TRY_ASSIGN(metric, get_enum_field(encoded, "metric", HealthMetric::Unsupported, "health metric"));
  out.metric = metric;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(presence, get_enum_field(encoded, "presence", SamplePresence::NotSupported, "sample presence"));
  out.presence = presence;
  TRXREG_TRY_ASSIGN(value, get_finite_real(encoded, "value"));
  out.value = value;
  TRXREG_TRY_ASSIGN(observed_at_wall_ns, detail::get_integer(encoded, "observed_at_wall_ns"));
  out.observed_at_wall_ns = observed_at_wall_ns;
  TRXREG_TRY_ASSIGN(observed_at_monotonic_ns, detail::get_unsigned(encoded, "observed_at_monotonic_ns"));
  out.observed_at_monotonic_ns = observed_at_monotonic_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(module, detail::get_unsigned(encoded, "module"));
  out.module = ModuleUid{module};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  return out;
}

Value Codec<HealthThreshold>::encode(const HealthThreshold& value) {
  return object({
      {"critical_enter", Value::real(value.critical_enter)},
      {"critical_exit", Value::real(value.critical_exit)},
      {"degraded_enter", Value::real(value.degraded_enter)},
      {"degraded_exit", Value::real(value.degraded_exit)},
      {"direction", Value::integer(static_cast<std::int64_t>(value.direction))},
      {"disagreement_tolerance", Value::real(value.disagreement_tolerance)},
      {"escalate_after", Value::integer(static_cast<std::int64_t>(value.escalate_after))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"has_critical", Value::boolean(value.has_critical)},
      {"has_degraded", Value::boolean(value.has_degraded)},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
      {"live", Value::boolean(value.live)},
      {"max_age_ns", Value::integer(value.max_age_ns)},
      {"metric", Value::integer(static_cast<std::int64_t>(value.metric))},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"recover_after", Value::integer(static_cast<std::int64_t>(value.recover_after))},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
  });
}

Result<HealthThreshold> Codec<HealthThreshold>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health threshold"));
  HealthThreshold out;
  TRXREG_TRY_ASSIGN(metric, get_enum_field(encoded, "metric", HealthMetric::Unsupported, "health metric"));
  out.metric = metric;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(direction, get_enum_field(encoded, "direction", ThresholdDirection::Below, "threshold direction"));
  out.direction = direction;
  TRXREG_TRY_ASSIGN(has_degraded, detail::get_boolean(encoded, "has_degraded"));
  out.has_degraded = has_degraded;
  TRXREG_TRY_ASSIGN(degraded_enter, get_finite_real(encoded, "degraded_enter"));
  out.degraded_enter = degraded_enter;
  TRXREG_TRY_ASSIGN(degraded_exit, get_finite_real(encoded, "degraded_exit"));
  out.degraded_exit = degraded_exit;
  TRXREG_TRY_ASSIGN(has_critical, detail::get_boolean(encoded, "has_critical"));
  out.has_critical = has_critical;
  TRXREG_TRY_ASSIGN(critical_enter, get_finite_real(encoded, "critical_enter"));
  out.critical_enter = critical_enter;
  TRXREG_TRY_ASSIGN(critical_exit, get_finite_real(encoded, "critical_exit"));
  out.critical_exit = critical_exit;
  TRXREG_TRY_ASSIGN(escalate_after, get_u32(encoded, "escalate_after"));
  out.escalate_after = escalate_after;
  TRXREG_TRY_ASSIGN(recover_after, get_u32(encoded, "recover_after"));
  out.recover_after = recover_after;
  TRXREG_TRY_ASSIGN(max_age_ns, detail::get_integer(encoded, "max_age_ns"));
  out.max_age_ns = max_age_ns;
  TRXREG_TRY_ASSIGN(disagreement_tolerance, get_finite_real(encoded, "disagreement_tolerance"));
  out.disagreement_tolerance = disagreement_tolerance;
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  return out;
}

Value Codec<HealthLatch>::encode(const HealthLatch& value) {
  return object({
      {"consecutive", Value::integer(static_cast<std::int64_t>(value.consecutive))},
      {"last_sample_sequence", Value::integer(as_integer(value.last_sample_sequence.value()))},
      {"last_sample_wall_ns", Value::integer(value.last_sample_wall_ns)},
      {"last_transition_generation", Value::integer(as_integer(value.last_transition_generation.value()))},
      {"last_transition_wall_ns", Value::integer(value.last_transition_wall_ns)},
      {"state", Value::integer(static_cast<std::int64_t>(value.state))},
  });
}

Result<HealthLatch> Codec<HealthLatch>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health latch"));
  HealthLatch out;
  TRXREG_TRY_ASSIGN(state, get_enum_field(encoded, "state", MetricState::Fenced, "metric state"));
  out.state = state;
  TRXREG_TRY_ASSIGN(consecutive, get_u32(encoded, "consecutive"));
  out.consecutive = consecutive;
  TRXREG_TRY_ASSIGN(last_sample_wall_ns, detail::get_integer(encoded, "last_sample_wall_ns"));
  out.last_sample_wall_ns = last_sample_wall_ns;
  TRXREG_TRY_ASSIGN(last_sample_sequence, detail::get_unsigned(encoded, "last_sample_sequence"));
  out.last_sample_sequence = Sequence{last_sample_sequence};
  TRXREG_TRY_ASSIGN(last_transition_generation, detail::get_unsigned(encoded, "last_transition_generation"));
  out.last_transition_generation = Generation{last_transition_generation};
  TRXREG_TRY_ASSIGN(last_transition_wall_ns, detail::get_integer(encoded, "last_transition_wall_ns"));
  out.last_transition_wall_ns = last_transition_wall_ns;
  return out;
}

Value Codec<MetricHealth>::encode(const MetricHealth& value) {
  return object({
      {"age_ns", Value::integer(value.age_ns)},
      {"fenced_count", Value::integer(value.fenced_count)},
      {"fresh_count", Value::integer(value.fresh_count)},
      {"has_age", Value::boolean(value.has_age)},
      {"has_value", Value::boolean(value.has_value)},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
      {"metric", Value::integer(static_cast<std::int64_t>(value.metric))},
      {"reason", Value::text(value.reason)},
      {"sample_count", Value::integer(value.sample_count)},
      {"source_count", Value::integer(static_cast<std::int64_t>(value.source_count))},
      {"stale_count", Value::integer(value.stale_count)},
      {"state", Value::integer(static_cast<std::int64_t>(value.state))},
      {"value", Value::real(value.value)},
  });
}

Result<MetricHealth> Codec<MetricHealth>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "metric health"));
  MetricHealth out;
  TRXREG_TRY_ASSIGN(metric, get_enum_field(encoded, "metric", HealthMetric::Unsupported, "health metric"));
  out.metric = metric;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(state, get_enum_field(encoded, "state", MetricState::Fenced, "metric state"));
  out.state = state;
  TRXREG_TRY_ASSIGN(has_value, detail::get_boolean(encoded, "has_value"));
  out.has_value = has_value;
  TRXREG_TRY_ASSIGN(value, get_finite_real(encoded, "value"));
  out.value = value;
  TRXREG_TRY_ASSIGN(has_age, detail::get_boolean(encoded, "has_age"));
  out.has_age = has_age;
  TRXREG_TRY_ASSIGN(age_ns, detail::get_integer(encoded, "age_ns"));
  out.age_ns = age_ns;
  TRXREG_TRY_ASSIGN(sample_count, detail::get_integer(encoded, "sample_count"));
  out.sample_count = sample_count;
  TRXREG_TRY_ASSIGN(fresh_count, detail::get_integer(encoded, "fresh_count"));
  out.fresh_count = fresh_count;
  TRXREG_TRY_ASSIGN(stale_count, detail::get_integer(encoded, "stale_count"));
  out.stale_count = stale_count;
  TRXREG_TRY_ASSIGN(fenced_count, detail::get_integer(encoded, "fenced_count"));
  out.fenced_count = fenced_count;
  TRXREG_TRY_ASSIGN(source_count, get_u32(encoded, "source_count"));
  out.source_count = source_count;
  TRXREG_TRY_ASSIGN(reason, detail::get_text(encoded, "reason"));
  out.reason = std::move(reason);
  return out;
}

Value Codec<HealthIssue>::encode(const HealthIssue& value) {
  return object({
      {"detail", Value::text(value.detail)},
      {"kind", Value::integer(static_cast<std::int64_t>(value.kind))},
      {"lane", Value::integer(static_cast<std::int64_t>(value.lane))},
      {"metric", Value::integer(static_cast<std::int64_t>(value.metric))},
  });
}

Result<HealthIssue> Codec<HealthIssue>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health issue"));
  HealthIssue out;
  TRXREG_TRY_ASSIGN(kind, get_enum_field(encoded, "kind", HealthIssueKind::SupersededThreshold, "health issue kind"));
  out.kind = kind;
  TRXREG_TRY_ASSIGN(metric, get_enum_field(encoded, "metric", HealthMetric::Unsupported, "health metric"));
  out.metric = metric;
  TRXREG_TRY_ASSIGN(lane, get_u16(encoded, "lane"));
  out.lane = lane;
  TRXREG_TRY_ASSIGN(detail_text, detail::get_text(encoded, "detail"));
  out.detail = std::move(detail_text);
  return out;
}

Value Codec<HealthReport>::encode(const HealthReport& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"digest", Value::text(value.digest.to_hex())},
      {"evaluated_at_wall_ns", Value::integer(value.evaluated_at_wall_ns)},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"issues", encode_record_array(value.issues)},
      {"metrics", encode_record_array(value.metrics)},
      {"outcome", Value::integer(static_cast<std::int64_t>(value.outcome))},
      {"uid", Value::integer(as_integer(value.uid.value()))},
      {"worst", Value::integer(static_cast<std::int64_t>(value.worst))},
  });
}

Result<HealthReport> Codec<HealthReport>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "health report"));
  HealthReport out;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(outcome, get_enum_field(encoded, "outcome", HealthOutcome::Fenced, "health outcome"));
  out.outcome = outcome;
  TRXREG_TRY_ASSIGN(worst, get_enum_field(encoded, "worst", MetricState::Fenced, "metric state"));
  out.worst = worst;
  TRXREG_TRY_ASSIGN(decoded_metrics, get_record_array<MetricHealth>(encoded, "metrics"));
  out.metrics = std::move(decoded_metrics);
  TRXREG_TRY_ASSIGN(decoded_issues, get_record_array<HealthIssue>(encoded, "issues"));
  out.issues = std::move(decoded_issues);
  TRXREG_TRY_ASSIGN(evaluated_at_wall_ns, detail::get_integer(encoded, "evaluated_at_wall_ns"));
  out.evaluated_at_wall_ns = evaluated_at_wall_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  return out;
}

// ---------------------------------------------------------------------------
// Evidence summary and attachment
// ---------------------------------------------------------------------------

Value Codec<EvidenceSummary>::encode(const EvidenceSummary& value) {
  return object({
      {"conflicting_attributes", Value::integer(static_cast<std::int64_t>(value.conflicting_attributes))},
      {"digest", Value::text(value.digest.to_hex())},
      {"fenced_samples", Value::integer(as_integer(value.fenced_samples))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"live_claims", Value::integer(as_integer(value.live_claims))},
      {"live_declarations", Value::integer(as_integer(value.live_declarations))},
      {"live_samples", Value::integer(as_integer(value.live_samples))},
      {"newest_sample_wall_ns", Value::integer(value.newest_sample_wall_ns)},
      {"oldest_sample_wall_ns", Value::integer(value.oldest_sample_wall_ns)},
      {"stale_samples", Value::integer(as_integer(value.stale_samples))},
      {"superseded_claims", Value::integer(as_integer(value.superseded_claims))},
      {"superseded_declarations", Value::integer(as_integer(value.superseded_declarations))},
      {"uid", Value::integer(as_integer(value.uid.value()))},
  });
}

Result<EvidenceSummary> Codec<EvidenceSummary>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "evidence summary"));
  EvidenceSummary out;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(live_claims, detail::get_unsigned(encoded, "live_claims"));
  out.live_claims = live_claims;
  TRXREG_TRY_ASSIGN(superseded_claims, detail::get_unsigned(encoded, "superseded_claims"));
  out.superseded_claims = superseded_claims;
  TRXREG_TRY_ASSIGN(live_declarations, detail::get_unsigned(encoded, "live_declarations"));
  out.live_declarations = live_declarations;
  TRXREG_TRY_ASSIGN(superseded_declarations, detail::get_unsigned(encoded, "superseded_declarations"));
  out.superseded_declarations = superseded_declarations;
  TRXREG_TRY_ASSIGN(live_samples, detail::get_unsigned(encoded, "live_samples"));
  out.live_samples = live_samples;
  TRXREG_TRY_ASSIGN(stale_samples, detail::get_unsigned(encoded, "stale_samples"));
  out.stale_samples = stale_samples;
  TRXREG_TRY_ASSIGN(fenced_samples, detail::get_unsigned(encoded, "fenced_samples"));
  out.fenced_samples = fenced_samples;
  TRXREG_TRY_ASSIGN(conflicting_attributes, get_u32(encoded, "conflicting_attributes"));
  out.conflicting_attributes = conflicting_attributes;
  TRXREG_TRY_ASSIGN(oldest_sample_wall_ns, detail::get_integer(encoded, "oldest_sample_wall_ns"));
  out.oldest_sample_wall_ns = oldest_sample_wall_ns;
  TRXREG_TRY_ASSIGN(newest_sample_wall_ns, detail::get_integer(encoded, "newest_sample_wall_ns"));
  out.newest_sample_wall_ns = newest_sample_wall_ns;
  TRXREG_TRY_ASSIGN(digest, get_digest_field(encoded, "digest"));
  out.digest = digest;
  return out;
}

Value Codec<AttachmentRecord>::encode(const AttachmentRecord& value) {
  return object({
      {"attached_at_wall_ns", Value::integer(value.attached_at_wall_ns)},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"live", Value::boolean(value.live)},
      {"note", Value::text(value.note)},
      {"port_index", Value::integer(static_cast<std::int64_t>(value.port_index))},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"slot", Value::text(value.slot.str())},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
      {"uid", Value::integer(as_integer(value.uid.value()))},
  });
}

Result<AttachmentRecord> Codec<AttachmentRecord>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "attachment record"));
  AttachmentRecord out;
  TRXREG_TRY_ASSIGN(parsed_slot, get_key<SlotKey>(encoded, "slot", "attachment slot"));
  out.slot = parsed_slot;
  TRXREG_TRY_ASSIGN(port_index, get_u32(encoded, "port_index"));
  out.port_index = port_index;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(attached_at_wall_ns, detail::get_integer(encoded, "attached_at_wall_ns"));
  out.attached_at_wall_ns = attached_at_wall_ns;
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  TRXREG_TRY_ASSIGN(note, detail::get_text(encoded, "note"));
  out.note = std::move(note);
  return out;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Value Codec<LifecycleEvent>::encode(const LifecycleEvent& value) {
  return object({
      {"from", Value::integer(static_cast<std::int64_t>(value.from))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"reason", Value::text(value.reason)},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
      {"to", Value::integer(static_cast<std::int64_t>(value.to))},
      {"wall_ns", Value::integer(value.wall_ns)},
  });
}

Result<LifecycleEvent> Codec<LifecycleEvent>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "lifecycle event"));
  LifecycleEvent out;
  TRXREG_TRY_ASSIGN(from, get_enum_field(encoded, "from", LifecycleState::Replaced, "lifecycle state"));
  out.from = from;
  TRXREG_TRY_ASSIGN(to, get_enum_field(encoded, "to", LifecycleState::Replaced, "lifecycle state"));
  out.to = to;
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(reason, detail::get_text(encoded, "reason"));
  out.reason = std::move(reason);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(wall_ns, detail::get_integer(encoded, "wall_ns"));
  out.wall_ns = wall_ns;
  return out;
}

// ---------------------------------------------------------------------------
// Compatibility
// ---------------------------------------------------------------------------

Value Codec<Requirement>::encode(const Requirement& value) {
  return object({
      {"key", Value::integer(static_cast<std::int64_t>(value.key))},
      {"note", Value::text(value.note)},
      {"op", Value::integer(static_cast<std::int64_t>(value.op))},
      {"operand", Codec<CapabilityValue>::encode(value.operand)},
      {"subject", Value::integer(static_cast<std::int64_t>(value.subject))},
      {"subkey", Value::text(value.subkey)},
  });
}

Result<Requirement> Codec<Requirement>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "requirement"));
  Requirement out;
  TRXREG_TRY_ASSIGN(subject, get_enum_field(encoded, "subject", RequirementSubject::Port, "requirement subject"));
  out.subject = subject;
  TRXREG_TRY_ASSIGN(key, get_enum_field(encoded, "key", CapabilityKey::Unsupported, "capability key"));
  out.key = key;
  TRXREG_TRY_ASSIGN(subkey, detail::get_text(encoded, "subkey"));
  out.subkey = std::move(subkey);
  TRXREG_TRY_ASSIGN(op, get_enum_field(encoded, "op", RequirementOp::AtLeast, "requirement operator"));
  out.op = op;
  TRXREG_TRY_ASSIGN(decoded_operand, get_record<CapabilityValue>(encoded, "operand"));
  out.operand = std::move(decoded_operand);
  TRXREG_TRY_ASSIGN(note, detail::get_text(encoded, "note"));
  out.note = std::move(note);
  return out;
}

Value Codec<RequirementEvaluation>::encode(const RequirementEvaluation& value) {
  return object({
      {"consensus", Value::integer(static_cast<std::int64_t>(value.consensus))},
      {"detail", Value::text(value.detail)},
      {"has_observed", Value::boolean(value.has_observed)},
      {"observed", Codec<CapabilityValue>::encode(value.observed)},
      {"requirement", Codec<Requirement>::encode(value.requirement)},
      {"state", Value::integer(static_cast<std::int64_t>(value.state))},
  });
}

Result<RequirementEvaluation> Codec<RequirementEvaluation>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "requirement evaluation"));
  RequirementEvaluation out;
  TRXREG_TRY_ASSIGN(decoded_requirement, get_record<Requirement>(encoded, "requirement"));
  out.requirement = std::move(decoded_requirement);
  TRXREG_TRY_ASSIGN(state, get_enum_field(encoded, "state", RequirementState::Indeterminate, "requirement state"));
  out.state = state;
  TRXREG_TRY_ASSIGN(consensus, get_enum_field(encoded, "consensus", ConsensusOutcome::Superseded, "consensus outcome"));
  out.consensus = consensus;
  TRXREG_TRY_ASSIGN(has_observed, detail::get_boolean(encoded, "has_observed"));
  out.has_observed = has_observed;
  TRXREG_TRY_ASSIGN(decoded_observed, get_record<CapabilityValue>(encoded, "observed"));
  out.observed = std::move(decoded_observed);
  TRXREG_TRY_ASSIGN(detail_text, detail::get_text(encoded, "detail"));
  out.detail = std::move(detail_text);
  return out;
}

Value Codec<MatchedRule>::encode(const MatchedRule& value) {
  return object({
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"id", Value::integer(static_cast<std::int64_t>(value.id.value()))},
      {"name", Value::text(value.name)},
      {"priority", Value::integer(static_cast<std::int64_t>(value.priority))},
      {"rationale", Value::text(value.rationale)},
      {"requirements", encode_record_array(value.requirements)},
      {"verdict", Value::integer(static_cast<std::int64_t>(value.verdict))},
  });
}

Result<MatchedRule> Codec<MatchedRule>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "matched rule"));
  MatchedRule out;
  TRXREG_TRY_ASSIGN(id, get_u32(encoded, "id"));
  out.id = RuleId{id};
  TRXREG_TRY_ASSIGN(name, detail::get_text(encoded, "name"));
  out.name = std::move(name);
  TRXREG_TRY_ASSIGN(verdict, get_enum_field(encoded, "verdict", CompatVerdict::Unsupported, "compat verdict"));
  out.verdict = verdict;
  TRXREG_TRY_ASSIGN(priority, get_i32(encoded, "priority"));
  out.priority = priority;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(rationale, detail::get_text(encoded, "rationale"));
  out.rationale = std::move(rationale);
  TRXREG_TRY_ASSIGN(decoded_requirements, get_record_array<RequirementEvaluation>(encoded, "requirements"));
  out.requirements = std::move(decoded_requirements);
  return out;
}

Value Codec<CompatRule>::encode(const CompatRule& value) {
  return object({
      {"enabled", Value::boolean(value.enabled)},
      {"name", Value::text(value.name)},
      {"priority", Value::integer(static_cast<std::int64_t>(value.priority))},
      {"provenance", Codec<Provenance>::encode(value.provenance)},
      {"rationale", Value::text(value.rationale)},
      {"requirements", encode_record_array(value.requirements)},
      {"verdict", Value::integer(static_cast<std::int64_t>(value.verdict))},
  });
}

Result<CompatRule> Codec<CompatRule>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "compat rule"));
  CompatRule out;
  TRXREG_TRY_ASSIGN(name, detail::get_text(encoded, "name"));
  out.name = std::move(name);
  TRXREG_TRY_ASSIGN(decoded_requirements, get_record_array<Requirement>(encoded, "requirements"));
  out.requirements = std::move(decoded_requirements);
  TRXREG_TRY_ASSIGN(verdict, get_enum_field(encoded, "verdict", CompatVerdict::Unsupported, "compat verdict"));
  out.verdict = verdict;
  TRXREG_TRY_ASSIGN(priority, get_i32(encoded, "priority"));
  out.priority = priority;
  TRXREG_TRY_ASSIGN(rationale, detail::get_text(encoded, "rationale"));
  out.rationale = std::move(rationale);
  TRXREG_TRY_ASSIGN(decoded_provenance, get_record<Provenance>(encoded, "provenance"));
  out.provenance = std::move(decoded_provenance);
  TRXREG_TRY_ASSIGN(enabled, detail::get_boolean(encoded, "enabled"));
  out.enabled = enabled;
  return out;
}

Value Codec<CompatRuleRecord>::encode(const CompatRuleRecord& value) {
  return object({
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"id", Value::integer(static_cast<std::int64_t>(value.id.value()))},
      {"live", Value::boolean(value.live)},
      {"rule", Codec<CompatRule>::encode(value.rule)},
      {"sequence", Value::integer(as_integer(value.sequence.value()))},
      {"source", Value::integer(static_cast<std::int64_t>(value.source.value()))},
      {"source_epoch", Value::integer(static_cast<std::int64_t>(value.source_epoch.value()))},
  });
}

Result<CompatRuleRecord> Codec<CompatRuleRecord>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "compat rule record"));
  CompatRuleRecord out;
  TRXREG_TRY_ASSIGN(id, get_u32(encoded, "id"));
  out.id = RuleId{id};
  TRXREG_TRY_ASSIGN(decoded_rule, get_record<CompatRule>(encoded, "rule"));
  out.rule = std::move(decoded_rule);
  TRXREG_TRY_ASSIGN(source, get_u32(encoded, "source"));
  out.source = SourceId{source};
  TRXREG_TRY_ASSIGN(source_epoch, get_u32(encoded, "source_epoch"));
  out.source_epoch = SourceEpoch{source_epoch};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(sequence, detail::get_unsigned(encoded, "sequence"));
  out.sequence = Sequence{sequence};
  TRXREG_TRY_ASSIGN(live, detail::get_boolean(encoded, "live"));
  out.live = live;
  return out;
}

Value Codec<CompatDecision>::encode(const CompatDecision& value) {
  return object({
      {"clock_domain", Value::unsigned_integer(value.clock_domain.value())},
      {"closure", Value::integer(static_cast<std::int64_t>(value.closure))},
      {"considered_rules", Value::integer(static_cast<std::int64_t>(value.considered_rules))},
      {"decision_digest", Value::text(value.decision_digest.to_hex())},
      {"evaluated_at_wall_ns", Value::integer(value.evaluated_at_wall_ns)},
      {"explanation", Value::text(value.explanation)},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnation", Value::integer(static_cast<std::int64_t>(value.incarnation.value()))},
      {"indeterminate_rules", Value::integer(static_cast<std::int64_t>(value.indeterminate_rules))},
      {"inputs_digest", Value::text(value.inputs_digest.to_hex())},
      {"matched_rules", encode_record_array(value.matched_rules)},
      {"outcome", Value::integer(static_cast<std::int64_t>(value.outcome))},
      {"port", Value::text(value.port.str())},
      {"uid", Value::integer(as_integer(value.uid.value()))},
      {"unmet_requirements", encode_record_array(value.unmet_requirements)},
      {"violated_requirements", encode_record_array(value.violated_requirements)},
  });
}

Result<CompatDecision> Codec<CompatDecision>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "compat decision"));
  CompatDecision out;
  TRXREG_TRY_ASSIGN(outcome, get_enum_field(encoded, "outcome", CompatOutcome::Unsupported, "compat outcome"));
  out.outcome = outcome;
  TRXREG_TRY_ASSIGN(closure, get_enum_field(encoded, "closure", KnowledgeClosure::Closed, "knowledge closure"));
  out.closure = closure;
  TRXREG_TRY_ASSIGN(parsed_port, get_key<PortKey>(encoded, "port", "compat decision port"));
  out.port = parsed_port;
  TRXREG_TRY_ASSIGN(uid, detail::get_unsigned(encoded, "uid"));
  out.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_u32(encoded, "incarnation"));
  out.incarnation = IncarnationId{incarnation};
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(considered_rules, get_u32(encoded, "considered_rules"));
  out.considered_rules = considered_rules;
  TRXREG_TRY_ASSIGN(indeterminate_rules, get_u32(encoded, "indeterminate_rules"));
  out.indeterminate_rules = indeterminate_rules;
  TRXREG_TRY_ASSIGN(decoded_matched_rules, get_record_array<MatchedRule>(encoded, "matched_rules"));
  out.matched_rules = std::move(decoded_matched_rules);
  TRXREG_TRY_ASSIGN(decoded_unmet_requirements, get_record_array<RequirementEvaluation>(encoded, "unmet_requirements"));
  out.unmet_requirements = std::move(decoded_unmet_requirements);
  TRXREG_TRY_ASSIGN(decoded_violated_requirements, get_record_array<RequirementEvaluation>(encoded, "violated_requirements"));
  out.violated_requirements = std::move(decoded_violated_requirements);
  TRXREG_TRY_ASSIGN(inputs_digest, get_digest_field(encoded, "inputs_digest"));
  out.inputs_digest = inputs_digest;
  TRXREG_TRY_ASSIGN(decision_digest, get_digest_field(encoded, "decision_digest"));
  out.decision_digest = decision_digest;
  TRXREG_TRY_ASSIGN(evaluated_at_wall_ns, detail::get_integer(encoded, "evaluated_at_wall_ns"));
  out.evaluated_at_wall_ns = evaluated_at_wall_ns;
  TRXREG_TRY_ASSIGN(clock_domain, detail::get_unsigned_field(encoded, "clock_domain"));
  out.clock_domain = ClockDomainId{clock_domain};
  TRXREG_TRY_ASSIGN(explanation, detail::get_text(encoded, "explanation"));
  out.explanation = std::move(explanation);
  return out;
}

// ---------------------------------------------------------------------------
// Aggregate reports
// ---------------------------------------------------------------------------

Value Codec<RegistryStats>::encode(const RegistryStats& value) {
  return object({
      {"attachments", Value::integer(as_integer(value.attachments))},
      {"claims", Value::integer(as_integer(value.claims))},
      {"conflicts_observed", Value::integer(as_integer(value.conflicts_observed))},
      {"declarations", Value::integer(as_integer(value.declarations))},
      {"fenced_incarnations", Value::integer(as_integer(value.fenced_incarnations))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnations", Value::integer(as_integer(value.incarnations))},
      {"live_attachments", Value::integer(as_integer(value.live_attachments))},
      {"modules", Value::integer(as_integer(value.modules))},
      {"mutations", Value::integer(as_integer(value.mutations))},
      {"ports", Value::integer(as_integer(value.ports))},
      {"queries", Value::integer(as_integer(value.queries))},
      {"refusals", Value::integer(as_integer(value.refusals))},
      {"registry_incarnation", Value::integer(static_cast<std::int64_t>(value.registry_incarnation))},
      {"rules", Value::integer(as_integer(value.rules))},
      {"samples", Value::integer(as_integer(value.samples))},
      {"sources", Value::integer(as_integer(value.sources))},
      {"state_digest", Value::text(value.state_digest.to_hex())},
      {"thresholds", Value::integer(as_integer(value.thresholds))},
  });
}

Result<RegistryStats> Codec<RegistryStats>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "registry stats"));
  RegistryStats out;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(registry_incarnation, get_u32(encoded, "registry_incarnation"));
  out.registry_incarnation = registry_incarnation;
  TRXREG_TRY_ASSIGN(sources, detail::get_unsigned(encoded, "sources"));
  out.sources = sources;
  TRXREG_TRY_ASSIGN(modules, detail::get_unsigned(encoded, "modules"));
  out.modules = modules;
  TRXREG_TRY_ASSIGN(incarnations, detail::get_unsigned(encoded, "incarnations"));
  out.incarnations = incarnations;
  TRXREG_TRY_ASSIGN(fenced_incarnations, detail::get_unsigned(encoded, "fenced_incarnations"));
  out.fenced_incarnations = fenced_incarnations;
  TRXREG_TRY_ASSIGN(ports, detail::get_unsigned(encoded, "ports"));
  out.ports = ports;
  TRXREG_TRY_ASSIGN(rules, detail::get_unsigned(encoded, "rules"));
  out.rules = rules;
  TRXREG_TRY_ASSIGN(thresholds, detail::get_unsigned(encoded, "thresholds"));
  out.thresholds = thresholds;
  TRXREG_TRY_ASSIGN(attachments, detail::get_unsigned(encoded, "attachments"));
  out.attachments = attachments;
  TRXREG_TRY_ASSIGN(live_attachments, detail::get_unsigned(encoded, "live_attachments"));
  out.live_attachments = live_attachments;
  TRXREG_TRY_ASSIGN(claims, detail::get_unsigned(encoded, "claims"));
  out.claims = claims;
  TRXREG_TRY_ASSIGN(declarations, detail::get_unsigned(encoded, "declarations"));
  out.declarations = declarations;
  TRXREG_TRY_ASSIGN(samples, detail::get_unsigned(encoded, "samples"));
  out.samples = samples;
  TRXREG_TRY_ASSIGN(mutations, detail::get_unsigned(encoded, "mutations"));
  out.mutations = mutations;
  TRXREG_TRY_ASSIGN(refusals, detail::get_unsigned(encoded, "refusals"));
  out.refusals = refusals;
  TRXREG_TRY_ASSIGN(queries, detail::get_unsigned(encoded, "queries"));
  out.queries = queries;
  TRXREG_TRY_ASSIGN(conflicts_observed, detail::get_unsigned(encoded, "conflicts_observed"));
  out.conflicts_observed = conflicts_observed;
  TRXREG_TRY_ASSIGN(state_digest, get_digest_field(encoded, "state_digest"));
  out.state_digest = state_digest;
  return out;
}

Value Codec<LoadReport>::encode(const LoadReport& value) {
  return object({
      {"claims", Value::integer(as_integer(value.claims))},
      {"content_digest", Value::text(value.content_digest.to_hex())},
      {"declarations", Value::integer(as_integer(value.declarations))},
      {"dropped_tail_bytes", Value::integer(as_integer(value.dropped_tail_bytes))},
      {"evidence_invalidated_on_load", Value::integer(as_integer(value.evidence_invalidated_on_load))},
      {"fenced_incarnations", Value::integer(as_integer(value.fenced_incarnations))},
      {"format_version", Value::integer(static_cast<std::int64_t>(value.format_version))},
      {"generation", Value::integer(as_integer(value.generation.value()))},
      {"incarnations", Value::integer(as_integer(value.incarnations))},
      {"loaded_at_wall_ns", Value::integer(value.loaded_at_wall_ns)},
      {"modules", Value::integer(as_integer(value.modules))},
      {"ports", Value::integer(as_integer(value.ports))},
      {"recovery_note", Value::text(value.recovery_note)},
      {"registry_incarnation", Value::integer(static_cast<std::int64_t>(value.registry_incarnation))},
      {"rules", Value::integer(as_integer(value.rules))},
      {"samples", Value::integer(as_integer(value.samples))},
      {"sources", Value::integer(as_integer(value.sources))},
      {"tail_recovered", Value::boolean(value.tail_recovered)},
      {"thresholds", Value::integer(as_integer(value.thresholds))},
  });
}

Result<LoadReport> Codec<LoadReport>::decode(const Value& encoded) {
  TRXREG_TRY(as_object(encoded, "load report"));
  LoadReport out;
  TRXREG_TRY_ASSIGN(format_version, get_u16(encoded, "format_version"));
  out.format_version = format_version;
  TRXREG_TRY_ASSIGN(generation, detail::get_unsigned(encoded, "generation"));
  out.generation = Generation{generation};
  TRXREG_TRY_ASSIGN(registry_incarnation, get_u32(encoded, "registry_incarnation"));
  out.registry_incarnation = registry_incarnation;
  TRXREG_TRY_ASSIGN(modules, detail::get_unsigned(encoded, "modules"));
  out.modules = modules;
  TRXREG_TRY_ASSIGN(incarnations, detail::get_unsigned(encoded, "incarnations"));
  out.incarnations = incarnations;
  TRXREG_TRY_ASSIGN(sources, detail::get_unsigned(encoded, "sources"));
  out.sources = sources;
  TRXREG_TRY_ASSIGN(ports, detail::get_unsigned(encoded, "ports"));
  out.ports = ports;
  TRXREG_TRY_ASSIGN(rules, detail::get_unsigned(encoded, "rules"));
  out.rules = rules;
  TRXREG_TRY_ASSIGN(thresholds, detail::get_unsigned(encoded, "thresholds"));
  out.thresholds = thresholds;
  TRXREG_TRY_ASSIGN(claims, detail::get_unsigned(encoded, "claims"));
  out.claims = claims;
  TRXREG_TRY_ASSIGN(declarations, detail::get_unsigned(encoded, "declarations"));
  out.declarations = declarations;
  TRXREG_TRY_ASSIGN(samples, detail::get_unsigned(encoded, "samples"));
  out.samples = samples;
  TRXREG_TRY_ASSIGN(fenced_incarnations, detail::get_unsigned(encoded, "fenced_incarnations"));
  out.fenced_incarnations = fenced_incarnations;
  TRXREG_TRY_ASSIGN(evidence_invalidated_on_load, detail::get_unsigned(encoded, "evidence_invalidated_on_load"));
  out.evidence_invalidated_on_load = evidence_invalidated_on_load;
  TRXREG_TRY_ASSIGN(tail_recovered, detail::get_boolean(encoded, "tail_recovered"));
  out.tail_recovered = tail_recovered;
  TRXREG_TRY_ASSIGN(dropped_tail_bytes, detail::get_unsigned(encoded, "dropped_tail_bytes"));
  out.dropped_tail_bytes = dropped_tail_bytes;
  TRXREG_TRY_ASSIGN(recovery_note, detail::get_text(encoded, "recovery_note"));
  out.recovery_note = std::move(recovery_note);
  TRXREG_TRY_ASSIGN(content_digest, get_digest_field(encoded, "content_digest"));
  out.content_digest = content_digest;
  TRXREG_TRY_ASSIGN(loaded_at_wall_ns, detail::get_integer(encoded, "loaded_at_wall_ns"));
  out.loaded_at_wall_ns = loaded_at_wall_ns;
  return out;
}

}  // namespace trxreg::codec
