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

// Strict, typed accessors over decoded canonical documents. Every accessor
// validates presence and type, so a malformed document is rejected at the field
// boundary rather than being coerced into a plausible-looking record.

#include <cstdint>
#include <string>
#include <string_view>

#include "trxreg/canonical.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/result.hpp"

namespace trxreg::detail {

inline Result<const Value*> as_object(const Value& value, std::string_view what) {
  if (!value.is_object()) {
    return make_error(StatusCode::Malformed, std::string(what) + " must be a canonical object");
  }
  return &value;
}

inline Result<const Value*> require_field(const Value& object, std::string_view key) {
  if (!object.is_object()) {
    return make_error(StatusCode::Malformed, "record must be a canonical object");
  }
  const Value* field = object.find(key);
  if (field == nullptr) {
    return make_error(StatusCode::Malformed, "missing required field " + std::string(key));
  }
  return field;
}

inline Result<std::int64_t> get_integer(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  if (!field->is_integer()) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be an integer");
  }
  return field->as_integer();
}

inline Result<std::uint64_t> get_unsigned(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(value, get_integer(object, key));
  if (value < 0) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must not be negative");
  }
  return static_cast<std::uint64_t>(value);
}

/// Read an unsigned 64-bit field. Accepts both the Unsigned kind and a
/// non-negative Integer so that documents written before the distinction was
/// introduced keep decoding.
inline Result<std::uint64_t> get_unsigned_field(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  if (field->is_unsigned()) {
    return field->as_unsigned();
  }
  if (field->is_integer()) {
    if (field->as_integer() < 0) {
      return make_error(StatusCode::Malformed, "field " + std::string(key) + " must not be negative");
    }
    return static_cast<std::uint64_t>(field->as_integer());
  }
  return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be an unsigned integer");
}

inline Result<bool> get_boolean(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  if (!field->is_boolean()) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be a boolean");
  }
  return field->as_boolean();
}

inline Result<double> get_real(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  double out = 0.0;
  if (!field->number_as_double(out)) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be numeric");
  }
  return out;
}

inline Result<std::string> get_text(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  if (!field->is_text()) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be text");
  }
  return field->as_text();
}

inline Result<Digest> get_digest(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(text, get_text(object, key));
  return Digest::from_hex(text);
}

inline Result<const Value::Array*> get_array(const Value& object, std::string_view key) {
  TRXREG_TRY_ASSIGN(field, require_field(object, key));
  if (!field->is_array()) {
    return make_error(StatusCode::Malformed, "field " + std::string(key) + " must be an array");
  }
  return &field->as_array();
}

// -- optional variants -------------------------------------------------------

inline std::int64_t get_integer_or(const Value& object, std::string_view key, std::int64_t fallback) {
  const Result<std::int64_t> value = get_integer(object, key);
  return value.ok() ? value.value() : fallback;
}

inline std::uint64_t get_unsigned_or(const Value& object, std::string_view key, std::uint64_t fallback) {
  const Result<std::uint64_t> value = get_unsigned(object, key);
  return value.ok() ? value.value() : fallback;
}

inline bool get_boolean_or(const Value& object, std::string_view key, bool fallback) {
  const Result<bool> value = get_boolean(object, key);
  return value.ok() ? value.value() : fallback;
}

inline double get_real_or(const Value& object, std::string_view key, double fallback) {
  const Result<double> value = get_real(object, key);
  return value.ok() ? value.value() : fallback;
}

inline std::string get_text_or(const Value& object, std::string_view key, std::string_view fallback) {
  const Result<std::string> value = get_text(object, key);
  return value.ok() ? value.value() : std::string(fallback);
}

inline Digest get_digest_or(const Value& object, std::string_view key) {
  const Result<Digest> value = get_digest(object, key);
  return value.ok() ? value.value() : Digest{};
}

inline const Value::Array* get_array_or(const Value& object, std::string_view key) {
  const Result<const Value::Array*> value = get_array(object, key);
  return value.ok() ? value.value() : nullptr;
}

/// Enum domains are validated on decode: an out-of-range integer is Malformed.
template <class Enum>
Result<Enum> get_enum(const Value& object, std::string_view key, std::uint8_t max_value, std::string_view what) {
  TRXREG_TRY_ASSIGN(raw, get_integer(object, key));
  if (raw < 0 || raw > static_cast<std::int64_t>(max_value)) {
    return make_error(StatusCode::Malformed, std::string(what) + " is not a known value");
  }
  return static_cast<Enum>(raw);
}

}  // namespace trxreg::detail
