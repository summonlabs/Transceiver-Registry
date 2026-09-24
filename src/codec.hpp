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

// Internal canonical codecs shared by the snapshot writer and the loopback
// transport.
//
// Every record maps to a canonical object Value. Building a Value (rather than
// streaming) means object members are always emitted in canonical key order:
// the encoder cannot produce a non-canonical document by accident. Decoding
// validates presence, type, range, and enum domain before any value is used, so
// a malformed document cannot reach registry state.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/capability.hpp"
#include "trxreg/compatibility.hpp"
#include "trxreg/health.hpp"
#include "trxreg/identity.hpp"
#include "trxreg/lifecycle.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/snapshot.hpp"

namespace trxreg::codec {

/// Reusable field helpers for encoders and decoders.
Value object(std::vector<Value::Member> members);
Value text_array(const std::vector<std::string>& values);

Result<const Value::Object*> as_object(const Value& value, std::string_view what);

Result<std::int64_t> get_integer(const Value& object, std::string_view key);
Result<std::uint64_t> get_unsigned(const Value& object, std::string_view key);
Result<bool> get_boolean(const Value& object, std::string_view key);
Result<double> get_real(const Value& object, std::string_view key);
Result<std::string> get_text(const Value& object, std::string_view key);
Result<Digest> get_digest(const Value& object, std::string_view key);
Result<const Value::Array*> get_array(const Value& object, std::string_view key);

std::int64_t get_integer_or(const Value& object, std::string_view key, std::int64_t fallback);
std::uint64_t get_unsigned_or(const Value& object, std::string_view key, std::uint64_t fallback);
bool get_boolean_or(const Value& object, std::string_view key, bool fallback);
double get_real_or(const Value& object, std::string_view key, double fallback);
std::string get_text_or(const Value& object, std::string_view key, std::string_view fallback);
Digest get_digest_or(const Value& object, std::string_view key);
const Value::Array* get_array_or(const Value& object, std::string_view key);

/// Enum domain checks: an out-of-range integer is Malformed, never silently
/// truncated to a valid enumerator.
template <class Enum>
Result<Enum> get_enum(const Value& object, std::string_view key, std::uint8_t max_value, std::string_view what);

/// Codec of one record type.
template <class T>
struct Codec {
  static Value encode(const T& value);
  static Result<T> decode(const Value& encoded);
};

/// Encode a record into a canonical document value.
template <class T>
Value encode(const T& value) {
  return Codec<T>::encode(value);
}

/// Decode a canonical document value into a record.
template <class T>
Result<T> decode(const Value& encoded) {
  return Codec<T>::decode(encoded);
}

#define TRXREG_DECLARE_CODEC(type)                        \
  template <>                                             \
  struct Codec<type> {                                    \
    static Value encode(const type& value);               \
    static Result<type> decode(const Value& encoded);     \
  }

TRXREG_DECLARE_CODEC(Provenance);
TRXREG_DECLARE_CODEC(SourceDescriptor);
TRXREG_DECLARE_CODEC(SourceHandle);
TRXREG_DECLARE_CODEC(ModuleHandle);
TRXREG_DECLARE_CODEC(AuthorityToken);
TRXREG_DECLARE_CODEC(IdentityFieldValue);
TRXREG_DECLARE_CODEC(IdentityClaim);
TRXREG_DECLARE_CODEC(FieldConsensus);
TRXREG_DECLARE_CODEC(IdentityView);
TRXREG_DECLARE_CODEC(ModuleRegistration);
TRXREG_DECLARE_CODEC(SpectrumDescriptor);
TRXREG_DECLARE_CODEC(CapabilityValue);
TRXREG_DECLARE_CODEC(CapabilityDeclaration);
TRXREG_DECLARE_CODEC(CapabilityConsensus);
TRXREG_DECLARE_CODEC(CapabilityView);
TRXREG_DECLARE_CODEC(HealthSampleInput);
TRXREG_DECLARE_CODEC(HealthSample);
TRXREG_DECLARE_CODEC(HealthThreshold);
TRXREG_DECLARE_CODEC(HealthLatch);
TRXREG_DECLARE_CODEC(MetricHealth);
TRXREG_DECLARE_CODEC(HealthIssue);
TRXREG_DECLARE_CODEC(HealthReport);
TRXREG_DECLARE_CODEC(EvidenceSummary);
TRXREG_DECLARE_CODEC(AttachmentRecord);
TRXREG_DECLARE_CODEC(LifecycleEvent);
TRXREG_DECLARE_CODEC(Requirement);
TRXREG_DECLARE_CODEC(RequirementEvaluation);
TRXREG_DECLARE_CODEC(MatchedRule);
TRXREG_DECLARE_CODEC(CompatRule);
TRXREG_DECLARE_CODEC(CompatRuleRecord);
TRXREG_DECLARE_CODEC(CompatDecision);
TRXREG_DECLARE_CODEC(RegistryStats);
TRXREG_DECLARE_CODEC(LoadReport);

#undef TRXREG_DECLARE_CODEC

}  // namespace trxreg::codec
