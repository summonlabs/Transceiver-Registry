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

#include "trxreg/snapshot.hpp"

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
// fopen/fread are the portable file primitives used here; the MSVC deprecation
// warning is about a C11 Annex K alternative this code deliberately avoids.
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "codec.hpp"
#include "domain.hpp"
#include "registry_internal.hpp"
#include "trxreg/version.hpp"
#include "value_fields.hpp"

namespace trxreg {
namespace {

using detail::as_object;
using detail::get_array;
using detail::get_boolean;
using detail::get_boolean_or;
using detail::get_enum;
using detail::get_integer;
using detail::get_integer_or;
using detail::get_text;
using detail::get_text_or;
using detail::get_unsigned;
using detail::get_unsigned_or;

constexpr std::uint8_t kRecordHeader = 1;
constexpr std::uint8_t kRecordSource = 2;
constexpr std::uint8_t kRecordModule = 3;
constexpr std::uint8_t kRecordPort = 4;
constexpr std::uint8_t kRecordAttachment = 5;
constexpr std::uint8_t kRecordThreshold = 6;
constexpr std::uint8_t kRecordRule = 7;

constexpr std::uint64_t kMaxRecordBytes = 16ull << 20;
constexpr std::uint64_t kMaxSnapshotBytes = 256ull << 20;
constexpr char kRecordTrailerMagic[8] = {'T', 'R', 'X', 'R', 'E', 'O', 'F', '1'};

struct Record {
  std::uint8_t kind{kRecordHeader};
  std::vector<std::byte> payload;
};

std::vector<std::byte> encode_document(const Value& document) {
  CanonicalWriter writer;
  writer.write_value(document);
  if (writer.failed()) {
    return {};
  }
  return std::move(writer).take();
}

void append_magic(std::vector<std::byte>& out, const char* magic, std::size_t size) {
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(magic[i])));
  }
}

Result<Value> decode_document(const std::vector<std::byte>& payload, const CanonicalLimits& limits) {
  CanonicalReader reader(payload, limits);
  return reader.read_document();
}

void append_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value & 0xffu));
  out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
}

std::uint16_t read_u16(const std::vector<std::byte>& data, std::size_t offset) {
  return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset]) |
                                    (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset + 1])) << 8u));
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::byte>((value >> (8u * i)) & 0xffu));
  }
}

void append_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::byte>((value >> (8u * i)) & 0xffu));
  }
}

std::uint32_t read_u32(const std::vector<std::byte>& data, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + i])) << (8u * i);
  }
  return value;
}

std::uint64_t read_u64(const std::vector<std::byte>& data, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data[offset + i])) << (8u * i);
  }
  return value;
}

/// Frame one record: length | kind | payload | crc-32c(kind|payload).
void append_record(std::vector<std::byte>& out, const Record& record) {
  const std::uint32_t body_length = static_cast<std::uint32_t>(record.payload.size() + 1);
  append_u32(out, body_length);
  std::vector<std::byte> body;
  body.reserve(body_length);
  body.push_back(static_cast<std::byte>(record.kind));
  body.insert(body.end(), record.payload.begin(), record.payload.end());
  out.insert(out.end(), body.begin(), body.end());
  append_u32(out, crc32c(body));
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

Value encode_latch_record(const HealthLatchRecord& record) {
  return codec::object({{"latch", codec::encode(record.latch)},
                        {"lane", Value::integer(record.lane)},
                        {"metric", Value::integer(static_cast<std::int64_t>(record.metric))}});
}

Result<HealthLatchRecord> decode_latch_record(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "health latch record"));
  TRXREG_TRY_ASSIGN(metric, get_enum<HealthMetric>(*object, "metric", static_cast<std::uint8_t>(HealthMetric::Unsupported), "health metric"));
  TRXREG_TRY_ASSIGN(lane, get_unsigned(*object, "lane"));
  if (lane > 65535) {
    return make_error(StatusCode::Malformed, "health latch lane is out of range");
  }
  const Value* latch_encoded = object->find("latch");
  if (latch_encoded == nullptr) {
    return make_error(StatusCode::Malformed, "health latch record is missing its latch");
  }
  HealthLatchRecord record;
  record.metric = metric;
  record.lane = static_cast<std::uint16_t>(lane);
  TRXREG_TRY_ASSIGN(latch, codec::decode<HealthLatch>(*latch_encoded));
  record.latch = latch;
  return record;
}

Value encode_source(const SourceRecord& source) {
  return codec::object({{"descriptor", codec::encode(source.descriptor)},
                        {"epoch", Value::integer(static_cast<std::int64_t>(source.epoch.value()))},
                        {"generation", Value::integer(static_cast<std::int64_t>(source.generation.value()))},
                        {"id", Value::integer(static_cast<std::int64_t>(source.id.value()))},
                        {"name", Value::text(source.name)},
                        {"registered_wall_ns", Value::integer(source.registered_wall_ns)},
                        {"sequence", Value::integer(static_cast<std::int64_t>(source.sequence.value()))}});
}

Result<SourceRecord> decode_source(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "source record"));
  SourceRecord source;
  TRXREG_TRY_ASSIGN(id, get_unsigned(*object, "id"));
  TRXREG_TRY_ASSIGN(epoch, get_unsigned(*object, "epoch"));
  if (id == 0 || id > 0xFFFFFFFFull || epoch == 0 || epoch > 0xFFFFFFFFull) {
    return make_error(StatusCode::Malformed, "source record ids are out of range");
  }
  source.id = SourceId{static_cast<std::uint32_t>(id)};
  source.epoch = SourceEpoch{static_cast<std::uint32_t>(epoch)};
  source.name = get_text_or(*object, "name", "");
  if (source.name.empty()) {
    return make_error(StatusCode::Malformed, "source record is missing its name");
  }
  const Value* descriptor = object->find("descriptor");
  if (descriptor != nullptr) {
    TRXREG_TRY_ASSIGN(parsed, codec::decode<SourceDescriptor>(*descriptor));
    source.descriptor = parsed;
  }
  source.generation = Generation{get_unsigned_or(*object, "generation", 0)};
  source.sequence = Sequence{get_unsigned_or(*object, "sequence", 0)};
  source.registered_wall_ns = get_integer_or(*object, "registered_wall_ns", 0);
  return source;
}

Value encode_module(const ModuleRecord& record, bool include_history) {
  std::vector<Value::Member> members;
  members.push_back({"key", Value::text(record.key.str())});
  members.push_back({"uid", Value::integer(static_cast<std::int64_t>(record.uid.value()))});
  members.push_back({"incarnation", Value::integer(static_cast<std::int64_t>(record.incarnation.value()))});
  members.push_back({"incarnation_count", Value::integer(static_cast<std::int64_t>(record.incarnation_count))});
  members.push_back({"state", Value::integer(static_cast<std::int64_t>(record.state))});
  members.push_back({"state_generation", Value::integer(static_cast<std::int64_t>(record.state_generation.value()))});
  members.push_back({"state_sequence", Value::integer(static_cast<std::int64_t>(record.state_sequence.value()))});
  members.push_back({"state_wall_ns", Value::integer(record.state_wall_ns)});
  members.push_back({"created_generation", Value::integer(static_cast<std::int64_t>(record.created_generation.value()))});
  members.push_back({"created_sequence", Value::integer(static_cast<std::int64_t>(record.created_sequence.value()))});
  members.push_back({"created_wall_ns", Value::integer(record.created_wall_ns)});
  members.push_back({"fenced_generation", Value::integer(static_cast<std::int64_t>(record.fenced_generation.value()))});

  std::vector<const IdentityClaim*> claims;
  for (const IdentityClaim& claim : record.claims) {
    if (include_history || claim.live) {
      claims.push_back(&claim);
    }
  }
  std::sort(claims.begin(), claims.end(), [](const IdentityClaim* lhs, const IdentityClaim* rhs) {
    if (lhs->sequence != rhs->sequence) {
      return lhs->sequence < rhs->sequence;
    }
    return lhs->value < rhs->value;
  });
  Value::Array encoded_claims;
  encoded_claims.reserve(claims.size());
  for (const IdentityClaim* claim : claims) {
    encoded_claims.push_back(codec::encode(*claim));
  }
  members.push_back({"claims", Value::array(std::move(encoded_claims))});

  std::vector<const CapabilityDeclaration*> declarations;
  for (const CapabilityDeclaration& declaration : record.declarations) {
    if (include_history || declaration.live) {
      declarations.push_back(&declaration);
    }
  }
  std::sort(declarations.begin(), declarations.end(),
            [](const CapabilityDeclaration* lhs, const CapabilityDeclaration* rhs) {
              if (lhs->sequence != rhs->sequence) {
                return lhs->sequence < rhs->sequence;
              }
              return lhs->key < rhs->key;
            });
  Value::Array encoded_declarations;
  encoded_declarations.reserve(declarations.size());
  for (const CapabilityDeclaration* declaration : declarations) {
    encoded_declarations.push_back(codec::encode(*declaration));
  }
  members.push_back({"declarations", Value::array(std::move(encoded_declarations))});

  std::vector<const HealthSample*> samples;
  for (const HealthSample& sample : record.samples) {
    samples.push_back(&sample);
  }
  std::sort(samples.begin(), samples.end(), [](const HealthSample* lhs, const HealthSample* rhs) {
    if (lhs->sequence != rhs->sequence) {
      return lhs->sequence < rhs->sequence;
    }
    return lhs->observed_at_wall_ns < rhs->observed_at_wall_ns;
  });
  Value::Array encoded_samples;
  encoded_samples.reserve(samples.size());
  for (const HealthSample* sample : samples) {
    encoded_samples.push_back(codec::encode(*sample));
  }
  members.push_back({"samples", Value::array(std::move(encoded_samples))});

  Value::Array encoded_latches;
  encoded_latches.reserve(record.latches.size());
  for (const HealthLatchRecord& latch : record.latches) {
    encoded_latches.push_back(encode_latch_record(latch));
  }
  members.push_back({"latches", Value::array(std::move(encoded_latches))});

  std::vector<const LifecycleEvent*> events;
  for (const LifecycleEvent& event : record.lifecycle) {
    events.push_back(&event);
  }
  std::sort(events.begin(), events.end(), [](const LifecycleEvent* lhs, const LifecycleEvent* rhs) {
    if (lhs->sequence != rhs->sequence) {
      return lhs->sequence < rhs->sequence;
    }
    return lhs->wall_ns < rhs->wall_ns;
  });
  Value::Array encoded_events;
  encoded_events.reserve(events.size());
  for (const LifecycleEvent* event : events) {
    encoded_events.push_back(codec::encode(*event));
  }
  members.push_back({"lifecycle", Value::array(std::move(encoded_events))});

  return Value::object(std::move(members));
}

Result<ModuleRecord> decode_module(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "module record"));
  ModuleRecord record;

  TRXREG_TRY_ASSIGN(key_text, get_text(*object, "key"));
  TRXREG_TRY_ASSIGN(key, ModuleKey::parse(key_text, "module key"));
  record.key = key;
  TRXREG_TRY_ASSIGN(uid, get_unsigned(*object, "uid"));
  if (uid == 0) {
    return make_error(StatusCode::Malformed, "module record has no identity");
  }
  record.uid = ModuleUid{uid};
  TRXREG_TRY_ASSIGN(incarnation, get_unsigned(*object, "incarnation"));
  if (incarnation == 0 || incarnation > 0xFFFFFFFFull) {
    return make_error(StatusCode::Malformed, "module incarnation is out of range");
  }
  record.incarnation = IncarnationId{static_cast<std::uint32_t>(incarnation)};
  TRXREG_TRY_ASSIGN(state, get_enum<LifecycleState>(*object, "state", static_cast<std::uint8_t>(LifecycleState::Replaced), "lifecycle state"));
  record.state = state;
  record.state_generation = Generation{get_unsigned_or(*object, "state_generation", 0)};
  record.state_sequence = Sequence{get_unsigned_or(*object, "state_sequence", 0)};
  record.state_wall_ns = get_integer_or(*object, "state_wall_ns", 0);
  record.created_generation = Generation{get_unsigned_or(*object, "created_generation", 0)};
  record.created_sequence = Sequence{get_unsigned_or(*object, "created_sequence", 0)};
  record.created_wall_ns = get_integer_or(*object, "created_wall_ns", 0);
  record.fenced_generation = Generation{get_unsigned_or(*object, "fenced_generation", 0)};
  const std::uint64_t incarnation_count = get_unsigned_or(*object, "incarnation_count", 1);
  if (incarnation_count == 0 || incarnation_count > 0xFFFFFFFFull) {
    return make_error(StatusCode::Malformed, "module incarnation count is out of range");
  }
  record.incarnation_count = static_cast<std::uint32_t>(incarnation_count);

  const Value::Array* claims = detail::get_array_or(*object, "claims");
  if (claims != nullptr) {
    for (const Value& entry : *claims) {
      TRXREG_TRY_ASSIGN(claim, codec::decode<IdentityClaim>(entry));
      record.claims.push_back(std::move(claim));
    }
  }
  const Value::Array* declarations = detail::get_array_or(*object, "declarations");
  if (declarations != nullptr) {
    for (const Value& entry : *declarations) {
      TRXREG_TRY_ASSIGN(declaration, codec::decode<CapabilityDeclaration>(entry));
      record.declarations.push_back(std::move(declaration));
    }
  }
  const Value::Array* samples = detail::get_array_or(*object, "samples");
  if (samples != nullptr) {
    for (const Value& entry : *samples) {
      TRXREG_TRY_ASSIGN(sample, codec::decode<HealthSample>(entry));
      record.series_counts[{static_cast<std::uint8_t>(sample.metric), sample.lane}] += 1;
      record.samples.push_back(std::move(sample));
    }
  }
  const Value::Array* latches = detail::get_array_or(*object, "latches");
  if (latches != nullptr) {
    for (const Value& entry : *latches) {
      TRXREG_TRY_ASSIGN(latch, decode_latch_record(entry));
      record.latches.push_back(std::move(latch));
    }
  }
  const Value::Array* lifecycle = detail::get_array_or(*object, "lifecycle");
  if (lifecycle != nullptr) {
    for (const Value& entry : *lifecycle) {
      TRXREG_TRY_ASSIGN(event, codec::decode<LifecycleEvent>(entry));
      record.lifecycle.push_back(std::move(event));
    }
  }
  if (record.lifecycle.empty()) {
    LifecycleEvent discovered;
    discovered.from = LifecycleState::Discovered;
    discovered.to = record.state;
    discovered.incarnation = record.incarnation;
    discovered.reason = "restored from a snapshot that carried no lifecycle history";
    discovered.generation = record.state_generation;
    discovered.sequence = record.state_sequence;
    discovered.wall_ns = record.created_wall_ns;
    record.lifecycle.push_back(discovered);
  }
  return record;
}

Value encode_port(const PortRecord& record) {
  Value::Array declarations;
  declarations.reserve(record.declarations.size());
  for (const CapabilityDeclaration& declaration : record.declarations) {
    declarations.push_back(codec::encode(declaration));
  }
  return codec::object({{"declarations", Value::array(std::move(declarations))},
                        {"first_generation", Value::integer(static_cast<std::int64_t>(record.first_generation.value()))},
                        {"first_wall_ns", Value::integer(record.first_wall_ns)},
                        {"key", Value::text(record.key.str())},
                        {"sequence", Value::integer(static_cast<std::int64_t>(record.sequence.value()))}});
}

Result<PortRecord> decode_port(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "port record"));
  PortRecord record;
  TRXREG_TRY_ASSIGN(key_text, get_text(*object, "key"));
  TRXREG_TRY_ASSIGN(key, PortKey::parse(key_text, "port key"));
  record.key = key;
  record.first_generation = Generation{get_unsigned_or(*object, "first_generation", 0)};
  record.first_wall_ns = get_integer_or(*object, "first_wall_ns", 0);
  record.sequence = Sequence{get_unsigned_or(*object, "sequence", 0)};
  const Value::Array* declarations = detail::get_array_or(*object, "declarations");
  if (declarations != nullptr) {
    for (const Value& entry : *declarations) {
      TRXREG_TRY_ASSIGN(declaration, codec::decode<CapabilityDeclaration>(entry));
      record.declarations.push_back(std::move(declaration));
    }
  }
  return record;
}

Value encode_threshold(const ThresholdRecord& record) {
  return codec::object({{"generation", Value::integer(static_cast<std::int64_t>(record.generation.value()))},
                        {"live", Value::boolean(record.live)},
                        {"sequence", Value::integer(static_cast<std::int64_t>(record.sequence.value()))},
                        {"threshold", codec::encode(record.threshold)}});
}

Result<ThresholdRecord> decode_threshold(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "threshold record"));
  ThresholdRecord record;
  const Value* threshold = object->find("threshold");
  if (threshold == nullptr) {
    return make_error(StatusCode::Malformed, "threshold record is missing its threshold");
  }
  TRXREG_TRY_ASSIGN(parsed, codec::decode<HealthThreshold>(*threshold));
  record.threshold = parsed;
  record.generation = Generation{get_unsigned_or(*object, "generation", 0)};
  record.sequence = Sequence{get_unsigned_or(*object, "sequence", 0)};
  record.live = get_boolean_or(*object, "live", true);
  return record;
}

Value encode_state_header(const State& state) {
  return codec::object({{"conflicts_observed", Value::integer(static_cast<std::int64_t>(state.conflicts_observed))},
                        {"dropped_samples", Value::integer(static_cast<std::int64_t>(state.dropped_samples))},
                        {"generation", Value::integer(static_cast<std::int64_t>(state.generation.value()))},
                        {"mutations", Value::integer(static_cast<std::int64_t>(state.mutations))},
                        {"next_module_uid", Value::integer(static_cast<std::int64_t>(state.next_module_uid))},
                        {"next_rule_id", Value::integer(static_cast<std::int64_t>(state.next_rule_id))},
                        {"next_sequence", Value::integer(static_cast<std::int64_t>(state.next_sequence))},
                        {"next_source_id", Value::integer(static_cast<std::int64_t>(state.next_source_id))},
                        {"registry_incarnation", Value::integer(static_cast<std::int64_t>(state.registry_incarnation))}});
}

Result<State> decode_state_header(const Value& encoded) {
  TRXREG_TRY_ASSIGN(object, as_object(encoded, "state header"));
  State state;
  state.generation = Generation{get_unsigned_or(*object, "generation", 0)};
  TRXREG_TRY_ASSIGN(incarnation, get_unsigned(*object, "registry_incarnation"));
  if (incarnation == 0 || incarnation > 0xFFFFFFFFull) {
    return make_error(StatusCode::Malformed, "registry incarnation is out of range");
  }
  state.registry_incarnation = static_cast<std::uint32_t>(incarnation);
  state.next_module_uid = get_unsigned_or(*object, "next_module_uid", 1);
  state.next_rule_id = get_unsigned_or(*object, "next_rule_id", 1);
  state.next_source_id = get_unsigned_or(*object, "next_source_id", 1);
  state.next_sequence = get_unsigned_or(*object, "next_sequence", 1);
  state.mutations = get_unsigned_or(*object, "mutations", 0);
  state.dropped_samples = get_unsigned_or(*object, "dropped_samples", 0);
  state.conflicts_observed = get_unsigned_or(*object, "conflicts_observed", 0);
  return state;
}

}  // namespace

/// Canonical record stream of a whole state. The same logical state always
/// produces the same bytes, so the digest is a stable identity and a snapshot
/// round-trip preserves it.
std::vector<std::byte> encode_state_records(const State& state, bool include_history) {
  std::vector<std::byte> out;
  append_record(out, Record{kRecordHeader, encode_document(encode_state_header(state))});

  std::vector<const SourceRecord*> sources;
  for (const auto& entry : state.sources) {
    sources.push_back(&entry.second);
  }
  std::sort(sources.begin(), sources.end(),
            [](const SourceRecord* lhs, const SourceRecord* rhs) { return lhs->id < rhs->id; });
  for (const SourceRecord* source : sources) {
    append_record(out, Record{kRecordSource, encode_document(encode_source(*source))});
  }

  std::vector<const ModuleRecord*> modules;
  for (const auto& entry : state.modules) {
    modules.push_back(&entry.second);
  }
  std::sort(modules.begin(), modules.end(),
            [](const ModuleRecord* lhs, const ModuleRecord* rhs) { return lhs->uid < rhs->uid; });
  for (const ModuleRecord* module : modules) {
    append_record(out, Record{kRecordModule, encode_document(encode_module(*module, include_history))});
  }

  std::vector<const PortRecord*> ports;
  for (const auto& entry : state.ports) {
    ports.push_back(&entry.second);
  }
  std::sort(ports.begin(), ports.end(), [](const PortRecord* lhs, const PortRecord* rhs) {
    return lhs->key.str() < rhs->key.str();
  });
  for (const PortRecord* port : ports) {
    append_record(out, Record{kRecordPort, encode_document(encode_port(*port))});
  }

  std::vector<const AttachmentRecord*> attachments;
  for (const auto& entry : state.attachments) {
    attachments.push_back(&entry.second);
  }
  std::sort(attachments.begin(), attachments.end(), [](const AttachmentRecord* lhs, const AttachmentRecord* rhs) {
    return lhs->slot.str() < rhs->slot.str();
  });
  for (const AttachmentRecord* attachment : attachments) {
    append_record(out, Record{kRecordAttachment, encode_document(codec::encode(*attachment))});
  }

  std::vector<const ThresholdRecord*> thresholds;
  for (const ThresholdRecord& record : state.thresholds) {
    if (include_history || record.live) {
      thresholds.push_back(&record);
    }
  }
  for (const ThresholdRecord* record : thresholds) {
    append_record(out, Record{kRecordThreshold, encode_document(encode_threshold(*record))});
  }

  std::vector<const CompatRuleRecord*> rules;
  for (const auto& entry : state.rules) {
    rules.push_back(&entry.second);
  }
  std::sort(rules.begin(), rules.end(),
            [](const CompatRuleRecord* lhs, const CompatRuleRecord* rhs) { return lhs->id < rhs->id; });
  for (const CompatRuleRecord* rule : rules) {
    append_record(out, Record{kRecordRule, encode_document(codec::encode(*rule))});
  }

  return out;
}

Digest compute_state_digest(const State& state) { return sha256(encode_state_records(state, true)); }

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

namespace {

Status write_file_atomically(const std::string& path, const std::vector<std::byte>& bytes, bool fsync) {
  if (path.empty()) {
    return Status(StatusCode::InvalidArgument, "a snapshot path is required");
  }
  const std::string temporary = path + ".tmp";
  std::FILE* file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return Status(StatusCode::IoError, "cannot open the temporary snapshot file '" + temporary + "' for writing");
  }
  bool ok = true;
  std::string failure;
  if (!bytes.empty()) {
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      ok = false;
      failure = "short write while persisting the snapshot";
    }
  }
  if (ok && fsync) {
#if defined(_WIN32)
    if (::_commit(::_fileno(file)) != 0) {
      ok = false;
      failure = "flush to stable storage failed";
    }
#else
    if (::fsync(::fileno(file)) != 0) {
      ok = false;
      failure = "flush to stable storage failed";
    }
#endif
  }
  if (std::fclose(file) != 0 && ok) {
    ok = false;
    failure = "closing the temporary snapshot file failed";
  }
  if (!ok) {
    std::remove(temporary.c_str());
    return Status(StatusCode::IoError, failure);
  }

#if defined(_WIN32)
  if (::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    std::remove(temporary.c_str());
    return Status(StatusCode::IoError, "atomic rename of the snapshot failed");
  }
#else
  if (std::rename(temporary.c_str(), path.c_str()) != 0) {
    std::remove(temporary.c_str());
    return Status(StatusCode::IoError, "atomic rename of the snapshot failed");
  }
#endif
  return ok_status();
}

Result<std::vector<std::byte>> read_file(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return make_error(StatusCode::IoError, "cannot open snapshot '" + path + "' for reading");
  }
  std::vector<std::byte> bytes;
  std::byte buffer[64 * 1024];
  while (true) {
    const std::size_t read = std::fread(buffer, 1, sizeof(buffer), file);
    if (read > 0) {
      if (bytes.size() + read > kMaxSnapshotBytes) {
        std::fclose(file);
        return make_error(StatusCode::CapacityExceeded, "snapshot exceeds the maximum accepted size");
      }
      bytes.insert(bytes.end(), buffer, buffer + read);
    }
    if (read < sizeof(buffer)) {
      if (std::ferror(file) != 0) {
        std::fclose(file);
        return make_error(StatusCode::IoError, "reading the snapshot failed");
      }
      break;
    }
  }
  std::fclose(file);
  return bytes;
}

}  // namespace

Status save_snapshot_impl(const RegistryImpl& impl, const std::string& path, const SaveOptions& options) {
  const StatePtr state = impl.current();
  std::vector<std::byte> records = encode_state_records(*state, options.include_history);

  std::vector<std::byte> file;
  file.reserve(records.size() + 64);
  append_magic(file, kSnapshotMagic, sizeof(kSnapshotMagic));
  append_u16(file, kSnapshotFormatVersion);
  append_u16(file, 0);  // flags
  append_u32(file, 0);  // reserved
  append_u64(file, static_cast<std::uint64_t>(records.size()));
  append_u64(file, static_cast<std::uint64_t>(state->generation.value()));
  file.insert(file.end(), records.begin(), records.end());
  append_magic(file, kRecordTrailerMagic, sizeof(kRecordTrailerMagic));
  append_u64(file, static_cast<std::uint64_t>(state->next_sequence));
  append_u32(file, crc32c(records));

  return write_file_atomically(path, file, options.fsync);
}

Status save_snapshot(const Registry& registry, const std::string& path, const SaveOptions& options) {
  return save_snapshot_impl(RegistryAccess::impl(registry), path, options);
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

namespace {

struct ParsedSnapshot {
  State state;
  bool tail_recovered{false};
  std::uint64_t dropped_bytes{0};
  std::string note;
  Digest content_digest{};
  std::uint16_t format_version{kSnapshotFormatVersion};
  std::uint64_t records{0};
};

Result<ParsedSnapshot> parse_snapshot(const std::vector<std::byte>& file, const LoadOptions& options) {
  // magic(8) | version(2) | flags(2) | reserved(4) | record bytes(8) | generation(8)
  constexpr std::size_t kHeaderBytes = 8 + 2 + 2 + 4 + 8 + 8;
  if (file.size() < kHeaderBytes + sizeof(kRecordTrailerMagic) + 12) {
    return make_error(StatusCode::Corrupt, "snapshot is too short to contain a header");
  }
  if (std::memcmp(file.data(), kSnapshotMagic, sizeof(kSnapshotMagic)) != 0) {
    return make_error(StatusCode::Corrupt, "snapshot magic does not match");
  }
  ParsedSnapshot parsed;
  const std::uint16_t version = read_u16(file, 8);
  parsed.format_version = version;
  if (version != kSnapshotFormatVersion) {
    return make_error(options.require_supported_version ? StatusCode::Unsupported : StatusCode::Corrupt,
                      "snapshot format version " + std::to_string(version) + " is not supported");
  }
  if (read_u16(file, 10) != 0 || read_u32(file, 12) != 0) {
    return make_error(StatusCode::Malformed, "snapshot header flags and reserved fields must be zero");
  }
  const std::uint64_t record_bytes = read_u64(file, 16);
  if (record_bytes > kMaxSnapshotBytes - kHeaderBytes) {
    return make_error(StatusCode::Corrupt, "snapshot declares an impossible record length");
  }
  if (file.size() < kHeaderBytes + record_bytes) {
    if (!options.allow_tail_recovery) {
      return make_error(StatusCode::Corrupt, "snapshot is truncated");
    }
    parsed.tail_recovered = true;
    parsed.dropped_bytes = static_cast<std::uint64_t>(file.size() - kHeaderBytes);
    parsed.note = "the snapshot payload is shorter than its header declares";
    return parsed;
  }
  const std::uint64_t generation = read_u64(file, 24);
  parsed.state.generation = Generation{generation};

  const std::size_t record_end = kHeaderBytes + static_cast<std::size_t>(record_bytes);
  std::size_t position = kHeaderBytes;
  std::vector<std::byte> accepted;
  accepted.reserve(static_cast<std::size_t>(record_bytes));

  while (position < record_end) {
    if (record_end - position < 4) {
      if (!options.allow_tail_recovery) {
        return make_error(StatusCode::Corrupt, "snapshot record framing is truncated");
      }
      parsed.tail_recovered = true;
      parsed.dropped_bytes = static_cast<std::uint64_t>(record_end - position);
      parsed.note = "a partial record header ends the snapshot payload";
      break;
    }
    const std::uint32_t body_length = read_u32(file, position);
    if (body_length == 0 || body_length > kMaxRecordBytes) {
      if (!options.allow_tail_recovery) {
        return make_error(StatusCode::Corrupt, "snapshot record length is out of range");
      }
      parsed.tail_recovered = true;
      parsed.dropped_bytes = static_cast<std::uint64_t>(record_end - position);
      parsed.note = "a record length is out of range; the rest of the payload was dropped";
      break;
    }
    const std::size_t body_start = position + 4;
    if (body_start + body_length + 4 > record_end) {
      if (!options.allow_tail_recovery) {
        return make_error(StatusCode::Corrupt, "snapshot record is truncated");
      }
      parsed.tail_recovered = true;
      parsed.dropped_bytes = static_cast<std::uint64_t>(record_end - position);
      parsed.note = "the final record is incomplete; it and everything after it were dropped";
      break;
    }
    std::vector<std::byte> body(file.begin() + static_cast<std::ptrdiff_t>(body_start),
                                file.begin() + static_cast<std::ptrdiff_t>(body_start + body_length));
    const std::uint32_t stored_crc = read_u32(file, body_start + body_length);
    if (crc32c(body) != stored_crc) {
      if (!options.allow_tail_recovery) {
        return make_error(StatusCode::Corrupt, "snapshot record failed its integrity check");
      }
      parsed.tail_recovered = true;
      parsed.dropped_bytes = static_cast<std::uint64_t>(record_end - position);
      parsed.note = "a record failed its integrity check; it and everything after it were dropped";
      break;
    }
    const auto kind = std::to_integer<std::uint8_t>(body.front());
    std::vector<std::byte> payload(body.begin() + 1, body.end());
    // The trailer integrity check covers the framed record stream, not just the
    // record bodies, so the accepted bytes must keep the framing.
    accepted.insert(accepted.end(), file.begin() + static_cast<std::ptrdiff_t>(position),
                    file.begin() + static_cast<std::ptrdiff_t>(body_start + body_length + 4));

    TRXREG_TRY_ASSIGN(document, decode_document(payload, options.limits));
    switch (kind) {
      case kRecordHeader: {
        TRXREG_TRY_ASSIGN(header, decode_state_header(document));
        parsed.state = header;
        parsed.state.generation = Generation{generation};
        break;
      }
      case kRecordSource: {
        TRXREG_TRY_ASSIGN(source, decode_source(document));
        parsed.state.source_id_by_name[source.name] = source.id.value();
        parsed.state.sources[source.id.value()] = source;
        break;
      }
      case kRecordModule: {
        TRXREG_TRY_ASSIGN(module, decode_module(document));
        if (parsed.state.modules.count(module.uid.value()) != 0) {
          return make_error(StatusCode::Malformed, "snapshot declares the same module twice");
        }
        parsed.state.module_uid_by_key[module.key.str()] = module.uid.value();
        parsed.state.modules[module.uid.value()] = std::move(module);
        break;
      }
      case kRecordPort: {
        TRXREG_TRY_ASSIGN(port, decode_port(document));
        parsed.state.ports[port.key.str()] = std::move(port);
        break;
      }
      case kRecordAttachment: {
        TRXREG_TRY_ASSIGN(attachment, codec::decode<AttachmentRecord>(document));
        parsed.state.attachments[attachment.slot.str()] = std::move(attachment);
        break;
      }
      case kRecordThreshold: {
        TRXREG_TRY_ASSIGN(threshold, decode_threshold(document));
        parsed.state.thresholds.push_back(std::move(threshold));
        break;
      }
      case kRecordRule: {
        TRXREG_TRY_ASSIGN(rule, codec::decode<CompatRuleRecord>(document));
        parsed.state.rules[rule.id.value()] = std::move(rule);
        break;
      }
      default:
        return make_error(StatusCode::Malformed, "snapshot contains an unknown record kind");
    }
    ++parsed.records;
    position = body_start + body_length + 4;
  }

  if (!parsed.tail_recovered) {
    const std::size_t trailer_start = record_end;
    if (file.size() < trailer_start + sizeof(kRecordTrailerMagic) + 12) {
      if (!options.allow_tail_recovery) {
        return make_error(StatusCode::Corrupt, "snapshot trailer is missing");
      }
      parsed.tail_recovered = true;
      parsed.dropped_bytes = static_cast<std::uint64_t>(file.size() - trailer_start);
      parsed.note = "the snapshot trailer is incomplete";
    } else {
      if (std::memcmp(file.data() + trailer_start, kRecordTrailerMagic, sizeof(kRecordTrailerMagic)) != 0) {
        if (!options.allow_tail_recovery) {
          return make_error(StatusCode::Corrupt, "snapshot trailer magic does not match");
        }
        parsed.tail_recovered = true;
        parsed.dropped_bytes = static_cast<std::uint64_t>(file.size() - trailer_start);
        parsed.note = "the snapshot trailer is damaged";
      } else {
        const std::size_t crc_offset = file.size() - 4;
        const std::uint32_t stored = read_u32(file, crc_offset);
        if (crc32c(accepted) != stored) {
          return make_error(StatusCode::Corrupt, "snapshot payload failed its integrity check");
        }
      }
    }
  }

  parsed.content_digest = sha256(accepted);
  return parsed;
}

/// Re-validate persisted dynamic evidence against the current clock. A latch
/// whose evidence base no longer holds becomes Unknown, and every sample that
/// cannot still describe the present is counted so the load report is honest
/// about what was discarded.
std::uint64_t revalidate_evidence(State& state, WallNs now) {
  std::uint64_t invalidated = 0;
  const std::vector<HealthThreshold> thresholds = live_thresholds(state);
  for (auto& entry : state.modules) {
    ModuleRecord& record = entry.second;
    for (HealthLatchRecord& latch : record.latches) {
      const HealthThreshold* threshold = detail::select_threshold(thresholds, latch.metric, latch.lane);
      const HealthSample* newest = nullptr;
      for (const HealthSample& sample : record.samples) {
        if (sample.metric != latch.metric || sample.lane != latch.lane) {
          continue;
        }
        if (sample.incarnation != record.incarnation || !sample.live) {
          continue;
        }
        if (!source_is_live(state, sample.source, sample.source_epoch)) {
          continue;
        }
        if (newest == nullptr || newest->observed_at_wall_ns < sample.observed_at_wall_ns) {
          newest = &sample;
        }
      }
      if (threshold == nullptr || newest == nullptr || newest->presence != SamplePresence::Present) {
        latch.latch = HealthLatch{};
        ++invalidated;
        continue;
      }
      const WallNs age = now > newest->observed_at_wall_ns ? now - newest->observed_at_wall_ns : 0;
      if (age > threshold->max_age_ns) {
        latch.latch = HealthLatch{};
        ++invalidated;
      }
    }
  }
  return invalidated;
}

}  // namespace

Result<LoadReport> load_snapshot(Registry& registry, const std::string& path, const LoadOptions& options) {
  RegistryImpl& impl = RegistryAccess::impl(registry);
  {
    std::unique_lock<std::mutex> lock(impl.mutex);
    const State& state = *impl.state;
    if (!state.modules.empty() || !state.ports.empty() || !state.rules.empty() || !state.sources.empty() ||
        !state.attachments.empty() || !state.thresholds.empty()) {
      return make_error(StatusCode::Conflict, "a snapshot can only be loaded into an empty registry");
    }
  }

  TRXREG_TRY_ASSIGN(file, read_file(path));
  TRXREG_TRY_ASSIGN(parsed, parse_snapshot(file, options));

  const WallNs now = impl.clock->wall_now_ns();
  const std::uint64_t invalidated = revalidate_evidence(parsed.state, now);

  // Dropping records can leave references dangling; a conservative load removes
  // attachments whose module is not present instead of resurrecting them.
  std::uint64_t dropped_attachments = 0;
  for (auto it = parsed.state.attachments.begin(); it != parsed.state.attachments.end();) {
    if (parsed.state.modules.count(it->second.uid.value()) == 0) {
      it = parsed.state.attachments.erase(it);
      ++dropped_attachments;
    } else {
      ++it;
    }
  }

  LoadReport report;
  report.format_version = parsed.format_version;
  report.tail_recovered = parsed.tail_recovered;
  report.dropped_tail_bytes = parsed.dropped_bytes;
  report.recovery_note = parsed.note;
  report.content_digest = parsed.content_digest;
  report.loaded_at_wall_ns = now;
  report.evidence_invalidated_on_load = invalidated;
  if (dropped_attachments > 0) {
    if (!report.recovery_note.empty()) {
      report.recovery_note += "; ";
    }
    report.recovery_note += "dropped " + std::to_string(dropped_attachments) +
                            " attachment(s) whose module did not survive the recovery";
  }

  {
    std::unique_lock<std::mutex> lock(impl.mutex);
    auto next = std::make_shared<State>(std::move(parsed.state));
    // A load is a new registry incarnation. The generation advances so that
    // decisions fenced against the previous process are provably stale.
    next->registry_incarnation = next->registry_incarnation == 0xFFFFFFFFu ? 1 : next->registry_incarnation + 1;
    next->generation = Generation{next->generation.value() + 1};
    if (next->next_sequence == 0) {
      next->next_sequence = 1;
    }
    impl.state = std::move(next);
  }

  const StatePtr state = impl.current();
  report.generation = state->generation;
  report.registry_incarnation = state->registry_incarnation;
  report.sources = state->sources.size();
  report.modules = state->modules.size();
  report.ports = state->ports.size();
  report.rules = state->rules.size();
  report.claims = 0;
  report.declarations = 0;
  report.samples = 0;
  for (const auto& entry : state->modules) {
    report.incarnations += entry.second.incarnation_count;
    if (entry.second.incarnation_count > 1) {
      ++report.fenced_incarnations;
    }
    report.claims += entry.second.claims.size();
    report.declarations += entry.second.declarations.size();
    report.samples += entry.second.samples.size();
  }
  for (const auto& entry : state->ports) {
    report.declarations += entry.second.declarations.size();
  }
  for (const ThresholdRecord& record : state->thresholds) {
    if (record.live) {
      ++report.thresholds;
    }
  }
  return report;
}

Result<LoadReport> inspect_snapshot(const std::string& path, const LoadOptions& options) {
  Registry scratch;
  return load_snapshot(scratch, path, options);
}

}  // namespace trxreg
