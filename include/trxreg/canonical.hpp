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
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/digest.hpp"
#include "trxreg/result.hpp"

// Canonical encoding used for digest identity, the snapshot payload, and the
// loopback transport.
//
// The encoding is deterministic: the same logical value always produces the
// same bytes, independent of insertion order. That property is what makes the
// digest a stable identity, so the decoder is strict: truncated input, overlong
// or out-of-range varints, NaN reals, empty or duplicate or unsorted object
// keys, invalid UTF-8, unknown tags, and values beyond the configured limits are
// all rejected as Malformed, Corrupt, or CapacityExceeded.
//
// Reals are compared and encoded bit-exactly, so -0.0 and +0.0 are distinct
// values and both round-trip; NaN has no encoding and is refused.
//
// The writer trusts its caller: Value and CanonicalWriter are the low-level
// encoding primitives, and CanonicalWriter::failed() reports when a value that
// has no canonical form (NaN, invalid UTF-8, an empty key) was handed to them.
// Every externally supplied document goes through CanonicalReader instead.

namespace trxreg {

/// Hard bounds applied to every externally supplied document. Validation always
/// happens before allocation, and allocation sizes are derived only from
/// already-validated counters.
struct CanonicalLimits {
  std::uint64_t max_document_bytes{1u << 20};
  std::uint64_t max_string_bytes{64u << 10};
  std::uint64_t max_binary_bytes{256u << 10};
  std::uint64_t max_elements{65536};
  std::uint64_t max_object_fields{4096};
  std::uint64_t max_depth{24};
  std::uint64_t max_nodes{131072};

  /// Limits suitable for a single registry mutation request.
  [[nodiscard]] static CanonicalLimits request() noexcept;
  /// Limits suitable for a whole registry snapshot.
  [[nodiscard]] static CanonicalLimits snapshot() noexcept;
};

/// A bounded, canonically ordered document value.
class Value {
 public:
  enum class Kind : std::uint8_t {
    Null = 0,
    Boolean,
    /// Signed 64-bit integer, zigzag encoded.
    Integer,
    /// Unsigned 64-bit integer. Distinct from Integer so that values above
    /// 2^63-1 (clock-domain hashes, for example) survive a round trip instead of
    /// being reinterpreted as negative.
    Unsigned,
    Real,
    Text,
    Binary,
    Array,
    Object,
  };

  struct Member;
  using Array = std::vector<Value>;
  using Object = std::vector<Member>;
  using Binary = std::vector<std::byte>;

  Value() = default;
  Value(const Value&) = default;
  Value(Value&&) noexcept = default;
  Value& operator=(const Value&) = default;
  Value& operator=(Value&&) noexcept = default;
  ~Value() = default;

  [[nodiscard]] static Value null();
  [[nodiscard]] static Value boolean(bool value);
  [[nodiscard]] static Value integer(std::int64_t value);
  [[nodiscard]] static Value unsigned_integer(std::uint64_t value);
  [[nodiscard]] static Value real(double value);
  [[nodiscard]] static Value text(std::string value);
  [[nodiscard]] static Value binary(Binary value);
  [[nodiscard]] static Value array(Array value);
  [[nodiscard]] static Value object(Object value);

  [[nodiscard]] Kind kind() const noexcept { return kind_; }
  [[nodiscard]] bool is_null() const noexcept { return kind_ == Kind::Null; }
  [[nodiscard]] bool is_boolean() const noexcept { return kind_ == Kind::Boolean; }
  [[nodiscard]] bool is_integer() const noexcept { return kind_ == Kind::Integer; }
  [[nodiscard]] bool is_unsigned() const noexcept { return kind_ == Kind::Unsigned; }
  [[nodiscard]] bool is_real() const noexcept { return kind_ == Kind::Real; }
  [[nodiscard]] bool is_number() const noexcept { return is_integer() || is_real(); }
  [[nodiscard]] bool is_text() const noexcept { return kind_ == Kind::Text; }
  [[nodiscard]] bool is_binary() const noexcept { return kind_ == Kind::Binary; }
  [[nodiscard]] bool is_array() const noexcept { return kind_ == Kind::Array; }
  [[nodiscard]] bool is_object() const noexcept { return kind_ == Kind::Object; }

  [[nodiscard]] bool as_boolean() const noexcept { return boolean_; }
  [[nodiscard]] std::int64_t as_integer() const noexcept { return integer_; }
  [[nodiscard]] std::uint64_t as_unsigned() const noexcept { return unsigned_; }
  [[nodiscard]] double as_real() const noexcept { return real_; }
  [[nodiscard]] const std::string& as_text() const noexcept { return text_; }
  [[nodiscard]] const Binary& as_binary() const noexcept { return binary_; }
  [[nodiscard]] const Array& as_array() const noexcept { return array_; }
  [[nodiscard]] const Object& as_object() const noexcept { return object_; }
  [[nodiscard]] Array& array_mut() noexcept { return array_; }
  [[nodiscard]] Object& object_mut() noexcept { return object_; }

  /// Numeric value as double, for integers and reals.
  [[nodiscard]] bool number_as_double(double& out) const noexcept;

  /// Object lookup. Keys are kept in canonical (byte-lexicographic) order.
  [[nodiscard]] const Value* find(std::string_view key) const noexcept;

  /// Insert or replace an object member, preserving canonical key order.
  /// Returns false when the value is not an object or the key is empty.
  /// A Value does not know the reader's limits, so the length limit is enforced
  /// where external input arrives (CanonicalReader) and by the codecs.
  bool set(std::string_view key, Value value);

  /// Insert an object member, rejecting duplicate keys.
  Status set_unique(std::string_view key, Value value);

  /// Structural equality (used by tests and by reference-model differential checks).
  friend bool operator==(const Value& lhs, const Value& rhs) noexcept;
  friend bool operator!=(const Value& lhs, const Value& rhs) noexcept { return !(lhs == rhs); }

  /// Human-readable rendering. Used by the CLI and by failure diagnostics; it is
  /// not the canonical form and must not be used for identity.
  [[nodiscard]] std::string to_json() const;

 private:
  Kind kind_{Kind::Null};
  bool boolean_{false};
  std::int64_t integer_{0};
  std::uint64_t unsigned_{0};
  double real_{0.0};
  std::string text_;
  Binary binary_;
  Array array_;
  Object object_;
};

/// Object member. Defined after Value so that the recursive containment is
/// legal; std::vector supports an incomplete element type at this point.
struct Value::Member {
  std::string key;
  Value value;

  friend bool operator==(const Member& lhs, const Member& rhs) noexcept;
};

/// Streaming canonical encoder. Array and object counts are supplied by the
/// caller, so no back-patching is required and the byte stream is final.
class CanonicalWriter {
 public:
  CanonicalWriter() = default;

  void null_value();
  void boolean(bool value);
  void integer(std::int64_t value);
  void unsigned_integer(std::uint64_t value);
  void real(double value);
  void text(std::string_view value);
  void binary(std::span<const std::byte> value);
  void begin_array(std::uint64_t count);
  void end_array();
  void begin_object(std::uint64_t count);
  void end_object();
  /// Object member key; the member value follows.
  void field(std::string_view key);

  void write_value(const Value& value);

  [[nodiscard]] const std::vector<std::byte>& bytes() const noexcept { return buffer_; }
  [[nodiscard]] std::vector<std::byte> take() && { return std::move(buffer_); }
  [[nodiscard]] std::uint64_t size() const noexcept { return static_cast<std::uint64_t>(buffer_.size()); }
  [[nodiscard]] Digest digest() const;

  /// True when a value with no canonical form was written (a NaN real, text
  /// that is not valid UTF-8, an empty object key). The offending value is
  /// skipped and every other byte is still written, so a caller that checks
  /// this flag can refuse to persist or transmit the result instead of
  /// producing a document its own reader would reject.
  [[nodiscard]] bool failed() const noexcept { return failed_; }

  void clear() noexcept {
    buffer_.clear();
    failed_ = false;
  }

 private:
  std::vector<std::byte> buffer_;
  bool failed_{false};
};

/// Canonical decoder with strict validation and bounded resource use.
class CanonicalReader {
 public:
  CanonicalReader(std::span<const std::byte> data, CanonicalLimits limits);
  CanonicalReader(const std::vector<std::byte>& data, CanonicalLimits limits);

  /// Decode one complete value.
  [[nodiscard]] Result<Value> read_value();
  /// Decode a document and require that no bytes remain.
  [[nodiscard]] Result<Value> read_document();

  [[nodiscard]] bool at_end() const noexcept { return position_ >= data_.size(); }
  [[nodiscard]] std::uint64_t remaining() const noexcept {
    return static_cast<std::uint64_t>(data_.size() - position_);
  }
  [[nodiscard]] const CanonicalLimits& limits() const noexcept { return limits_; }

 private:
  Result<Value> read_value_at_depth(std::uint64_t depth);
  Status read_tag(std::uint8_t& tag);
  Status read_varint(std::uint64_t& out);
  Status read_length(std::uint64_t& out, std::uint64_t max_allowed, std::string_view what);
  Status read_bytes_exact(std::uint64_t count, std::span<const std::byte>& out);

  std::span<const std::byte> data_;
  CanonicalLimits limits_;
  std::size_t position_{0};
  std::uint64_t nodes_{0};
};

/// Validate UTF-8 well-formedness of a byte range.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

}  // namespace trxreg
