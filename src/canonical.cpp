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

#include "trxreg/canonical.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace trxreg {
namespace {

constexpr std::uint8_t kTagNull = 0x00u;
constexpr std::uint8_t kTagFalse = 0x01u;
constexpr std::uint8_t kTagTrue = 0x02u;
constexpr std::uint8_t kTagInteger = 0x03u;
constexpr std::uint8_t kTagReal = 0x04u;
constexpr std::uint8_t kTagText = 0x05u;
constexpr std::uint8_t kTagBinary = 0x06u;
constexpr std::uint8_t kTagArray = 0x07u;
constexpr std::uint8_t kTagObject = 0x08u;
constexpr std::uint8_t kTagUnsigned = 0x09u;

/// Byte-lexicographic comparison with unsigned semantics. std::string's own
/// comparison is not relied upon here so that the canonical order is identical
/// on every platform and standard library.
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

void append_byte(std::vector<std::byte>& out, std::uint8_t value) {
  out.push_back(static_cast<std::byte>(value));
}

void append_varint(std::vector<std::byte>& out, std::uint64_t value) {
  while (value >= 0x80u) {
    append_byte(out, static_cast<std::uint8_t>((value & 0x7fu) | 0x80u));
    value >>= 7u;
  }
  append_byte(out, static_cast<std::uint8_t>(value));
}

std::uint64_t zigzag_encode(std::int64_t value) noexcept {
  const auto bits = static_cast<std::uint64_t>(value);
  return (bits << 1u) ^ static_cast<std::uint64_t>(value >> 63);
}

std::int64_t zigzag_decode(std::uint64_t value) noexcept {
  const std::uint64_t magnitude = (value >> 1u) ^ (~(value & 1u) + 1u);
  return static_cast<std::int64_t>(magnitude);
}

void append_json_string(std::string& out, std::string_view text) {
  out.push_back('"');
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (byte < 0x20u) {
          static constexpr char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out.push_back(kHex[(byte >> 4u) & 0x0fu]);
          out.push_back(kHex[byte & 0x0fu]);
        } else {
          out.push_back(ch);
        }
        break;
    }
  }
  out.push_back('"');
}

}  // namespace

bool is_valid_utf8(std::string_view text) noexcept {
  const auto* data = reinterpret_cast<const unsigned char*>(text.data());
  const std::size_t size = text.size();
  std::size_t i = 0;
  while (i < size) {
    const unsigned char byte = data[i];
    if (byte < 0x80u) {
      ++i;
      continue;
    }
    std::size_t extra = 0;
    unsigned char lower = 0x80u;
    unsigned char upper = 0xbfu;
    if (byte >= 0xc2u && byte <= 0xdfu) {
      extra = 1;
    } else if (byte == 0xe0u) {
      extra = 2;
      lower = 0xa0u;
    } else if (byte >= 0xe1u && byte <= 0xecu) {
      extra = 2;
    } else if (byte == 0xedu) {
      extra = 2;
      upper = 0x9fu;
    } else if (byte >= 0xeeu && byte <= 0xefu) {
      extra = 2;
    } else if (byte == 0xf0u) {
      extra = 3;
      lower = 0x90u;
    } else if (byte >= 0xf1u && byte <= 0xf3u) {
      extra = 3;
    } else if (byte == 0xf4u) {
      extra = 3;
      upper = 0x8fu;
    } else {
      return false;
    }
    if (i + extra >= size) {
      return false;
    }
    const unsigned char first_continuation = data[i + 1];
    if (first_continuation < lower || first_continuation > upper) {
      return false;
    }
    for (std::size_t k = 2; k <= extra; ++k) {
      const unsigned char continuation = data[i + k];
      if (continuation < 0x80u || continuation > 0xbfu) {
        return false;
      }
    }
    i += extra + 1;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

bool operator==(const Value::Member& lhs, const Value::Member& rhs) noexcept {
  return lhs.key == rhs.key && lhs.value == rhs.value;
}

Value Value::null() { return Value{}; }

Value Value::boolean(bool value) {
  Value out;
  out.kind_ = Kind::Boolean;
  out.boolean_ = value;
  return out;
}

Value Value::integer(std::int64_t value) {
  Value out;
  out.kind_ = Kind::Integer;
  out.integer_ = value;
  return out;
}

Value Value::unsigned_integer(std::uint64_t value) {
  Value out;
  out.kind_ = Kind::Unsigned;
  out.unsigned_ = value;
  return out;
}

Value Value::real(double value) {
  Value out;
  out.kind_ = Kind::Real;
  out.real_ = value;
  return out;
}

Value Value::text(std::string value) {
  Value out;
  out.kind_ = Kind::Text;
  out.text_ = std::move(value);
  return out;
}

Value Value::binary(Binary value) {
  Value out;
  out.kind_ = Kind::Binary;
  out.binary_ = std::move(value);
  return out;
}

Value Value::array(Array value) {
  Value out;
  out.kind_ = Kind::Array;
  out.array_ = std::move(value);
  return out;
}

Value Value::object(Object value) {
  std::stable_sort(value.begin(), value.end(), [](const Member& lhs, const Member& rhs) {
    return compare_bytes(lhs.key, rhs.key) < 0;
  });
  // Duplicate keys are not canonical; keep the first occurrence and drop the rest.
  value.erase(std::unique(value.begin(), value.end(),
                          [](const Member& lhs, const Member& rhs) { return lhs.key == rhs.key; }),
              value.end());
  Value out;
  out.kind_ = Kind::Object;
  out.object_ = std::move(value);
  return out;
}

bool Value::number_as_double(double& out) const noexcept {
  if (is_integer()) {
    out = static_cast<double>(integer_);
    return true;
  }
  if (is_unsigned()) {
    out = static_cast<double>(unsigned_);
    return true;
  }
  if (is_real()) {
    out = real_;
    return true;
  }
  return false;
}

const Value* Value::find(std::string_view key) const noexcept {
  if (kind_ != Kind::Object) {
    return nullptr;
  }
  const auto it = std::lower_bound(object_.begin(), object_.end(), key,
                                   [](const Member& member, std::string_view needle) {
                                     return compare_bytes(member.key, needle) < 0;
                                   });
  if (it == object_.end() || compare_bytes(it->key, key) != 0) {
    return nullptr;
  }
  return &it->value;
}

bool Value::set(std::string_view key, Value value) {
  if (kind_ != Kind::Object || key.empty()) {
    return false;
  }
  const auto it = std::lower_bound(object_.begin(), object_.end(), key,
                                   [](const Member& member, std::string_view needle) {
                                     return compare_bytes(member.key, needle) < 0;
                                   });
  if (it != object_.end() && compare_bytes(it->key, key) == 0) {
    it->value = std::move(value);
    return true;
  }
  object_.insert(it, Member{std::string(key), std::move(value)});
  return true;
}

Status Value::set_unique(std::string_view key, Value value) {
  if (kind_ != Kind::Object) {
    return Status(StatusCode::Malformed, "canonical object member inserted into a non-object value");
  }
  if (key.empty()) {
    return Status(StatusCode::Malformed, "canonical object member key must not be empty");
  }
  const auto it = std::lower_bound(object_.begin(), object_.end(), key,
                                   [](const Member& member, std::string_view needle) {
                                     return compare_bytes(member.key, needle) < 0;
                                   });
  if (it != object_.end() && compare_bytes(it->key, key) == 0) {
    return Status(StatusCode::Malformed, "duplicate object key in canonical document");
  }
  object_.insert(it, Member{std::string(key), std::move(value)});
  return ok_status();
}

bool operator==(const Value& lhs, const Value& rhs) noexcept {
  if (lhs.kind_ != rhs.kind_) {
    return false;
  }
  switch (lhs.kind_) {
    case Value::Kind::Null:
      return true;
    case Value::Kind::Boolean:
      return lhs.boolean_ == rhs.boolean_;
    case Value::Kind::Integer:
      return lhs.integer_ == rhs.integer_;
    case Value::Kind::Unsigned:
      return lhs.unsigned_ == rhs.unsigned_;
    case Value::Kind::Real:
      return std::bit_cast<std::uint64_t>(lhs.real_) == std::bit_cast<std::uint64_t>(rhs.real_);
    case Value::Kind::Text:
      return lhs.text_ == rhs.text_;
    case Value::Kind::Binary:
      return lhs.binary_ == rhs.binary_;
    case Value::Kind::Array:
      return lhs.array_ == rhs.array_;
    case Value::Kind::Object:
      return lhs.object_ == rhs.object_;
  }
  return false;
}

namespace {

void render_json(const Value& value, std::string& out, std::uint32_t depth) {
  constexpr std::uint32_t kRenderDepthLimit = 32;
  if (depth > kRenderDepthLimit) {
    out += "\"<depth-limit>\"";
    return;
  }
  switch (value.kind()) {
    case Value::Kind::Null:
      out += "null";
      break;
    case Value::Kind::Boolean:
      out += value.as_boolean() ? "true" : "false";
      break;
    case Value::Kind::Integer:
      out += std::to_string(value.as_integer());
      break;
    case Value::Kind::Unsigned:
      out += std::to_string(value.as_unsigned());
      break;
    case Value::Kind::Real: {
      const double number = value.as_real();
      if (!std::isfinite(number)) {
        out += "null";
        break;
      }
      char buffer[40];
      const int written = std::snprintf(buffer, sizeof(buffer), "%.17g", number);
      if (written > 0) {
        out.append(buffer, static_cast<std::size_t>(written));
      }
      break;
    }
    case Value::Kind::Text:
      append_json_string(out, value.as_text());
      break;
    case Value::Kind::Binary: {
      static constexpr char kHex[] = "0123456789abcdef";
      out += "\"0x";
      for (const std::byte raw : value.as_binary()) {
        const auto byte = std::to_integer<unsigned char>(raw);
        out.push_back(kHex[(byte >> 4u) & 0x0fu]);
        out.push_back(kHex[byte & 0x0fu]);
      }
      out += "\"";
      break;
    }
    case Value::Kind::Array: {
      out.push_back('[');
      bool first = true;
      for (const Value& element : value.as_array()) {
        if (!first) {
          out.push_back(',');
        }
        first = false;
        render_json(element, out, depth + 1);
      }
      out.push_back(']');
      break;
    }
    case Value::Kind::Object: {
      out.push_back('{');
      bool first = true;
      for (const Value::Member& member : value.as_object()) {
        if (!first) {
          out.push_back(',');
        }
        first = false;
        append_json_string(out, member.key);
        out.push_back(':');
        render_json(member.value, out, depth + 1);
      }
      out.push_back('}');
      break;
    }
  }
}

}  // namespace

std::string Value::to_json() const {
  std::string out;
  render_json(*this, out, 0);
  return out;
}

// ---------------------------------------------------------------------------
// CanonicalWriter
// ---------------------------------------------------------------------------

void CanonicalWriter::null_value() { append_byte(buffer_, kTagNull); }

void CanonicalWriter::boolean(bool value) { append_byte(buffer_, value ? kTagTrue : kTagFalse); }

void CanonicalWriter::integer(std::int64_t value) {
  append_byte(buffer_, kTagInteger);
  append_varint(buffer_, zigzag_encode(value));
}

void CanonicalWriter::unsigned_integer(std::uint64_t value) {
  append_byte(buffer_, kTagUnsigned);
  append_varint(buffer_, value);
}

void CanonicalWriter::real(double value) {
  if (std::isnan(value)) {
    // NaN has no canonical encoding; the reader refuses it, so the writer must
    // not pretend it wrote one.
    failed_ = true;
    return;
  }
  append_byte(buffer_, kTagReal);
  const std::uint64_t bits = std::bit_cast<std::uint64_t>(value);
  for (std::size_t i = 0; i < 8; ++i) {
    append_byte(buffer_, static_cast<std::uint8_t>((bits >> (8u * i)) & 0xffu));
  }
}

void CanonicalWriter::text(std::string_view value) {
  if (!is_valid_utf8(value)) {
    failed_ = true;
    return;
  }
  append_byte(buffer_, kTagText);
  append_varint(buffer_, static_cast<std::uint64_t>(value.size()));
  const auto* raw = reinterpret_cast<const std::byte*>(value.data());
  buffer_.insert(buffer_.end(), raw, raw + value.size());
}

void CanonicalWriter::binary(std::span<const std::byte> value) {
  append_byte(buffer_, kTagBinary);
  append_varint(buffer_, static_cast<std::uint64_t>(value.size()));
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void CanonicalWriter::begin_array(std::uint64_t count) {
  append_byte(buffer_, kTagArray);
  append_varint(buffer_, count);
}

void CanonicalWriter::end_array() {}

void CanonicalWriter::begin_object(std::uint64_t count) {
  append_byte(buffer_, kTagObject);
  append_varint(buffer_, count);
}

void CanonicalWriter::end_object() {}

void CanonicalWriter::field(std::string_view key) {
  if (key.empty()) {
    failed_ = true;
    return;
  }
  text(key);
}

void CanonicalWriter::write_value(const Value& value) {
  switch (value.kind()) {
    case Value::Kind::Null:
      null_value();
      break;
    case Value::Kind::Boolean:
      boolean(value.as_boolean());
      break;
    case Value::Kind::Integer:
      integer(value.as_integer());
      break;
    case Value::Kind::Unsigned:
      unsigned_integer(value.as_unsigned());
      break;
    case Value::Kind::Real:
      real(value.as_real());
      break;
    case Value::Kind::Text:
      text(value.as_text());
      break;
    case Value::Kind::Binary:
      binary(value.as_binary());
      break;
    case Value::Kind::Array:
      begin_array(static_cast<std::uint64_t>(value.as_array().size()));
      for (const Value& element : value.as_array()) {
        write_value(element);
      }
      end_array();
      break;
    case Value::Kind::Object:
      begin_object(static_cast<std::uint64_t>(value.as_object().size()));
      for (const Value::Member& member : value.as_object()) {
        field(member.key);
        write_value(member.value);
      }
      end_object();
      break;
  }
}

Digest CanonicalWriter::digest() const {
  // A writer that failed carries no identity: the digest of a partial document
  // would be a stable name for something that cannot be decoded.
  return failed_ ? Digest::zero() : sha256(buffer_);
}

// ---------------------------------------------------------------------------
// CanonicalReader
// ---------------------------------------------------------------------------

CanonicalReader::CanonicalReader(std::span<const std::byte> data, CanonicalLimits limits)
    : data_(data), limits_(limits) {}

CanonicalReader::CanonicalReader(const std::vector<std::byte>& data, CanonicalLimits limits)
    : data_(data), limits_(limits) {}

Status CanonicalReader::read_tag(std::uint8_t& tag) {
  if (data_.size() > limits_.max_document_bytes) {
    return Status(StatusCode::CapacityExceeded, "canonical document exceeds the configured byte limit");
  }
  if (position_ >= data_.size()) {
    return Status(StatusCode::Corrupt, "canonical document is truncated");
  }
  tag = std::to_integer<std::uint8_t>(data_[position_]);
  ++position_;
  return ok_status();
}

Status CanonicalReader::read_varint(std::uint64_t& out) {
  std::uint64_t value = 0;
  std::uint32_t shift = 0;
  std::size_t used = 0;
  while (true) {
    if (position_ >= data_.size()) {
      return Status(StatusCode::Corrupt, "canonical varint is truncated");
    }
    const auto byte = std::to_integer<std::uint8_t>(data_[position_]);
    ++position_;
    ++used;
    if (shift > 63u) {
      return Status(StatusCode::Malformed, "canonical varint overflows 64 bits");
    }
    if (shift == 63u && (byte & 0x7eu) != 0u) {
      // The final byte of a 10-byte varint may only carry bit 63. Letting the
      // other bits shift out would make several distinct byte strings decode to
      // the same value, which is exactly the canonical uniqueness this codec
      // exists to guarantee.
      return Status(StatusCode::Malformed, "canonical varint overflows 64 bits");
    }
    value |= static_cast<std::uint64_t>(byte & 0x7fu) << shift;
    if ((byte & 0x80u) == 0u) {
      break;
    }
    shift += 7u;
    if (used >= 10u) {
      return Status(StatusCode::Malformed, "canonical varint is longer than 10 bytes");
    }
  }
  if (used > 1 && (value >> (7u * (used - 1))) == 0u) {
    return Status(StatusCode::Malformed, "canonical varint is not minimally encoded");
  }
  out = value;
  return ok_status();
}

Status CanonicalReader::read_length(std::uint64_t& out, std::uint64_t max_allowed, std::string_view what) {
  std::uint64_t value = 0;
  TRXREG_TRY(read_varint(value));
  if (value > max_allowed) {
    return Status(StatusCode::CapacityExceeded, std::string(what) + " exceeds the configured limit");
  }
  out = value;
  return ok_status();
}

Status CanonicalReader::read_bytes_exact(std::uint64_t count, std::span<const std::byte>& out) {
  const std::uint64_t available = static_cast<std::uint64_t>(data_.size() - position_);
  if (count > available) {
    return Status(StatusCode::Corrupt, "canonical payload is truncated");
  }
  const auto length = static_cast<std::size_t>(count);
  out = data_.subspan(position_, length);
  position_ += length;
  return ok_status();
}

Result<Value> CanonicalReader::read_value() { return read_value_at_depth(0); }

Result<Value> CanonicalReader::read_document() {
  TRXREG_TRY_ASSIGN(value, read_value_at_depth(0));
  if (!at_end()) {
    return make_error(StatusCode::Malformed, "trailing bytes after the canonical document");
  }
  return value;
}

Result<Value> CanonicalReader::read_value_at_depth(std::uint64_t depth) {
  if (depth > limits_.max_depth) {
    return make_error(StatusCode::CapacityExceeded, "canonical document nesting exceeds the configured depth");
  }
  if (nodes_ >= limits_.max_nodes) {
    return make_error(StatusCode::CapacityExceeded, "canonical document exceeds the configured node budget");
  }
  ++nodes_;

  std::uint8_t tag = 0;
  TRXREG_TRY(read_tag(tag));
  switch (tag) {
    case kTagNull:
      return Value::null();
    case kTagFalse:
      return Value::boolean(false);
    case kTagTrue:
      return Value::boolean(true);
    case kTagInteger: {
      std::uint64_t raw = 0;
      TRXREG_TRY(read_varint(raw));
      return Value::integer(zigzag_decode(raw));
    }
    case kTagUnsigned: {
      std::uint64_t raw = 0;
      TRXREG_TRY(read_varint(raw));
      return Value::unsigned_integer(raw);
    }
    case kTagReal: {
      std::uint64_t bits = 0;
      for (std::size_t i = 0; i < 8; ++i) {
        if (position_ >= data_.size()) {
          return make_error(StatusCode::Corrupt, "canonical real is truncated");
        }
        bits |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data_[position_])) << (8u * i);
        ++position_;
      }
      const double number = std::bit_cast<double>(bits);
      if (std::isnan(number)) {
        return make_error(StatusCode::Malformed, "canonical real must not be NaN");
      }
      return Value::real(number);
    }
    case kTagText: {
      std::uint64_t length = 0;
      TRXREG_TRY(read_length(length, limits_.max_string_bytes, "canonical text"));
      std::span<const std::byte> raw;
      TRXREG_TRY(read_bytes_exact(length, raw));
      std::string text(reinterpret_cast<const char*>(raw.data()), raw.size());
      if (!is_valid_utf8(text)) {
        return make_error(StatusCode::Malformed, "canonical text is not valid UTF-8");
      }
      return Value::text(std::move(text));
    }
    case kTagBinary: {
      std::uint64_t length = 0;
      TRXREG_TRY(read_length(length, limits_.max_binary_bytes, "canonical binary"));
      std::span<const std::byte> raw;
      TRXREG_TRY(read_bytes_exact(length, raw));
      return Value::binary(Value::Binary(raw.begin(), raw.end()));
    }
    case kTagArray: {
      std::uint64_t count = 0;
      TRXREG_TRY(read_length(count, limits_.max_elements, "canonical array"));
      Value::Array elements;
      for (std::uint64_t i = 0; i < count; ++i) {
        TRXREG_TRY_ASSIGN(element, read_value_at_depth(depth + 1));
        elements.push_back(std::move(element));
      }
      return Value::array(std::move(elements));
    }
    case kTagObject: {
      std::uint64_t count = 0;
      TRXREG_TRY(read_length(count, limits_.max_object_fields, "canonical object"));
      Value object = Value::object({});
      std::string previous_key;
      bool has_previous = false;
      for (std::uint64_t i = 0; i < count; ++i) {
        if (nodes_ >= limits_.max_nodes) {
          return make_error(StatusCode::CapacityExceeded, "canonical document exceeds the configured node budget");
        }
        ++nodes_;
        std::uint8_t key_tag = 0;
        TRXREG_TRY(read_tag(key_tag));
        if (key_tag != kTagText) {
          return make_error(StatusCode::Malformed, "canonical object key must be a text value");
        }
        std::uint64_t key_length = 0;
        TRXREG_TRY(read_length(key_length, limits_.max_string_bytes, "canonical object key"));
        std::span<const std::byte> key_raw;
        TRXREG_TRY(read_bytes_exact(key_length, key_raw));
        std::string key(reinterpret_cast<const char*>(key_raw.data()), key_raw.size());
        if (!is_valid_utf8(key)) {
          return make_error(StatusCode::Malformed, "canonical object key is not valid UTF-8");
        }
        if (key.empty()) {
          return make_error(StatusCode::Malformed, "canonical object key must not be empty");
        }
        if (has_previous && compare_bytes(previous_key, key) >= 0) {
          return make_error(StatusCode::Malformed, "canonical object keys must be unique and sorted");
        }
        previous_key = key;
        has_previous = true;
        TRXREG_TRY_ASSIGN(member_value, read_value_at_depth(depth + 1));
        TRXREG_TRY(object.set_unique(key, std::move(member_value)));
      }
      return object;
    }
    default:
      return make_error(StatusCode::Malformed, "unknown canonical tag byte");
  }
}

CanonicalLimits CanonicalLimits::request() noexcept {
  CanonicalLimits limits;
  limits.max_document_bytes = 256u << 10;
  limits.max_string_bytes = 16u << 10;
  limits.max_binary_bytes = 64u << 10;
  limits.max_elements = 8192;
  limits.max_object_fields = 512;
  limits.max_depth = 12;
  limits.max_nodes = 16384;
  return limits;
}

CanonicalLimits CanonicalLimits::snapshot() noexcept {
  CanonicalLimits limits;
  limits.max_document_bytes = 64u << 20;
  limits.max_string_bytes = 64u << 10;
  limits.max_binary_bytes = 1u << 20;
  limits.max_elements = 1u << 20;
  limits.max_object_fields = 65536;
  limits.max_depth = 24;
  limits.max_nodes = 4u << 20;
  return limits;
}

}  // namespace trxreg
