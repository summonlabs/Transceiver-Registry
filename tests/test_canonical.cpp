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

// Canonical encoding and digest primitives.
//
// The canonical form is the identity of a value: the same logical value must
// always produce the same bytes, every kind must survive a round trip, and a
// document that is truncated, non-canonical, or over budget must be refused
// with the right classification. These tests pin the order independence, the
// round trip over every kind, the SHA-256 and CRC-32C known answers, the strict
// rejection paths, the resource bounds, and UTF-8 well-formedness.
//
// The tag bytes and the kind enumeration are private to the library, so this
// file observes them from the writer instead of assuming their values: adding a
// kind must extend the format, not break the tests that pin it.

#include "test_support.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/result.hpp"

namespace {

using trxreg::CanonicalLimits;
using trxreg::CanonicalReader;
using trxreg::CanonicalWriter;
using trxreg::Digest;
using trxreg::StatusCode;
using trxreg::Value;
using trxreg::test::Random;

using Bytes = std::vector<std::byte>;

/// The library gained an unsigned 64-bit integer kind while this suite was
/// being written. Detecting it keeps every kind covered when it is present and
/// still compiles if it is ever absent.
template <class T>
concept HasUnsignedInteger = requires(std::uint64_t value) { T::unsigned_integer(value); };

/// Kind counts derived from the enum itself: the scalar kinds come first and the
/// two container kinds close the list.
constexpr std::size_t kScalarKinds = static_cast<std::size_t>(Value::Kind::Array);
constexpr std::size_t kAllKinds = static_cast<std::size_t>(Value::Kind::Object) + 1u;
static_assert(kAllKinds <= 16, "the kind-coverage bitmap is too small for this Value::Kind");

/// One round-trip case with a label for the failure message.
struct RoundTripCase {
  std::string what;
  Value value;
};

/// Hand-built document bytes. Used only for encodings the writer must never
/// produce and the reader must therefore reject.
Bytes document(std::initializer_list<int> values) {
  Bytes out;
  out.reserve(values.size());
  for (const int value : values) {
    out.push_back(static_cast<std::byte>(value & 0xff));
  }
  return out;
}

/// Canonical bytes for a value.
Bytes encode(const Value& value) {
  CanonicalWriter writer;
  writer.write_value(value);
  return std::move(writer).take();
}

std::string hex_of(const Bytes& data) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (const std::byte raw : data) {
    const auto value = std::to_integer<unsigned>(raw);
    out.push_back(kDigits[static_cast<std::size_t>((value >> 4u) & 0x0fu)]);
    out.push_back(kDigits[static_cast<std::size_t>(value & 0x0fu)]);
  }
  return out;
}

std::string hex_of_text(std::string_view text) {
  Bytes data;
  data.reserve(text.size());
  for (const char ch : text) {
    data.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
  }
  return hex_of(data);
}

/// The tag byte the writer uses for this value's kind.
std::uint8_t tag_of(const Value& value) {
  const Bytes encoded = encode(value);
  CHECK(!encoded.empty());
  return encoded.empty() ? std::uint8_t{0} : std::to_integer<std::uint8_t>(encoded.front());
}

/// Decode a whole document and name the classification using the library's own
/// rendering, e.g. "ok" or "corrupt".
std::string_view status_of(const Bytes& data, const CanonicalLimits& limits) {
  CanonicalReader reader(data, limits);
  const auto decoded = reader.read_document();
  return decoded.ok() ? trxreg::to_string(StatusCode::Ok) : trxreg::to_string(decoded.error().code);
}

/// Arrays nested "depth" deep; the innermost is empty. The root sits at depth 0.
Value nested_arrays(int depth) {
  Value value = Value::array({});
  for (int level = 1; level < depth; ++level) {
    value = Value::array({std::move(value)});
  }
  return value;
}

Value array_with_elements(std::size_t count) {
  Value::Array elements;
  elements.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    elements.push_back(Value::integer(static_cast<std::int64_t>(index)));
  }
  return Value::array(std::move(elements));
}

Value object_with_fields(std::size_t count) {
  Value object = Value::object({});
  for (std::size_t index = 0; index < count; ++index) {
    const bool inserted = object.set("k" + std::to_string(index), Value::integer(static_cast<std::int64_t>(index)));
    CHECK(inserted);
  }
  return object;
}

/// Append unsigned prototypes when the library models that kind.
template <class T>
void add_unsigned_scalars(std::vector<Value>& pool) {
  if constexpr (HasUnsignedInteger<T>) {
    pool.push_back(T::unsigned_integer(0));
    pool.push_back(T::unsigned_integer(std::uint64_t{1} << 63));
    pool.push_back(T::unsigned_integer(std::numeric_limits<std::uint64_t>::max()));
  }
}

/// Scalar prototypes: at least one value of every scalar kind.
std::vector<Value> scalar_pool() {
  std::vector<Value> pool;
  pool.push_back(Value::null());
  pool.push_back(Value::boolean(false));
  pool.push_back(Value::boolean(true));
  pool.push_back(Value::integer(0));
  pool.push_back(Value::integer(-1));
  pool.push_back(Value::integer(std::numeric_limits<std::int64_t>::min()));
  pool.push_back(Value::integer(std::numeric_limits<std::int64_t>::max()));
  pool.push_back(Value::integer(-(std::int64_t{1} << 40)));
  pool.push_back(Value::real(0.0));
  pool.push_back(Value::real(-0.0));
  pool.push_back(Value::real(3.141592653589793));
  pool.push_back(Value::real(std::numeric_limits<double>::denorm_min()));
  pool.push_back(Value::text(""));
  pool.push_back(Value::text("ascii text"));
  pool.push_back(Value::text("h\xc3\xa9llo \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80"));
  pool.push_back(Value::binary(Value::Binary{}));
  pool.push_back(Value::binary(Value::Binary{std::byte{0x00}, std::byte{0xff}, std::byte{0x7f}}));
  add_unsigned_scalars<Value>(pool);
  return pool;
}

/// Deterministic random value of bounded depth, drawn from the scalar pool so
/// every scalar kind stays reachable. Containers are only built above depth 0.
Value random_value(Random& random, int depth, const std::vector<Value>& scalars, std::array<bool, 16>& seen) {
  if (depth > 0 && random.below(3) == 0) {
    if (random.boolean()) {
      seen[static_cast<std::size_t>(Value::Kind::Array)] = true;
      Value::Array elements;
      const std::uint64_t count = random.below(5);
      for (std::uint64_t index = 0; index < count; ++index) {
        elements.push_back(random_value(random, depth - 1, scalars, seen));
      }
      return Value::array(std::move(elements));
    }
    seen[static_cast<std::size_t>(Value::Kind::Object)] = true;
    Value object = Value::object({});
    const std::uint64_t count = random.below(5);
    for (std::uint64_t index = 0; index < count; ++index) {
      // set() replaces, so a repeated key simply collapses: the object stays canonical.
      const bool inserted =
          object.set("key" + std::to_string(random.below(1000)), random_value(random, depth - 1, scalars, seen));
      CHECK(inserted);
    }
    return object;
  }
  const Value value = scalars[static_cast<std::size_t>(random.below(static_cast<std::uint64_t>(scalars.size())))];
  seen[static_cast<std::size_t>(value.kind())] = true;
  return value;
}

/// Round-trip cases for the unsigned kind, when the library models it.
template <class T>
void add_unsigned_cases(std::vector<RoundTripCase>& cases) {
  if constexpr (HasUnsignedInteger<T>) {
    cases.push_back(RoundTripCase{"unsigned zero", T::unsigned_integer(0)});
    cases.push_back(RoundTripCase{"unsigned 2^63", T::unsigned_integer(std::uint64_t{1} << 63)});
    cases.push_back(RoundTripCase{"unsigned maximum", T::unsigned_integer(std::numeric_limits<std::uint64_t>::max())});
  }
}

}  // namespace

// The encoding is a function of the logical value, not of the order in which
// the members happened to be inserted.
TRXREG_TEST(canonical_encoding_is_order_independent) {
  const std::vector<std::pair<std::string, Value>> members = {
      {"b", Value::integer(-17)},
      {"a", Value::text("alpha")},
      {"Z", Value::boolean(true)},
      {"aa", Value::array({Value::null(), Value::real(0.5)})},
      {"A0", Value::text("caf\xc3\xa9")},  // U+00E9, two bytes
  };
  const std::vector<std::vector<std::size_t>> orders = {
      {0, 1, 2, 3, 4},
      {4, 3, 2, 1, 0},
      {2, 0, 4, 1, 3},
      {1, 2, 3, 4, 0},
  };

  const auto build_with_set = [&members](const std::vector<std::size_t>& order) {
    Value object = Value::object({});
    for (const std::size_t index : order) {
      const bool inserted = object.set(members[index].first, members[index].second);
      CHECK(inserted);
    }
    return object;
  };
  const auto build_with_object = [&members](const std::vector<std::size_t>& order) {
    Value::Object list;
    list.reserve(order.size());
    for (const std::size_t index : order) {
      list.push_back(Value::Member{members[index].first, members[index].second});
    }
    return Value::object(std::move(list));
  };

  const Value reference = build_with_set(orders[0]);
  const Bytes reference_bytes = encode(reference);
  for (const std::vector<std::size_t>& order : orders) {
    const Value via_set = build_with_set(order);
    const Value via_object = build_with_object(order);
    CHECK(via_set == reference);     // equality is order independent ...
    CHECK(via_object == reference);  // ... for both construction paths ...
    CHECK_EQ(hex_of(encode(via_set)), hex_of(reference_bytes));     // ... and so are the bytes.
    CHECK_EQ(hex_of(encode(via_object)), hex_of(reference_bytes));
  }

  // Canonical order is byte-lexicographic: uppercase sorts before lowercase and
  // a prefix sorts before its extension.
  REQUIRE_EQ(reference.as_object().size(), std::size_t{5});
  const std::vector<std::string> expected_keys = {"A0", "Z", "a", "aa", "b"};
  for (std::size_t index = 0; index < expected_keys.size(); ++index) {
    CHECK_EQ(reference.as_object()[index].key, expected_keys[index]);
  }
  const Value* nested = reference.find("aa");
  REQUIRE(nested != nullptr);
  CHECK(nested->is_array());
  CHECK_EQ(nested->as_array().size(), std::size_t{2});
  CHECK(reference.find("missing") == nullptr);

  // Writing the same value twice (clearing in between) produces the same bytes.
  CanonicalWriter writer;
  writer.write_value(reference);
  const Bytes first = writer.bytes();
  writer.clear();
  writer.write_value(reference);
  CHECK_EQ(hex_of(writer.bytes()), hex_of(first));
  CHECK_EQ(hex_of(first), hex_of(reference_bytes));
}

// Every kind survives encode -> decode -> encode unchanged.
TRXREG_TEST(canonical_round_trip_all_kinds) {
  const CanonicalLimits limits = CanonicalLimits::snapshot();

  const auto round_trip = [&limits](const Value& original, const std::string& what) {
    const Bytes encoded = encode(original);
    CanonicalReader reader(encoded, limits);
    const auto decoded = reader.read_document();
    if (!decoded.ok()) {
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     "round trip failed for " + what + ": " +
                                         std::string(trxreg::to_string(decoded.error().code)) + ": " +
                                         decoded.error().message);
      return;
    }
    if (!(decoded.value() == original)) {
      ::trxreg::test::report_failure(__FILE__, __LINE__, "round trip changed the value for " + what +
                                                             ": decoded=" + decoded.value().to_json() +
                                                             " original=" + original.to_json());
      return;
    }
    CanonicalWriter writer;
    writer.write_value(decoded.value());
    if (hex_of(writer.bytes()) != hex_of(encoded)) {
      ::trxreg::test::report_failure(__FILE__, __LINE__, "re-encoding differs for " + what + ": first=" +
                                                             hex_of(encoded) + " second=" + hex_of(writer.bytes()));
    }
  };

  Value::Binary all_bytes;
  for (int value = 0; value < 256; ++value) {
    all_bytes.push_back(static_cast<std::byte>(value));
  }

  Value deep = Value::null();
  for (int level = 0; level < 12; ++level) {
    deep = Value::array({std::move(deep)});
  }

  Value nested_object = Value::object({});
  const bool inner_inserted = nested_object.set(
      "inner", Value::object({{"x", Value::integer(1)}, {"y", Value::array({Value::text("z")})}}));
  CHECK(inner_inserted);

  Value mixed = Value::object({});
  CHECK(mixed.set("array", Value::array({Value::null(), Value::boolean(false), Value::integer(-5), Value::real(2.5),
                                         Value::text("text")})));
  CHECK(mixed.set("binary", Value::binary(all_bytes)));
  CHECK(mixed.set("empty_array", Value::array({})));
  CHECK(mixed.set("empty_object", Value::object({})));
  CHECK(mixed.set("object", nested_object));
  CHECK(mixed.set("deep", Value::array({deep})));
  CHECK(mixed.set("wide", array_with_elements(300)));
  CHECK(mixed.set("keys", object_with_fields(100)));

  std::vector<RoundTripCase> cases = {
      {"null", Value::null()},
      {"boolean true", Value::boolean(true)},
      {"boolean false", Value::boolean(false)},
      {"integer zero", Value::integer(0)},
      {"integer -1", Value::integer(-1)},
      {"integer minimum", Value::integer(std::numeric_limits<std::int64_t>::min())},
      {"integer maximum", Value::integer(std::numeric_limits<std::int64_t>::max())},
      {"integer -2^40", Value::integer(-(std::int64_t{1} << 40))},
      {"real zero", Value::real(0.0)},
      {"real negative zero", Value::real(-0.0)},
      {"real pi", Value::real(3.141592653589793)},
      {"real maximum", Value::real(std::numeric_limits<double>::max())},
      {"real denormal minimum", Value::real(std::numeric_limits<double>::denorm_min())},
      {"real infinity", Value::real(std::numeric_limits<double>::infinity())},
      {"real negative infinity", Value::real(-std::numeric_limits<double>::infinity())},
      {"empty text", Value::text("")},
      {"ascii text", Value::text("hello, world")},
      {"text with embedded NUL", Value::text(std::string("a\0b", 3))},
      {"multi-byte UTF-8 text", Value::text("h\xc3\xa9llo \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80")},
      {"long text", Value::text(std::string(300, 'x'))},
      {"empty binary", Value::binary(Value::Binary{})},
      {"binary bytes", Value::binary(Value::Binary{std::byte{0x00}, std::byte{0xff}, std::byte{0x7f}})},
      {"binary all byte values", Value::binary(all_bytes)},
      {"empty array", Value::array({})},
      {"empty object", Value::object({})},
      {"nested arrays and objects", nested_object},
      {"200-element array", array_with_elements(200)},
      {"mixed document", mixed},
  };
  add_unsigned_cases<Value>(cases);
  for (const RoundTripCase& item : cases) {
    round_trip(item.value, item.what);
  }
  // The mixed document really does carry the 256-byte binary plus everything else.
  CHECK(encode(mixed).size() > all_bytes.size());
}

// The digest is the identity of the canonical bytes: stable under insertion
// order and repetition, different as soon as one member changes.
TRXREG_TEST(canonical_digest_identity) {
  Value first = Value::object({});
  CHECK(first.set("a", Value::integer(1)));
  CHECK(first.set("b", Value::text("two")));
  CHECK(first.set("c", Value::boolean(true)));

  Value second = Value::object({});
  CHECK(second.set("c", Value::boolean(true)));
  CHECK(second.set("b", Value::text("two")));
  CHECK(second.set("a", Value::integer(1)));

  CHECK(first == second);
  CHECK_EQ(hex_of(encode(first)), hex_of(encode(second)));

  const Digest digest = trxreg::sha256(encode(first));
  CHECK_EQ(digest.to_hex(), trxreg::sha256(encode(second)).to_hex());
  CHECK_EQ(digest.to_hex(), trxreg::sha256(encode(first)).to_hex());  // stable when recomputed
  CHECK(!digest.is_zero());
  CHECK(Digest::zero().is_zero());

  // CanonicalWriter::digest() hashes exactly the bytes the writer produced.
  CanonicalWriter writer;
  writer.write_value(first);
  CHECK_EQ(writer.digest().to_hex(), digest.to_hex());
  CHECK_EQ(writer.digest().to_hex(), trxreg::sha256(writer.bytes()).to_hex());

  // One changed value, one changed key, or one changed kind changes the digest.
  Value changed_value = first;
  CHECK(changed_value.set("b", Value::text("three")));
  CHECK_NE(trxreg::sha256(encode(changed_value)).to_hex(), digest.to_hex());

  Value renamed = Value::object({});
  CHECK(renamed.set("a", Value::integer(1)));
  CHECK(renamed.set("bb", Value::text("two")));
  CHECK(renamed.set("c", Value::boolean(true)));
  CHECK_NE(trxreg::sha256(encode(renamed)).to_hex(), digest.to_hex());

  // Integer 1 and real 1.0 are different values and must not share a digest.
  Value retyped = Value::object({});
  CHECK(retyped.set("a", Value::real(1.0)));
  CHECK(retyped.set("b", Value::text("two")));
  CHECK(retyped.set("c", Value::boolean(true)));
  CHECK_NE(trxreg::sha256(encode(retyped)).to_hex(), digest.to_hex());

  // to_hex/from_hex round trip.
  const std::string hex = digest.to_hex();
  CHECK_EQ(hex.size(), std::size_t{64});
  const auto parsed = Digest::from_hex(hex);
  REQUIRE_OK(parsed);
  CHECK(parsed.value() == digest);

  // from_hex accepts uppercase and to_hex always renders lowercase.
  const auto uppercase = Digest::from_hex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
  REQUIRE_OK(uppercase);
  CHECK_EQ(uppercase.value().to_hex(), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

  // Wrong shapes and non-hex characters are InvalidArgument.
  const auto expect_invalid = [](const std::string& text) {
    const auto rejected = Digest::from_hex(text);
    if (rejected.ok()) {
      ::trxreg::test::report_failure(__FILE__, __LINE__, "digest hex was accepted: '" + text + "'");
      return;
    }
    if (rejected.error().code != StatusCode::InvalidArgument) {
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     "digest hex was rejected as " +
                                         std::string(trxreg::to_string(rejected.error().code)) + ", not InvalidArgument");
    }
  };
  expect_invalid("");
  expect_invalid(std::string(63, 'a'));  // one character short
  expect_invalid(std::string(65, 'a'));  // one character long
  std::string non_hex(64, 'a');
  non_hex[17] = 'z';
  expect_invalid(non_hex);
  std::string spaced(64, 'a');
  spaced[0] = ' ';
  expect_invalid(spaced);
}

// FIPS 180-4 known answers, including the streaming path.
TRXREG_TEST(canonical_sha256_known_answers) {
  CHECK_EQ(trxreg::sha256(std::string_view{}).to_hex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CHECK_EQ(trxreg::sha256(std::string_view{"abc"}).to_hex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ(trxreg::sha256(std::string_view{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"}).to_hex(),
           std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

  // One million 'a', once in a single call and once through many small updates.
  const std::string million(1000000, 'a');
  const std::string single = trxreg::sha256(std::string_view{million}).to_hex();
  CHECK_EQ(single, std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

  trxreg::Sha256 streamed;
  const std::size_t chunks[] = {1, 7, 63, 64, 65, 127, 1000, 4096};
  const std::size_t chunk_count = sizeof(chunks) / sizeof(chunks[0]);
  std::size_t index = 0;
  for (std::size_t position = 0; position < million.size();) {
    std::size_t take = chunks[index % chunk_count];
    if (take > million.size() - position) {
      take = million.size() - position;
    }
    streamed.update(million.data() + position, take);
    position += take;
    ++index;
  }
  const std::string streamed_hex = streamed.finish().to_hex();
  CHECK_EQ(streamed_hex, single);
  CHECK_EQ(streamed_hex, std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

  // Byte-at-a-time streaming agrees with the single call across both padding
  // boundaries (55/56 and 63/64 bytes).
  for (std::size_t length = 0; length <= 130; ++length) {
    const std::string text(length, 'q');
    trxreg::Sha256 bytewise;
    for (std::size_t position = 0; position < text.size(); ++position) {
      bytewise.update(text.data() + position, 1);
    }
    CHECK_EQ(bytewise.finish().to_hex(), trxreg::sha256(std::string_view{text}).to_hex());
  }
}

// CRC-32C known answers, including how the seed composes.
TRXREG_TEST(canonical_crc32c_known_answers) {
  CHECK_EQ(trxreg::crc32c(std::string_view{"123456789"}), 0xE3069283u);
  CHECK_EQ(trxreg::crc32c(std::string_view{}), 0u);

  // Order sensitivity: a CRC is not a sum, so swapping two bytes changes it.
  CHECK_EQ(trxreg::crc32c(std::string_view{"ab"}), 0xE2A22936u);
  CHECK_EQ(trxreg::crc32c(std::string_view{"ba"}), 0xC515725Bu);
  CHECK_NE(trxreg::crc32c(std::string_view{"ab"}), trxreg::crc32c(std::string_view{"ba"}));

  // The string_view is spelled explicitly because a seeded call with a literal
  // is ambiguous between the (const void*, size_t, uint32_t) and
  // (std::string_view, uint32_t) overloads.
  //
  // The seed is the previously returned CRC, not a raw internal state: the
  // implementation complements the seed on entry (~seed) and the state on exit,
  // so the public value composes exactly like a running CRC and a stream can be
  // folded in pieces. Observed: crc32c("bc", crc32c("a")) == crc32c("abc") ==
  // 0x364B3FB7, and the same holds for any other split of the same bytes.
  CHECK_EQ(trxreg::crc32c(std::string_view{"a"}), 0xC1D04330u);
  CHECK_EQ(trxreg::crc32c(std::string_view{"abc"}), 0x364B3FB7u);
  CHECK_EQ(trxreg::crc32c(std::string_view{"bc"}, trxreg::crc32c(std::string_view{"a"})), 0x364B3FB7u);
  CHECK_EQ(trxreg::crc32c(std::string_view{"c"}, trxreg::crc32c(std::string_view{"ab"})), 0x364B3FB7u);
  CHECK_EQ(trxreg::crc32c(std::string_view{"abc"}, trxreg::crc32c(std::string_view{})), 0x364B3FB7u);

  // The byte-range overload checksums the same bytes as the text overload.
  CHECK_EQ(trxreg::crc32c(document({0x61, 0x62, 0x63})), 0x364B3FB7u);
}

// Truncation is Corrupt, a non-canonical structure is Malformed, and a value
// beyond the configured limits is CapacityExceeded.
TRXREG_TEST(canonical_malformed_documents_are_rejected) {
  const CanonicalLimits limits{};

  // The tag vocabulary is private to the library, so every tag byte below is
  // observed from the writer rather than assumed.
  const std::uint8_t null_tag = tag_of(Value::null());
  const std::uint8_t integer_tag = tag_of(Value::integer(0));
  const std::uint8_t real_tag = tag_of(Value::real(0.0));
  const std::uint8_t text_tag = tag_of(Value::text(""));
  const std::uint8_t array_tag = tag_of(Value::array({}));
  const std::uint8_t object_tag = tag_of(Value::object({}));
  const std::uint8_t known_tags[] = {null_tag, integer_tag, real_tag, text_tag, array_tag, object_tag};
  bool sentinel_is_unknown = true;
  for (const std::uint8_t tag : known_tags) {
    sentinel_is_unknown = sentinel_is_unknown && tag != 0xFF;
  }
  CHECK(sentinel_is_unknown);

  // Truncations: the bytes a value needs are simply not there.
  // The integer varint ends after a continuation byte, so no value can be built.
  CHECK_EQ(status_of(document({integer_tag, 0x80}), limits), std::string_view{"corrupt"});
  // Text declares five bytes and only one is present.
  CHECK_EQ(status_of(document({text_tag, 0x05, 'a'}), limits), std::string_view{"corrupt"});
  // A real declares eight bytes and only two are present.
  CHECK_EQ(status_of(document({real_tag, 0x00, 0x00}), limits), std::string_view{"corrupt"});
  // Empty input has no tag at all.
  CHECK_EQ(status_of(document({}), limits), std::string_view{"corrupt"});
  // The array count is within the element limit, so the missing elements are a
  // truncation rather than an over-budget header.
  CHECK_EQ(status_of(document({array_tag, 0x03}), limits), std::string_view{"corrupt"});

  // Structural violations: every byte is present, but the encoding is not the
  // one canonical form of the value, so it cannot be given an identity.
  // Zero encoded in two bytes instead of one.
  CHECK_EQ(status_of(document({integer_tag, 0x80, 0x00}), limits), std::string_view{"malformed"});
  // Ten continuation bytes: no 64-bit varint can need more than ten bytes.
  CHECK_EQ(status_of(document({integer_tag, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}), limits),
           std::string_view{"malformed"});
  // Duplicate object key: rejected at the second key, before its value is read.
  CHECK_EQ(status_of(document({object_tag, 0x02, text_tag, 0x01, 'a', null_tag, text_tag, 0x01, 'a', null_tag}), limits),
           std::string_view{"malformed"});
  // Out-of-order object keys: 'b' before 'a' is not the canonical order.
  CHECK_EQ(status_of(document({object_tag, 0x02, text_tag, 0x01, 'b', null_tag, text_tag, 0x01, 'a', null_tag}), limits),
           std::string_view{"malformed"});
  // 0xC0 0x80 is the overlong two-byte encoding of U+0000.
  CHECK_EQ(status_of(document({text_tag, 0x02, 0xC0, 0x80}), limits), std::string_view{"malformed"});
  // 0xE2 0x82 is a three-byte lead plus one continuation: the third byte is missing.
  CHECK_EQ(status_of(document({text_tag, 0x02, 0xE2, 0x82}), limits), std::string_view{"malformed"});
  // 0xED 0xA0 0x80 is the UTF-16 surrogate U+D800, never valid UTF-8.
  CHECK_EQ(status_of(document({text_tag, 0x03, 0xED, 0xA0, 0x80}), limits), std::string_view{"malformed"});
  // A quiet NaN has no canonical real encoding.
  CHECK_EQ(status_of(document({real_tag, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x7F}), limits),
           std::string_view{"malformed"});
  // 0xFF is not a tag the writer can produce.
  CHECK_EQ(status_of(document({0xFF}), limits), std::string_view{"malformed"});
  // A complete document followed by one more byte is not a document.
  CHECK_EQ(status_of(document({null_tag, null_tag}), limits), std::string_view{"malformed"});

  // read_value() stops after the first value: only read_document() requires the
  // input to be exhausted, which is why the trailing byte above is Malformed.
  {
    const Bytes trailing = document({null_tag, null_tag});
    CanonicalReader reader(trailing, limits);
    const auto first_value = reader.read_value();
    REQUIRE_OK(first_value);
    CHECK(first_value.value().is_null());
    CHECK(!reader.at_end());
    CHECK_EQ(reader.remaining(), std::uint64_t{1});
  }

  // The final byte of a 10-byte varint may carry only bit 63. Accepting the
  // other bits would let 64 distinct byte strings decode to one value, so the
  // bytes of a document would no longer be a function of the value it denotes.
  {
    Bytes overflow;
    overflow.push_back(static_cast<std::byte>(integer_tag));
    for (int i = 0; i < 9; ++i) {
      overflow.push_back(static_cast<std::byte>(0xFF));
    }
    overflow.push_back(static_cast<std::byte>(0x01));
    // 0x01 as the final byte is the legitimate encoding of INT64_MIN (bit 63 set,
    // every other bit of that byte clear) and must keep decoding.
    CHECK_EQ(status_of(overflow, limits), std::string_view{"ok"});
    // Any other final byte would set bits above bit 63 and must be refused.
    const std::uint8_t variations[] = {0x02, 0x03, 0x05, 0x40, 0x7F};
    for (const std::uint8_t last : variations) {
      Bytes variant = overflow;
      variant.back() = static_cast<std::byte>(last);
      CHECK_EQ(status_of(variant, limits), std::string_view{"malformed"});
    }
  }

  // The writer refuses to pretend it encoded a value with no canonical form,
  // and the digest of such a writer is zero rather than a name for a document
  // its own reader would reject.
  {
    CanonicalWriter nan_writer;
    nan_writer.write_value(Value::real(std::numeric_limits<double>::quiet_NaN()));
    CHECK(nan_writer.failed());
    CHECK(nan_writer.digest().is_zero());

    CanonicalWriter text_writer;
    text_writer.write_value(Value::text(std::string("x\xff")));
    CHECK(text_writer.failed());

    CanonicalWriter key_writer;
    key_writer.begin_object(1);
    key_writer.field("");
    key_writer.integer(1);
    key_writer.end_object();
    CHECK(key_writer.failed());

    CanonicalWriter healthy;
    healthy.write_value(Value::integer(7));
    CHECK(!healthy.failed());
    CHECK(!healthy.digest().is_zero());
    healthy.clear();
    CHECK(!healthy.failed());
    CHECK_EQ(healthy.size(), std::uint64_t{0});
  }

  // Limit violations are classified separately: the bytes are well-formed, the
  // payload is just larger than this caller allows.
  CanonicalLimits tight = limits;
  tight.max_string_bytes = 64;
  // Length 65 is refused from the length field alone, before the payload is read.
  CHECK_EQ(status_of(document({text_tag, 0x41}), tight), std::string_view{"capacity_exceeded"});
}

// Every configured bound accepts exactly up to its limit and refuses one past
// it, and an over-budget header is refused before anything is allocated.
TRXREG_TEST(canonical_bounded_resources) {
  CanonicalLimits limits;
  limits.max_document_bytes = 1u << 16;
  limits.max_string_bytes = 64;
  limits.max_binary_bytes = 64;
  limits.max_elements = 8;
  limits.max_object_fields = 8;
  limits.max_depth = 4;
  limits.max_nodes = 64;

  // The whole document.
  {
    CanonicalLimits per_case = limits;
    per_case.max_document_bytes = 4;
    CHECK_EQ(status_of(encode(Value::text("ab")), per_case), std::string_view{"ok"});  // 4 bytes
    CHECK_EQ(status_of(encode(Value::text("abc")), per_case), std::string_view{"capacity_exceeded"});  // 5 bytes
  }
  // max_string_bytes.
  {
    CanonicalLimits per_case = limits;
    per_case.max_string_bytes = 4;
    CHECK_EQ(status_of(encode(Value::text(std::string(4, 'x'))), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(Value::text(std::string(5, 'x'))), per_case), std::string_view{"capacity_exceeded"});
  }
  // max_binary_bytes.
  {
    CanonicalLimits per_case = limits;
    per_case.max_binary_bytes = 4;
    CHECK_EQ(status_of(encode(Value::binary(Value::Binary(4))), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(Value::binary(Value::Binary(5))), per_case), std::string_view{"capacity_exceeded"});
  }
  // max_elements.
  {
    CanonicalLimits per_case = limits;
    per_case.max_elements = 4;
    CHECK_EQ(status_of(encode(array_with_elements(4)), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(array_with_elements(5)), per_case), std::string_view{"capacity_exceeded"});
  }
  // max_object_fields.
  {
    CanonicalLimits per_case = limits;
    per_case.max_object_fields = 4;
    CHECK_EQ(status_of(encode(object_with_fields(4)), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(object_with_fields(5)), per_case), std::string_view{"capacity_exceeded"});
  }
  // max_depth: the root is depth 0, so three nested arrays reach depth 2 and
  // four nested arrays reach depth 3.
  {
    CanonicalLimits per_case = limits;
    per_case.max_depth = 2;
    CHECK_EQ(status_of(encode(nested_arrays(3)), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(nested_arrays(4)), per_case), std::string_view{"capacity_exceeded"});
  }
  // max_nodes: every value counts, so two integers inside an array are 3 nodes.
  {
    CanonicalLimits per_case = limits;
    per_case.max_nodes = 3;
    CHECK_EQ(status_of(encode(array_with_elements(2)), per_case), std::string_view{"ok"});
    CHECK_EQ(status_of(encode(array_with_elements(3)), per_case), std::string_view{"capacity_exceeded"});
  }

  // A header that declares 2^40 elements is refused from the count alone. The
  // count is validated against the configured limit before a single element is
  // read and before any container is sized, so this test stays tiny instead of
  // asking for terabytes: the varint below is 2^40 (0x80 0x80 0x80 0x80 0x80 0x20).
  const Bytes huge_count = document({0x80, 0x80, 0x80, 0x80, 0x80, 0x20});
  const std::uint8_t header_tags[] = {tag_of(Value::array({})), tag_of(Value::object({})), tag_of(Value::text("")),
                                      tag_of(Value::binary(Value::Binary{}))};
  for (const std::uint8_t tag : header_tags) {
    Bytes header;
    header.push_back(static_cast<std::byte>(tag));
    header.insert(header.end(), huge_count.begin(), huge_count.end());
    CHECK_EQ(status_of(header, limits), std::string_view{"capacity_exceeded"});
  }
}

// UTF-8 well-formedness, including every boundary code point.
TRXREG_TEST(canonical_utf8_validation) {
  const auto expect_utf8 = [](std::string_view text, bool expected) {
    const bool observed = trxreg::is_valid_utf8(text);
    if (observed != expected) {
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     std::string(expected ? "is_valid_utf8 rejected " : "is_valid_utf8 accepted ") +
                                         hex_of_text(text));
    }
  };

  const std::string_view accepted[] = {
      "",                  // empty
      "ascii",             // one-byte sequences
      "~",
      "\x7f",              // U+007F, the last one-byte code point
      "\xc2\x80",          // U+0080, the first two-byte code point
      "\xdf\xbf",          // U+07FF, the last two-byte code point
      "\xe0\xa0\x80",      // U+0800, the first three-byte code point
      "\xed\x9f\xbf",      // U+D7FF, the last code point before the surrogates
      "\xee\x80\x80",      // U+E000, the first code point after the surrogates
      "\xef\xbf\xbf",      // U+FFFF, the last three-byte code point
      "\xf0\x90\x80\x80",  // U+10000, the first four-byte code point
      "\xf4\x8f\xbf\xbf",  // U+10FFFF, the last code point
      "caf\xc3\xa9",       // mixed widths in one string
  };
  for (const std::string_view text : accepted) {
    expect_utf8(text, true);
  }

  const std::string_view rejected[] = {
      "\x80",                      // continuation byte with no lead
      "\xc0\x80",                  // overlong U+0000 in two bytes
      "\xc1\xbf",                  // overlong U+007F in two bytes
      "\xe0\x80\x80",              // overlong U+0000 in three bytes
      "\xf0\x80\x80\x80",          // overlong U+0000 in four bytes
      "\xed\xa0\x80",              // U+D800, a UTF-16 surrogate
      "\xed\xbf\xbf",              // U+DFFF, the last surrogate
      "\xc2",                      // truncated two-byte sequence
      "\xe2\x82",                  // truncated three-byte sequence
      "\xf0\x9f\x98",              // truncated four-byte sequence
      "\xf8\x88\x80\x80\x80",      // five-byte lead, never valid in UTF-8
      "\xfc\x80\x80\x80\x80\x80",  // six-byte lead
      "\xfe",                      // never valid in UTF-8
      "\xff",
  };
  for (const std::string_view text : rejected) {
    expect_utf8(text, false);
  }

  // The reader applies the same predicate to object keys: 0xC0 0x80 is not a key.
  CHECK_EQ(status_of(document({tag_of(Value::object({})), 0x01, tag_of(Value::text("")), 0x02, 0xC0, 0x80,
                               tag_of(Value::null())}),
                   CanonicalLimits{}),
           std::string_view{"malformed"});
}

// Randomized round trip: random values of bounded depth must survive
// encode -> decode -> encode with identical bytes. The seed is printed so a
// failure can be reproduced exactly.
TRXREG_TEST(canonical_randomized_round_trip) {
  constexpr std::uint64_t kSeed = 0x5eed1234abcdULL;
  constexpr int kIterations = 400;
  trxreg::test::note("canonical_randomized_round_trip seed=" + std::to_string(kSeed) +
                     " iterations=" + std::to_string(kIterations));

  const CanonicalLimits limits = CanonicalLimits::snapshot();
  const std::vector<Value> scalars = scalar_pool();
  Random random(kSeed);
  std::array<bool, 16> seen{};
  std::size_t failures = 0;
  std::size_t encoded_bytes = 0;

  for (int iteration = 0; iteration < kIterations; ++iteration) {
    const Value original = random_value(random, 3, scalars, seen);
    const Bytes encoded = encode(original);
    encoded_bytes += encoded.size();

    CanonicalReader reader(encoded, limits);
    const auto decoded = reader.read_document();
    if (!decoded.ok()) {
      ++failures;
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     "iteration " + std::to_string(iteration) + ": decode failed as " +
                                         std::string(trxreg::to_string(decoded.error().code)) + ": " +
                                         decoded.error().message + " bytes=" + hex_of(encoded));
      continue;
    }
    if (!(decoded.value() == original)) {
      ++failures;
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     "iteration " + std::to_string(iteration) +
                                         ": decoded=" + decoded.value().to_json() + " original=" + original.to_json());
      continue;
    }
    CanonicalWriter writer;
    writer.write_value(decoded.value());
    if (hex_of(writer.bytes()) != hex_of(encoded)) {
      ++failures;
      ::trxreg::test::report_failure(__FILE__, __LINE__,
                                     "iteration " + std::to_string(iteration) + ": re-encoding differs: first=" +
                                         hex_of(encoded) + " second=" + hex_of(writer.bytes()));
    }
  }

  CHECK_EQ(failures, std::size_t{0});
  trxreg::test::note("canonical_randomized_round_trip encoded " + std::to_string(encoded_bytes) + " bytes");

  // The scalar pool offers at least one value of every scalar kind ...
  std::array<bool, 16> pooled{};
  for (const Value& scalar : scalars) {
    pooled[static_cast<std::size_t>(scalar.kind())] = true;
  }
  std::size_t pooled_kinds = 0;
  for (const bool present : pooled) {
    pooled_kinds += present ? 1u : 0u;
  }
  CHECK_EQ(pooled_kinds, kScalarKinds);

  // ... and the random run actually produced every kind the library defines.
  std::size_t kinds_seen = 0;
  for (const bool present : seen) {
    kinds_seen += present ? 1u : 0u;
  }
  CHECK_EQ(kinds_seen, kAllKinds);
}


