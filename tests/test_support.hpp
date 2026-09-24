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

// Minimal deterministic test harness.
//
// No test uses a timeout, a watchdog, or a forced termination: a hanging test
// is a defect, and a test that cannot finish must fail loudly rather than be
// declared green by an external mechanism.

#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "trxreg/result.hpp"

namespace trxreg::test {

struct TestCase {
  std::string name;
  void (*function)();
};

void register_test(const char* name, void (*function)());
std::vector<const TestCase*>& all_tests();

struct Registrar {
  Registrar(const char* name, void (*function)()) { register_test(name, function); }
};

/// Deterministic pseudo-random generator (splitmix64). Every property test
/// prints the seed it used so a failure can be reproduced exactly.
class Random {
 public:
  explicit Random(std::uint64_t seed) : state_(seed) {}

  std::uint64_t next() {
    state_ += 0x9e3779b97f4a7c15ull;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
  }

  std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }

  std::int64_t range(std::int64_t low, std::int64_t high) {
    if (high <= low) {
      return low;
    }
    const auto span = static_cast<std::uint64_t>(high - low + 1);
    return low + static_cast<std::int64_t>(below(span));
  }

  double real(double low, double high) {
    const double unit = static_cast<double>(next() >> 11) / static_cast<double>(1ull << 53);
    return low + (high - low) * unit;
  }

  bool boolean() { return (next() & 1u) != 0u; }

  std::string text(std::size_t length) {
    static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789-_/";
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
      out.push_back(kAlphabet[below(sizeof(kAlphabet) - 1)]);
    }
    return out;
  }

 private:
  std::uint64_t state_;
};

/// Values that can be rendered into a failure message.
template <class T>
std::string display(const T& value) {
  if constexpr (std::is_same_v<T, std::string>) {
    return value;
  } else if constexpr (std::is_same_v<T, std::string_view>) {
    return std::string(value);
  } else if constexpr (std::is_same_v<T, bool>) {
    return value ? "true" : "false";
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_arithmetic_v<T>) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    return "<value>";
  }
}

void report_failure(const char* file, int line, const std::string& message);
void note(const std::string& message);

int run_all(int argc, char** argv);

}  // namespace trxreg::test

#define TRXREG_TEST(name)                                                              \
  static void name();                                                                  \
  static const ::trxreg::test::Registrar trxreg_test_registrar_##name(#name, &name);    \
  static void name()

#define TRXREG_TEST_NAMED(test_name, display_name)                                     \
  static void test_name();                                                             \
  static const ::trxreg::test::Registrar trxreg_test_registrar_##test_name(display_name, &test_name); \
  static void test_name()

#define CHECK(condition)                                                               \
  do {                                                                                 \
    if (!(condition)) {                                                                \
      ::trxreg::test::report_failure(__FILE__, __LINE__, "CHECK failed: " #condition);  \
    }                                                                                  \
  } while (false)

#define CHECK_EQ(actual, expected)                                                     \
  do {                                                                                 \
    const auto& trxreg_actual = (actual);                                              \
    const auto& trxreg_expected = (expected);                                          \
    if (!(trxreg_actual == trxreg_expected)) {                                         \
      ::trxreg::test::report_failure(__FILE__, __LINE__,                               \
                                     std::string("CHECK_EQ failed: " #actual " == " #expected " (actual=") + \
                                         ::trxreg::test::display(trxreg_actual) + " expected=" +                \
                                         ::trxreg::test::display(trxreg_expected) + ")");                       \
    }                                                                                  \
  } while (false)

#define CHECK_NE(actual, unexpected)                                                   \
  do {                                                                                 \
    if ((actual) == (unexpected)) {                                                    \
      ::trxreg::test::report_failure(__FILE__, __LINE__, "CHECK_NE failed: " #actual " != " #unexpected); \
    }                                                                                  \
  } while (false)

#define REQUIRE(condition)                                                             \
  do {                                                                                 \
    if (!(condition)) {                                                                \
      ::trxreg::test::report_failure(__FILE__, __LINE__, "REQUIRE failed: " #condition); \
      return;                                                                          \
    }                                                                                  \
  } while (false)

#define REQUIRE_EQ(actual, expected)                                                   \
  do {                                                                                 \
    const auto& trxreg_actual = (actual);                                              \
    const auto& trxreg_expected = (expected);                                          \
    if (!(trxreg_actual == trxreg_expected)) {                                         \
      ::trxreg::test::report_failure(__FILE__, __LINE__,                               \
                                     std::string("REQUIRE_EQ failed: " #actual " == " #expected " (actual=") + \
                                         ::trxreg::test::display(trxreg_actual) + " expected=" +                \
                                         ::trxreg::test::display(trxreg_expected) + ")");                       \
      return;                                                                          \
    }                                                                                  \
  } while (false)

/// Require a Status/Result to be Ok, reporting its classification otherwise.
#define REQUIRE_OK(expression)                                                         \
  do {                                                                                 \
    const auto& trxreg_status = (expression);                                          \
    if (!trxreg_status.ok()) {                                                         \
      ::trxreg::test::report_failure(__FILE__, __LINE__,                               \
                                     std::string("REQUIRE_OK failed: " #expression " -> ") +                    \
                                         std::string(::trxreg::to_string(trxreg_status.error().code)) + ": " +   \
                                         trxreg_status.error().message);                                        \
      return;                                                                          \
    }                                                                                  \
  } while (false)

/// Require a Status/Result to fail with a specific classification.
#define REQUIRE_FAILS(expression, expected_code)                                       \
  do {                                                                                 \
    const auto& trxreg_status = (expression);                                          \
    if (trxreg_status.ok()) {                                                          \
      ::trxreg::test::report_failure(__FILE__, __LINE__, "REQUIRE_FAILS failed: " #expression " unexpectedly succeeded"); \
      return;                                                                          \
    }                                                                                  \
    if (trxreg_status.error().code != (expected_code)) {                               \
      ::trxreg::test::report_failure(__FILE__, __LINE__,                               \
                                     std::string("REQUIRE_FAILS failed: " #expression " -> ") +                  \
                                         std::string(::trxreg::to_string(trxreg_status.error().code)) +          \
                                         " expected " + std::string(::trxreg::to_string(expected_code)));        \
      return;                                                                          \
    }                                                                                  \
  } while (false)
