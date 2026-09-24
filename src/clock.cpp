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

#include "trxreg/clock.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

// Two implementations of the Clock interface live here.
//
//   * SystemClock reads the real platform clocks: std::chrono::system_clock for
//     wall time and std::chrono::steady_clock for the monotonic counter. The
//     steady origin is captured exactly once per process, in a function-local
//     static, so every SystemClock handed out by make_system_clock() counts from
//     the same instant.
//   * ManualClock is the deterministic clock used by tests and by replay of
//     captured scenarios.
//
// A ClockDomainId names one incarnation of a clock. It is an FNV-1a hash of
// (process id, steady origin in nanoseconds), so a restarted process can never be
// mistaken for the previous incarnation when monotonic readings are compared -
// even when the platform hands the new process a steady reading close to (or
// equal to) the old one. Zero is the invalid StrongId sentinel, so the domain is
// forced away from zero.

namespace trxreg {
namespace {

// FNV-1a, 64 bit: a few lines, no tables, and enough mixing for two small
// structured inputs (a process id and a steady-clock reading).
constexpr std::uint64_t kFnvOffsetBasis = 0xcbf29ce484222325ULL;
constexpr std::uint64_t kFnvPrime = 0x00000100000001b3ULL;

/// Substituted when the hash folds to zero: ClockDomainId{0} is the invalid id.
constexpr std::uint64_t kFallbackDomain = kFnvPrime;

std::uint64_t hash_bytes(std::uint64_t hash, const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const unsigned char*>(data);
  for (std::size_t index = 0; index < size; ++index) {
    hash ^= static_cast<std::uint64_t>(bytes[index]);
    hash *= kFnvPrime;
  }
  return hash;
}

std::uint64_t hash_u64(std::uint64_t hash, std::uint64_t value) noexcept {
  return hash_bytes(hash, &value, sizeof(value));
}

/// Identity of the running process. The platform call is the only non-standard
/// dependency of this file.
std::uint64_t current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(static_cast<std::uint32_t>(::_getpid()));
#else
  return static_cast<std::uint64_t>(static_cast<std::uint32_t>(::getpid()));
#endif
}

/// Steady-clock reading in nanoseconds. The steady epoch is unspecified, hence
/// the unsigned conversion: only differences of these readings are meaningful.
std::uint64_t steady_now_ns() noexcept {
  const auto since_epoch = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch).count());
}

/// Domain identifier of one clock incarnation: FNV-1a over the process id and
/// the steady origin, never zero.
std::uint64_t make_domain_id(std::uint64_t process_id, std::uint64_t steady_origin_ns) noexcept {
  std::uint64_t hash = kFnvOffsetBasis;
  hash = hash_u64(hash, process_id);
  hash = hash_u64(hash, steady_origin_ns);
  return hash == 0 ? kFallbackDomain : hash;
}

/// Process-wide clock origin, fixed by the first call to make_system_clock().
struct ClockOrigin {
  std::uint64_t steady_ns;
  std::uint64_t domain;

  ClockOrigin() noexcept
      : steady_ns(steady_now_ns()), domain(make_domain_id(current_process_id(), steady_ns)) {}
};

/// Function-local static: thread-safe initialization (C++11 magic statics) makes
/// concurrent first callers agree on one origin, and therefore on one domain.
const ClockOrigin& clock_origin() noexcept {
  static const ClockOrigin origin;
  return origin;
}

/// Wall time from the platform clock, in nanoseconds since the Unix epoch.
WallNs system_wall_now_ns() noexcept {
  const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<WallNs>(std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch).count());
}

class SystemClock final : public Clock {
 public:
  SystemClock() noexcept : origin_ns_(clock_origin().steady_ns), domain_(clock_origin().domain) {}

  [[nodiscard]] WallNs wall_now_ns() const noexcept override { return system_wall_now_ns(); }

  [[nodiscard]] std::uint64_t monotonic_now_ns() const noexcept override {
    const std::uint64_t now_ns = steady_now_ns();
    // steady_clock never runs backwards, but clamp anyway so that a pathological
    // platform cannot publish a reading from before the process origin.
    return now_ns > origin_ns_ ? now_ns - origin_ns_ : 0;
  }

  [[nodiscard]] ClockDomainId domain() const noexcept override { return ClockDomainId{domain_}; }

 private:
  std::uint64_t origin_ns_;
  std::uint64_t domain_;
};

}  // namespace

ClockPtr make_system_clock() { return std::make_shared<SystemClock>(); }

ManualClock::ManualClock(WallNs wall_ns, ClockDomainId domain)
    : wall_ns_(wall_ns), monotonic_ns_(0), domain_(domain.value()) {}

WallNs ManualClock::wall_now_ns() const noexcept { return wall_ns_.load(); }

std::uint64_t ManualClock::monotonic_now_ns() const noexcept { return monotonic_ns_.load(); }

ClockDomainId ManualClock::domain() const noexcept { return ClockDomainId{domain_.load()}; }

void ManualClock::set_wall_ns(WallNs wall_ns) noexcept { wall_ns_.store(wall_ns); }

void ManualClock::advance_ns(std::int64_t delta_ns) noexcept {
  wall_ns_.fetch_add(delta_ns);
  // The monotonic counter is unsigned; a negative delta is applied modulo 2^64,
  // so callers move this clock forward and use restart() to rewind it.
  monotonic_ns_.fetch_add(static_cast<std::uint64_t>(delta_ns));
}

void ManualClock::set_monotonic_ns(std::uint64_t monotonic_ns) noexcept {
  monotonic_ns_.store(monotonic_ns);
}

void ManualClock::restart(ClockDomainId new_domain, std::uint64_t monotonic_base_ns) noexcept {
  monotonic_ns_.store(monotonic_base_ns);
  domain_.store(new_domain.value());
}

}  // namespace trxreg
