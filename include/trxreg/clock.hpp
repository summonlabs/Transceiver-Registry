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

#include <atomic>
#include <cstdint>
#include <memory>

#include "trxreg/ids.hpp"

namespace trxreg {

/// Nanoseconds since the Unix epoch.
using WallNs = std::int64_t;

/// The registry never reads the platform clock directly: every time-dependent
/// decision goes through this interface, so that freshness and hysteresis are
/// deterministic in tests and provably re-evaluated after a restart.
class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock() = default;

  [[nodiscard]] virtual WallNs wall_now_ns() const noexcept = 0;
  [[nodiscard]] virtual std::uint64_t monotonic_now_ns() const noexcept = 0;
  /// Identifier of this clock's incarnation. Monotonic readings may only be
  /// compared inside one clock domain; a restarted process has a new domain.
  [[nodiscard]] virtual ClockDomainId domain() const noexcept = 0;
};

using ClockPtr = std::shared_ptr<Clock>;

/// Wall clock (Unix epoch) plus a process-lifetime monotonic clock.
[[nodiscard]] ClockPtr make_system_clock();

/// Deterministic clock for tests and for replaying captured scenarios.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(WallNs wall_ns, ClockDomainId domain = ClockDomainId{1});

  [[nodiscard]] WallNs wall_now_ns() const noexcept override;
  [[nodiscard]] std::uint64_t monotonic_now_ns() const noexcept override;
  [[nodiscard]] ClockDomainId domain() const noexcept override;

  void set_wall_ns(WallNs wall_ns) noexcept;
  void advance_ns(std::int64_t delta_ns) noexcept;
  void set_monotonic_ns(std::uint64_t monotonic_ns) noexcept;
  /// Simulate a process restart: a new clock domain with a fresh monotonic base.
  void restart(ClockDomainId new_domain, std::uint64_t monotonic_base_ns) noexcept;

 private:
  std::atomic<WallNs> wall_ns_;
  std::atomic<std::uint64_t> monotonic_ns_;
  std::atomic<std::uint64_t> domain_;
};

}  // namespace trxreg
