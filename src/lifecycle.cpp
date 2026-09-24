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

#include "trxreg/lifecycle.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

// The lifecycle is a small finite state machine, so the transition relation is a
// constexpr bit table instead of a chain of comparisons: the predicate allocates
// nothing, branches once, and the legal moves are stated in exactly one place.
// Bit [to] of kTargets[from] means [from -> to] is legal.
//
//   Discovered  -> Registered, Removed
//   Registered  -> Attached, Quarantined, Removed, Retired, Replaced
//   Attached    -> Active, Degraded, Quarantined, Removed, Replaced
//   Active      -> Degraded, Quarantined, Removed, Retired, Replaced
//   Degraded    -> Active, Quarantined, Removed, Replaced
//   Quarantined -> Registered, Attached, Active, Removed, Retired, Replaced
//   Removed     -> Registered, Retired
//   Retired     -> (none: terminal)
//   Replaced    -> Removed, Retired
//
// Every legal move changes the state: there are no self-transitions, and Retired
// is the only state with no outgoing edge. Every row is listed in ascending
// LifecycleState order, which is also the order lifecycle_allowed_targets()
// reports.

namespace trxreg {
namespace {

/// Number of LifecycleState enumerators; also the first out-of-range index.
constexpr std::size_t kStateCount = 9;

/// Position of a state in the table, or kStateCount when the value is not an
/// enumerator at all (a caller may pass an arbitrary casted byte).
constexpr std::size_t lifecycle_index(LifecycleState state) noexcept {
  switch (state) {
    case LifecycleState::Discovered:
      return 0;
    case LifecycleState::Registered:
      return 1;
    case LifecycleState::Attached:
      return 2;
    case LifecycleState::Active:
      return 3;
    case LifecycleState::Degraded:
      return 4;
    case LifecycleState::Quarantined:
      return 5;
    case LifecycleState::Removed:
      return 6;
    case LifecycleState::Retired:
      return 7;
    case LifecycleState::Replaced:
      return 8;
  }
  return kStateCount;
}

constexpr std::uint32_t state_bit(std::size_t index) noexcept {
  return static_cast<std::uint32_t>(1) << index;
}

constexpr std::uint32_t kTargets[kStateCount] = {
    state_bit(1) | state_bit(6),  // Discovered
    state_bit(2) | state_bit(5) | state_bit(6) | state_bit(7) | state_bit(8),  // Registered
    state_bit(3) | state_bit(4) | state_bit(5) | state_bit(6) | state_bit(8),  // Attached
    state_bit(4) | state_bit(5) | state_bit(6) | state_bit(7) | state_bit(8),  // Active
    state_bit(3) | state_bit(5) | state_bit(6) | state_bit(8),  // Degraded
    state_bit(1) | state_bit(2) | state_bit(3) | state_bit(6) | state_bit(7) | state_bit(8),  // Quarantined
    state_bit(1) | state_bit(7),  // Removed
    0,                            // Retired
    state_bit(6) | state_bit(7),  // Replaced
};

}  // namespace

bool lifecycle_transition_allowed(LifecycleState from, LifecycleState to) noexcept {
  const std::size_t from_index = lifecycle_index(from);
  const std::size_t to_index = lifecycle_index(to);
  if (from_index == kStateCount || to_index == kStateCount) {
    return false;
  }
  return (kTargets[from_index] & state_bit(to_index)) != 0;
}

bool lifecycle_state_is_terminal(LifecycleState state) noexcept {
  const std::size_t index = lifecycle_index(state);
  // Retired is the only state whose row is empty; deriving terminality from the
  // table keeps it from ever disagreeing with the transition predicate.
  return index != kStateCount && kTargets[index] == 0;
}

bool lifecycle_state_implies_attachment(LifecycleState state) noexcept {
  return state == LifecycleState::Attached || state == LifecycleState::Active ||
         state == LifecycleState::Degraded;
}

std::vector<LifecycleState> lifecycle_allowed_targets(LifecycleState from) {
  std::vector<LifecycleState> targets;
  const std::size_t from_index = lifecycle_index(from);
  if (from_index == kStateCount) {
    return targets;
  }
  const std::uint32_t mask = kTargets[from_index];
  // Enumerators are scanned in declaration order, and every row above is written
  // in that same ascending order, so the documented order falls out directly.
  for (std::size_t index = 0; index < kStateCount; ++index) {
    if ((mask & state_bit(index)) != 0) {
      targets.push_back(static_cast<LifecycleState>(index));
    }
  }
  return targets;
}

}  // namespace trxreg
