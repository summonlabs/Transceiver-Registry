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
#include <string>
#include <vector>

#include "trxreg/clock.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// Lifecycle of one module incarnation.
///
///   Discovered -> Registered -> Attached -> Active <-> Degraded
///                                    |          |
///                                    v          v
///                                Quarantined ----+
///                                    |
///   any ------------------------> Removed / Retired / Replaced
///
/// `Replaced` is entered automatically by the registry when a new incarnation
/// takes over the module key or the slot of an older one. `Retired` is terminal.
bool lifecycle_transition_allowed(LifecycleState from, LifecycleState to) noexcept;

/// True when no further transition is possible from this state.
bool lifecycle_state_is_terminal(LifecycleState state) noexcept;

/// True when the state implies a live physical attachment.
bool lifecycle_state_implies_attachment(LifecycleState state) noexcept;

std::vector<LifecycleState> lifecycle_allowed_targets(LifecycleState from);

/// One recorded transition.
struct LifecycleEvent {
  LifecycleState from{LifecycleState::Discovered};
  LifecycleState to{LifecycleState::Discovered};
  /// Incarnation the transition applies to. Transitions of a superseded
  /// incarnation stay in history and are never applied to the replacement.
  IncarnationId incarnation{};
  std::string reason;
  SourceId source{};
  SourceEpoch source_epoch{};
  Generation generation{};
  Sequence sequence{};
  WallNs wall_ns{0};

  friend bool operator==(const LifecycleEvent& lhs, const LifecycleEvent& rhs) noexcept = default;
};

}  // namespace trxreg
