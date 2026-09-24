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
#include <string_view>

// Transceiver Registry version and on-disk / on-wire format identities.
//
// The snapshot format version and the wire protocol version are independent of
// the library version: they change only when the encoding changes in a way that
// older readers cannot interpret.

#define TRXREG_VERSION_MAJOR 1
#define TRXREG_VERSION_MINOR 0
#define TRXREG_VERSION_PATCH 0

#define TRXREG_VERSION_STRING "1.0.0"

namespace trxreg {

/// Semantic version of the runtime.
struct Version {
  std::uint32_t major{TRXREG_VERSION_MAJOR};
  std::uint32_t minor{TRXREG_VERSION_MINOR};
  std::uint32_t patch{TRXREG_VERSION_PATCH};
};

constexpr Version version() noexcept { return Version{}; }

constexpr std::string_view version_string() noexcept { return TRXREG_VERSION_STRING; }

/// Version of the persisted snapshot envelope.
constexpr std::uint16_t kSnapshotFormatVersion = 1;

/// Version of the framed loopback transport.
constexpr std::uint16_t kWireProtocolVersion = 1;

/// Magic bytes at the head of a snapshot file: "TRXRSNAP".
inline constexpr char kSnapshotMagic[8] = {'T', 'R', 'X', 'R', 'S', 'N', 'A', 'P'};

/// Magic bytes at the head of a transport frame: "TRXF".
inline constexpr char kFrameMagic[4] = {'T', 'R', 'X', 'F'};

}  // namespace trxreg
