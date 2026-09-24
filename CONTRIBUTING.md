# Contributing to Transceiver Registry

Thank you for your interest in contributing to Transceiver Registry. This
document describes the contribution terms for this project.

## License

By contributing to this project, you agree that your contributions are
licensed under the **Apache License, Version 2.0**. See the `LICENSE`
file for the full license text and the `NOTICE` file for attribution
and license notices. There is **no separate Contributor License
Agreement (CLA)** requirement: you retain ownership of your
contributions and grant the project a license to use them under the
terms of the Apache License 2.0.

## License headers

New source files should carry the following header:

```
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
```

## Coding standards

- C++20 and CMake. The runtime builds warning-clean under `/W4 /WX`
  (MSVC) and `-Wall -Wextra -Werror` (GCC/Clang).
- No third-party runtime dependencies. Everything shipped here is
  first-party code plus the C++ standard library and the platform socket
  API.
- Evidence boundaries are the core invariant of this project. Anything
  that enters the registry from outside must carry provenance, an
  observation time, a source incarnation, and a bounded size.
- Nothing may silently overwrite another source's claim. If two sources
  disagree, both claims stay visible and the consensus outcome is
  `Conflicting`.
- `UNKNOWN` must never be reported as `COMPATIBLE`, and missing
  telemetry must never be reported as a healthy measurement.
- Time-dependent behavior must be driven by the injectable clock so it can
  be tested deterministically.

## Architecture boundaries

Transceiver Registry owns authoritative module identity, capability, health,
compatibility, and lifecycle knowledge. It does **not** own optical path
allocation, wavelength assignment, route planning, cable identity, or active
hardware programming. Contributions that pull those responsibilities into
this runtime will be declined; publish the knowledge instead and let the
adjacent runtime act on it.

## Testing

Run the full suite before submitting:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The suite covers identity conflicts, lifecycle fences, health freshness
across restart, compatibility determinism, persistence corruption and
torn-tail recovery, malformed-payload rejection, concurrent publishers,
fixed-seed property tests against a small reference model, and a real
multi-process publication/query/restart proof over loopback TCP.

## Pull requests

Please keep changes focused, add tests for new behavior, and ensure the
repository builds and tests cleanly in both Release and Debug.
