# Transceiver Registry

Transceiver Registry is an open-source, vendor-neutral C++20 runtime that answers one
question about optical and electrical transceiver modules:

> For this exact module identity and this evidence generation, what is it, what can it
> do, what is its health state, what is it compatible with, and how fresh is the
> evidence supporting that answer?

It is a **knowledge runtime**, not a device driver. Nothing in this repository opens a
device, programs a module, allocates optical paths, assigns wavelengths, plans routes,
or identifies cables. Observations enter through the API (or the loopback transport)
with provenance attached, and everything the registry answers can be traced back to the
evidence that produced it.

## Contents

- [Scope](#scope)
- [Build and install](#build-and-install)
- [Using the library](#using-the-library)
- [The evidence model](#the-evidence-model)
- [Identity and conflict](#identity-and-conflict)
- [Capability](#capability)
- [Health](#health)
- [Compatibility](#compatibility)
- [Lifecycle](#lifecycle)
- [Persistence and recovery](#persistence-and-recovery)
- [Loopback transport](#loopback-transport)
- [Tools](#tools)
- [Concurrency model](#concurrency-model)
- [Bounded resources](#bounded-resources)
- [Proof obligations and where they are proven](#proof-obligations-and-where-they-are-proven)
- [Verified configurations](#verified-configurations)
- [Benchmarks](#benchmarks)
- [Repository layout](#repository-layout)

## Scope

**Owned by this runtime**

| Area | What it means |
| --- | --- |
| Identity | Typed, per-source claims about what a module is: vendor, part number, serial, revision, OUI, date code, firmware version/build, EEPROM content digest, vendor-specific fields, with visible conflict instead of silent merge |
| Attachment | Which module incarnation occupies which slot, and on which port index |
| Capability | Vendor-neutral declarations: module family, media class, connector class, lane count, speed classes, encodings, FEC modes, wavelength/frequency descriptors, reach class, power class, maximum power, operating temperature window, telemetry capabilities |
| Health | Evidence-gated classification of temperature, supply voltage, TX/RX optical power, bias current, and lane skew |
| Compatibility | Explicit, explainable rules that decide COMPATIBLE / INCOMPATIBLE / UNKNOWN / UNSUPPORTED |
| Lifecycle | discovered, registered, attached, active, degraded, quarantined, removed, retired, replaced |
| Evidence | Provenance, observation time, source incarnation, registry generation, and history for every claim, declaration, and measurement |

**Deliberately not owned** (adjacent runtimes do these, and this runtime does not pretend
to):

- optical path allocation and wavelength assignment;
- route planning and path placement;
- cable identity and cable plant records;
- active hardware programming, firmware update, or module configuration;
- vendor SDK integration, switch/ASIC behaviour, RDMA/InfiniBand/NVLink semantics;
- physical device I/O of any kind. No code in this repository talks to hardware.

The registry models what a module *is*, *can do*, *is measured to be*, and *is declared
compatible with*. Acting on that knowledge is somebody else's runtime.

## Build and install

Requirements: CMake 3.24+, a C++20 compiler, and threads. There are no third-party
dependencies.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix <prefix>
```

CMake options:

| Option | Default | Meaning |
| --- | --- | --- |
| `TRXREG_BUILD_TESTS` | ON | Build the test suite |
| `TRXREG_BUILD_TOOLS` | ON | Build `trxreg_server`, `trxreg_cli`, `trxreg_bench` |
| `TRXREG_BUILD_EXAMPLES` | ON | Build the three examples |
| `TRXREG_INSTALL` | ON | Generate install rules and the CMake package |
| `TRXREG_ENABLE_ASAN` | OFF | Build with AddressSanitizer (MSVC `/fsanitize=address`, GCC/Clang `-fsanitize=address,undefined`) |
| `TRXREG_WARNINGS_AS_ERRORS` | ON | Treat warnings as errors |

### Consuming the installed package

```
cmake -S examples/downstream -B downstream-build -DCMAKE_PREFIX_PATH=<prefix>
cmake --build downstream-build
downstream-build/trxreg_downstream
```

`examples/downstream` is an independent project: it is not part of this build tree, it
uses only `find_package(TransceiverRegistry REQUIRED)` and the exported target
`TransceiverRegistry::trxreg`, and it builds and runs against an install prefix alone.

## Using the library

```cpp
#include "trxreg/registry.hpp"

using namespace trxreg;

Registry registry;                                   // system clock by default

SourceDescriptor source;
source.name = "probe-agent-1";
source.declared_kind = EvidenceKind::Real;           // evidence captured from a device
const SourceHandle handle = registry.register_source(source).value();

ModuleRegistration registration;
registration.key = ModuleKey::parse("chassis0/bay2", "module key").value();
registration.intent = RegisterIntent::EnsureCurrent;
registration.provenance = Provenance{EvidenceKind::Real, "eeprom-page0", "decoded", {}, {}};
registration.identity.push_back({IdentityField::Vendor, {}, "Acme Optics"});
registration.identity.push_back({IdentityField::SerialNumber, {}, "SN-0001"});
const ModuleHandle module = registry.register_module(registration, handle.authority()).value();

registry.publish_capability(handle.authority(), module, CapabilityKey::MediaClass, {},
                            CapabilityValue::of(MediaClass::MultimodeFiber),
                            registration.provenance, MutationPolicy::AutoRetry);

HealthThreshold threshold;                            // published policy, not a built-in
threshold.metric = HealthMetric::TemperatureCelsius;
threshold.has_degraded = true;
threshold.degraded_enter = 70.0;  threshold.degraded_exit = 65.0;
threshold.has_critical = true;
threshold.critical_enter = 80.0;  threshold.critical_exit = 75.0;
threshold.max_age_ns = 60'000'000'000LL;              // freshness bound: 60 s
registry.publish_threshold(handle.authority(), threshold, MutationPolicy::AutoRetry);

HealthSampleInput sample;
sample.metric = HealthMetric::TemperatureCelsius;
sample.value = 42.0;                                  // observed_at_wall_ns 0 means "now"
sample.provenance = Provenance{EvidenceKind::Real, "ddm-poll", "read", {}, {}};
registry.ingest_health(handle.authority(), module, sample, MutationPolicy::AutoRetry);

const HealthReport report = registry.health(module).value();
// report.outcome, report.worst, report.metrics, report.issues, report.healthy()
```

Every call returns a typed `Status` or `Result<T>`. Failures carry a
`StatusCode` (`stale_authority`, `stale_generation`, `fenced`, `invalid_transition`,
`capacity_exceeded`, `clock_skew`, `refused`, `unsupported`, `malformed`, `corrupt`,
...) and are never collapsed into a generic success.

Three complete, compiling examples are in `examples/`: a lifecycle walkthrough, a
compatibility walkthrough, and a loopback-transport walkthrough.

## The evidence model

Every claim, declaration, measurement, rule, and threshold carries:

- a **provenance**: `EvidenceKind` (`Real`, `Synthetic`, or `Unsupported`), an origin,
  a method, an optional content digest of the captured bytes, and an optional capture
  reference. Evidence must name a real or synthetic origin; `Unsupported` provenance is
  refused for evidence;
- the **source** that produced it and that source's **incarnation** (epoch);
- the **module incarnation** it describes;
- the **observation time** (wall clock) and, where the publisher supplies it, a
  monotonic reading plus its clock domain;
- the **registry generation** and the **evidence sequence** at which it was recorded.

The distinction between REAL, SYNTHETIC, and UNSUPPORTED evidence is load-bearing:
this runtime never fabricates device data. Everything the shipped tests and benchmarks
publish is SYNTHETIC and says so; the examples mark their fixtures SYNTHETIC too. A
deployment that reads real EEPROM pages or DDM registers marks that evidence REAL and
supplies its own capture digests.

## Identity and conflict

Identity is a set of per-source claims. Claims from different sources are **never
merged**:

- two sources that disagree produce a `FieldConsensus` with outcome `Conflicting`;
  both claims, with their provenance and observation times, stay visible through
  `Registry::identity` and `Registry::claim_history`;
- a source that revises its own claim supersedes its own earlier claim (visible in
  history, marked `live == false`) without conflicting with itself;
- re-registering a source name with a *different* (or absent) instance id mints a new
  **epoch**: claims from the retired epoch are fenced (they stay visible, they stop
  deciding) and authority tokens from that epoch are refused with `stale_authority`.
  Re-registering with the *same* non-empty instance id is a renewal — the source is the
  same agent reconnecting, so it keeps its epoch and its earlier claims stay live;
- a new physical module in the same position is registered with
  `RegisterIntent::NewIncarnation`. That bumps the module's **incarnation**, records a
  `Replaced` lifecycle event for the previous one, fences its evidence, and releases its
  slot. Queries against the old handle fail with `fenced` instead of silently returning
  the replacement's data.

Consensus outcomes are `unknown`, `single_source`, `agreed`, `conflicting`, and
`superseded`. There is no "merged" identity.

## Capability

Capabilities are declared per subject (module incarnation or host port) with the same
provenance and conflict rules as identity. The accepted shape of each attribute is
fixed by `capability_value_kind`, so a mis-shaped publication is refused at the
boundary instead of being coerced:

| Attribute | Shape |
| --- | --- |
| `module_family`, `media_class`, `connector_class`, `reach_class`, `power_class`, `wavelength_grid` | enum |
| `lane_count` | count |
| `speed_classes`, `encodings`, `fec_modes` | enum set (canonically sorted, duplicate-free) |
| `wavelengths` | spectrum descriptors (lane, center nm, frequency THz, grid, channel) |
| `wavelength_tunable`, `temperature_telemetry`, `voltage_telemetry`, `tx_power_telemetry`, `rx_power_telemetry`, `bias_current_telemetry`, `lane_skew_telemetry`, `digital_diagnostic_monitoring` | boolean |
| `max_power_milli_watts`, `operating_temperature_min_celsius`, `operating_temperature_max_celsius` | real |
| `vendor_specific` (requires a subkey) | text |

`CapabilityView::digest` is a content-addressed digest over the consensus of every
attribute; it does not depend on the registry generation or on insertion order.

## Health

Health is **evidence-gated and freshness-bounded**:

- a metric is classified only from live samples of the current module incarnation whose
  source epoch is current, and only while the newest such sample is inside the freshness
  bound published for that metric;
- **missing telemetry is not zero and not healthy**: `NotAvailable`, `ReadError`, and
  `NotSupported` presences produce `unknown` with an explicit issue, never a
  measurement;
- a metric with no published threshold is `unclassified` — never `ok`. Health requires
  published policy *and* fresh evidence;
- hysteresis is typed: separate enter/exit bounds, an escalation count, and a recovery
  count. A value between the exit and entry bound holds the current state and resets the
  counter instead of starting a recovery;
- two live sources that disagree beyond the published tolerance produce `conflicting`,
  not an average;
- **a historical measurement never becomes current after a restart**: freshness is
  evaluated against the wall clock at query time, not at ingestion. Evidence that has
  aged out is `stale`, and the persisted hysteresis latch is reset to `unknown` when its
  evidence base no longer holds;
- monotonic readings are only compared inside one clock domain; a restarted process has a
  new domain, so cross-boot monotonic comparisons are refused rather than guessed;
- implausible values (outside the metric's physical range), non-finite values, future
  timestamps, and replayed/out-of-order observations of the same series in the same clock
  domain are refused with a classified error.

`HealthReport::healthy()` is true only when every considered metric is `ok` on fresh
evidence. `MetricState` distinguishes `ok`, `degraded`, `critical`, `stale`,
`unclassified`, `conflicting`, `fenced`, and `unknown`.

## Compatibility

Compatibility is explicit and explainable. Rules are published by sources, ordered
deterministically by `(priority, rule id)`, and evaluated as three-valued logic:

1. a matched **deny** rule decides `INCOMPATIBLE` (deny wins over allow);
2. a matched **unsupported** rule decides `UNSUPPORTED`;
3. a matched **allow** rule decides `COMPATIBLE` only if no considered rule is
   indeterminate;
4. otherwise the answer is `UNKNOWN`, with the knowledge closure distinguishing `open`
   (no rule approves the pair) from `partial` (a rule is waiting for evidence).

**Absence of a rule is UNKNOWN, not approval.** An indeterminate deny rule blocks a
matching allow rule. Two sources disagreeing about an attribute makes every requirement
on it indeterminate. Every decision reports the matched rules, their requirements with
satisfied/violated/indeterminate states and the observed values, the registry generation
it was taken at, an inputs digest, and a decision digest; `explain_decision` renders it.

Decisions are **generation-fenced**: `Registry::verify_decision` re-checks that the
decision still describes the current registry, and a query can require the latest
generation explicitly.

## Lifecycle

`discovered → registered → attached → active ↔ degraded`, with `quarantined`,
`removed`, `retired`, and `replaced` terminal or transitional states. Transitions are
a fixed table: an illegal transition is refused with `invalid_transition` and does not
consume a generation. Attachment and detachment drive `attached`/`removed`
automatically; `reconcile_lifecycle` moves a module between `active` and `degraded`
strictly from health evidence and never invents a state when the evidence is missing,
stale, or conflicted.

## Persistence and recovery

A snapshot is a versioned, integrity-checked, record-framed file:

```
magic "TRXRSNAP" | version u16 | flags u16 | reserved u32 | record bytes u64 | generation u64
  record* : length u32 | kind u8 | canonical document | CRC-32C u32
trailer "TRXREOF1" | next sequence u64 | CRC-32C of the record stream u32
```

- writes are **atomic**: content goes to a temporary file in the same directory, is
  flushed to stable storage, and is renamed over the target, so a crash never leaves a
  half-overwritten snapshot;
- loading is **conservative**: an unsupported version, a wrong magic, a damaged record,
  or a bad trailer is rejected with `corrupt`/`unsupported`; with tail recovery enabled
  the longest valid prefix is loaded and the dropped bytes, the reason, and every
  invalidated latch are reported in the `LoadReport`;
- a corrupt record drops that record **and everything after it** — never a gap;
- attachments whose module did not survive recovery are dropped and reported;
- **dynamic evidence never silently becomes fresh on load.** Every sample keeps its wall
  clock observation time, freshness is re-evaluated against the clock at load time, and
  hysteresis latches whose evidence base has aged out are reset to `unknown` and counted
  in `evidence_invalidated_on_load`;
- loading is a new registry incarnation: `registry_incarnation` increments and the
  generation advances by one, so a decision fenced against the previous process is
  provably stale;
- `enable_autosave` persists after every committed mutation, which is what makes a
  killed daemon recoverable.

## Loopback transport

`trxreg_server` serves the registry over real loopback TCP with a framed protocol:

```
magic "TRXF" (4) | version u16 | type u16 | flags u16 | reserved u16 | body length u32 | body | CRC-32C u32
```

The body is a canonical document. The frame length is validated against
`FrameLimits::max_body_bytes` **before** any buffer for the body is allocated; a
zero-length body is refused because a canonical document is at least one byte; a frame
that fails its CRC is dropped without being parsed. Operations include
`source.register`, `module.register`, `module.identity`, `identity.update`,
`capability.publish`, `port.capability.publish`, `attachment.attach`,
`attachment.detach`, `health.ingest`, `health.threshold.publish`, `health.report`,
`health.samples`, `compat.rule.publish`, `compat.query`, `lifecycle.transition`,
`lifecycle.reconcile`, `evidence.claims`, `evidence.declarations`,
`evidence.summary`, `registry.stats`, `registry.generation`, `registry.save`, and
`hello`/`ping`.

The server bounds connections, requests per connection, frame size, and document size;
a malformed, oversized, or hostile frame closes that connection with a classified
failure while the process keeps serving other connections. Shutdown stops accepting,
unblocks and joins every worker, and never joins a worker while holding a lock it needs.

## Tools

| Tool | Purpose |
| --- | --- |
| `trxreg_server` | Long-lived daemon: `--port`, `--bind`, `--ready-file`, `--snapshot`, `--max-connections`. Prints `READY port=<n> pid=<n>` once bound, autosaves every mutation, and saves on a graceful stop |
| `trxreg_cli` | Inspection and mutation utility. In-process against a snapshot (`--snapshot FILE`) or remote over the transport (`--server HOST:PORT`). Subcommands: `stats`, `info`, `inspect`, `save`, `source-register`, `module-register`, `identity`, `capabilities`, `evidence`, `health`, `capability-publish`, `attach`, `detach`, `health-threshold`, `health-ingest`, `compat-rule`, `compat-query`, `compat-rules`, `transition`, `reconcile`, `selftest`. Every response is printed as a canonical JSON document |
| `trxreg_bench` | Benchmarks of completed useful work (see below). States that all data is synthetic |

## Concurrency model

The registry holds one immutable state snapshot behind one mutex. A mutation copies the
state, applies the change, and publishes the copy; readers only hold the mutex while
copying the shared pointer. Consequences that are tested rather than asserted:

- no callback ever runs under the lock, and a reader can never observe a torn state;
- `MutationPolicy::RequireGeneration` fences a mutation against the generation the
  caller observed. Because the fence check and the commit happen under one lock, exactly
  one of several racing publishers commits and the rest receive `stale_generation`;
- `MutationPolicy::AutoRetry` applies the change to the latest generation, so
  independent publishers all land on distinct generations and nothing is lost;
- a refused mutation consumes neither a generation nor a state change;
- `ModuleHandle::generation` is the fence token: it is the generation the handle was
  minted at, so a handle goes stale as soon as anything else commits. Use
  `MutationPolicy::AutoRetry` or refresh the field from `Registry::generation()` when a
  publisher wants to fence against a freshly observed state.

## Bounded resources

Every externally derived size is validated before allocation, and every collection has a
configured cap: sources, modules, ports, rules, thresholds, attachments, claims per
attribute and per module, declarations per subject, samples per series and per module,
lifecycle and claim history, string and document sizes, frame body size, nesting depth,
element counts, and node budgets. Exceeding a cap is `capacity_exceeded`, never silent
truncation; when a bounded history has to drop an entry it drops the oldest superseded
one and the sample counters report what was dropped.

## Proof obligations and where they are proven

| Obligation | Test |
| --- | --- |
| Stale module incarnation evidence is fenced after replacement | `identity_replacement_fences_previous_incarnation`, `health_evidence_is_fenced_by_replacement`, `lifecycle_replacement_records_replaced_event` |
| Conflicting identity sources stay visible and cannot silently merge | `identity_conflicting_sources_stay_visible`, `identity_self_revision_supersedes_without_hiding`, `identity_retired_source_epoch_is_fenced_not_deleted` |
| Compatibility decisions are deterministic and generation-fenced | `compatibility_decisions_are_generation_fenced`, `compatibility_rule_order_does_not_change_the_outcome`, `compatibility_matches_the_reference_model` (differential against an independent model, 60 seeded cases) |
| UNKNOWN never collapses to COMPATIBLE | `compatibility_without_rules_is_unknown`, `compatibility_indeterminate_requirement_is_unknown`, `compatibility_indeterminate_deny_blocks_approval`, `compatibility_conflicting_capability_is_indeterminate` |
| Health freshness expires correctly across restart | `health_freshness_across_restart`, `health_historical_sample_never_becomes_current`, `health_freshness_expires_without_restart` |
| Concurrent publisher race resolves to one authoritative generation | `concurrency_one_publisher_wins_the_race`, `concurrency_auto_retry_publishers_all_commit`, `concurrency_readers_never_observe_a_torn_state`, `concurrency_refusals_do_not_advance_the_generation` |
| Malformed EEPROM-like/telemetry payloads are rejected within bounded resources | `canonical_malformed_documents_are_rejected`, `canonical_bounded_resources`, `canonical_utf8_validation`, `wire_hostile_frames_are_contained`, `health_rejects_implausible_and_inconsistent_input` |
| Corruption and torn-tail recovery | `persistence_rejects_corruption_and_recovers_torn_tails` (wrong magic, bad version, flipped byte, truncation at many lengths, trailing garbage), `persistence_round_trip_with_system_clock_domain` |
| Real independent-process publication/query/restart | `multiprocess_publish_query_kill_restart`: a real `trxreg_server` process over real loopback TCP, killed with `TerminateProcess` and restarted, proving the previous authority is fenced, the claims published by the killed process survive, fresh evidence stays fresh, a replacement incarnation fences the old samples, and a decision fenced against the old generation is refused |
| Stable canonical serialization and digest identity | `canonical_encoding_is_order_independent`, `canonical_digest_identity`, `canonical_randomized_round_trip`, `persistence_state_digest_is_stable`, `property_identical_operations_produce_identical_state` |

Randomized suites print the seed they used (`trxreg::test::note`), so a failure is
reproducible exactly.

## Verified configurations

| Configuration | Result |
| --- | --- |
| Windows 11, MSVC 19.44 (VS 2022 BuildTools), Ninja, Release, `/W4 /WX /permissive-` | Builds warning-free; 63 tests, 0 failures; CTest 10/10 suites pass |
| Same, Debug | Builds warning-free; the full suite passes |
| Same, `TRXREG_ENABLE_ASAN=ON` (`/fsanitize=address`), RelWithDebInfo | Builds warning-free, no sanitizer reports |
| `cmake --install` + `examples/downstream` via `find_package` | Consumer builds and runs against the install prefix only |

The POSIX code paths (`net.cpp`, `clock.cpp`, snapshot flushing) are implemented but
have not been exercised on this machine, which has no GCC/Clang or POSIX toolchain. Only
the MSVC/Windows configuration above is verified.

## Benchmarks

`trxreg_bench` measures **completed** operations with `std::chrono::steady_clock`. All
data is synthetic, generated by the benchmark itself; no hardware was contacted and
these numbers say nothing about device performance. Measured on an AMD Ryzen 7 9800X3D
(8 cores, 64 GiB), Windows 11, MSVC Release:

| Scenario | Completed operations | Throughput |
| --- | --- | --- |
| Module registration | 2 000 | ≈ 2 100 /s |
| Identity claims | 20 000 | ≈ 3 190 /s |
| Capability publications | 20 000 | ≈ 1 920 /s |
| Health ingestions | 20 000 | ≈ 3 840 /s |
| Compatibility decisions | 20 000 | ≈ 9 980 /s |
| Snapshot save+load cycles | 50 | ≈ 49 /s (≈ 476 KB per snapshot) |
| Loopback request/response round trips | 2 000 | ≈ 18 080 /s |

Each mutation copies the immutable state, so registration and publication throughput
falls as the registry grows; the benchmark reports the generation it reached so the
reader can see how much work was actually committed. A full run completes 84 050
operations across 62 877 committed mutations.

## Repository layout

```
include/trxreg/    public headers (installed)
src/               library implementation (internal headers are not installed)
tools/             trxreg_server, trxreg_cli, trxreg_bench
examples/          three walkthroughs plus the independent downstream consumer
tests/             the suite described above
cmake/             package configuration template
```

Repository requirements: Apache License 2.0 (see `LICENSE`), attribution in `NOTICE`,
and contribution terms in `CONTRIBUTING.md`.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
