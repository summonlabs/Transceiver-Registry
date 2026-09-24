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

#include "registry_support.hpp"

#include <atomic>
#include <thread>
#include <vector>

namespace {

using namespace trxreg;
using namespace trxreg::test;

}  // namespace

// Several publishers that observed the same generation race to commit. Exactly
// one may win; the losers must be told they are stale instead of silently
// overwriting the winner.
TRXREG_TEST(concurrency_one_publisher_wins_the_race) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay1");

  const Generation observed = registry.generation();
  constexpr int kThreads = 8;
  std::atomic<int> committed{0};
  std::atomic<int> refused{0};
  std::atomic<int> other{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&, i]() {
      ModuleRegistration registration;
      const Result<ModuleKey> key = ModuleKey::parse("chassis0/race-" + std::to_string(i), "module key");
      if (!key.ok()) {
        other.fetch_add(1);
        return;
      }
      registration.key = key.value();
      registration.provenance = synthetic_provenance("racer-" + std::to_string(i));
      registration.policy = MutationPolicy::RequireGeneration;
      registration.expected_generation = observed;
      const Result<ModuleHandle> handle = registry.register_module(registration, source.authority());
      if (handle.ok()) {
        committed.fetch_add(1);
      } else if (handle.error().code == StatusCode::StaleGeneration) {
        refused.fetch_add(1);
      } else {
        other.fetch_add(1);
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  CHECK_EQ(committed.load(), 1);
  CHECK_EQ(refused.load(), kThreads - 1);
  CHECK_EQ(other.load(), 0);
  // Exactly one generation was consumed by the race.
  CHECK_EQ(registry.generation().value(), observed.value() + 1);
  CHECK_EQ(registry.stats().modules, std::uint64_t{2});
}

// Publishers that opt into the registry's own ordering all land, each on its
// own generation, and no committed work is lost.
TRXREG_TEST(concurrency_auto_retry_publishers_all_commit) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay2");

  constexpr int kThreads = 8;
  constexpr int kClaimsPerThread = 25;
  std::atomic<int> committed{0};
  std::atomic<int> failed{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&, i]() {
      for (int claim = 0; claim < kClaimsPerThread; ++claim) {
        IdentityFieldValue value;
        value.field = IdentityField::VendorSpecific;
        value.subkey = "slot" + std::to_string(i);
        value.value = "value-" + std::to_string(claim);
        const Status status = registry.update_identity(source.authority(), module, value,
                                                       synthetic_provenance("racer-" + std::to_string(i)),
                                                       MutationPolicy::AutoRetry);
        if (status.ok()) {
          committed.fetch_add(1);
        } else {
          failed.fetch_add(1);
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  CHECK_EQ(committed.load(), kThreads * kClaimsPerThread);
  CHECK_EQ(failed.load(), 0);

  // Every committed claim is visible: the registry kept the newest claim of each
  // source and the bounded history of the rest.
  ClaimQuery query;
  query.include_superseded = true;
  query.limit = 4096;
  const Result<std::vector<IdentityClaim>> history = registry.claim_history(module, query);
  REQUIRE_OK(history);
  // Every source keeps exactly one live claim per attribute: the newest one.
  int live_vendor_specific = 0;
  for (int i = 0; i < kThreads; ++i) {
    const std::string subkey = "slot" + std::to_string(i);
    int live_for_subkey = 0;
    for (const IdentityClaim& claim : history.value()) {
      if (claim.subkey != subkey) {
        continue;
      }
      if (claim.live) {
        ++live_for_subkey;
        CHECK_EQ(claim.value, std::string("value-") + std::to_string(kClaimsPerThread - 1));
      }
    }
    CHECK_EQ(live_for_subkey, 1);
    live_vendor_specific += live_for_subkey;
  }
  CHECK_EQ(live_vendor_specific, kThreads);
}

// Readers run concurrently with writers and always observe a self-consistent
// snapshot: the reported generation never moves backwards and every module the
// reader sees is complete.
TRXREG_TEST(concurrency_readers_never_observe_a_torn_state) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");

  std::atomic<bool> stop{false};
  std::atomic<int> reader_failures{0};
  std::atomic<int> reads{0};
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&]() {
      Generation last{};
      while (!stop.load(std::memory_order_relaxed)) {
        const std::vector<ModuleHandle> modules = registry.modules();
        const Generation current = registry.generation();
        if (current.value() < last.value()) {
          reader_failures.fetch_add(1);
        }
        last = current;
        for (const ModuleHandle& handle : modules) {
          const Result<IdentityView> view = registry.identity(handle);
          if (!view.ok()) {
            reader_failures.fetch_add(1);
            continue;
          }
          if (view.value().uid != handle.uid) {
            reader_failures.fetch_add(1);
          }
        }
        reads.fetch_add(1);
      }
    });
  }

  constexpr int kWriters = 4;
  constexpr int kModulesPerWriter = 30;
  std::vector<std::thread> writers;
  for (int w = 0; w < kWriters; ++w) {
    writers.emplace_back([&, w]() {
      for (int i = 0; i < kModulesPerWriter; ++i) {
        ModuleRegistration registration;
        const Result<ModuleKey> key = ModuleKey::parse("chassis0/w" + std::to_string(w) + "-" + std::to_string(i),
                                                      "module key");
        if (!key.ok()) {
          reader_failures.fetch_add(1);
          return;
        }
        registration.key = key.value();
        registration.provenance = synthetic_provenance("writer-" + std::to_string(w));
        registration.policy = MutationPolicy::AutoRetry;
        const Result<ModuleHandle> handle = registry.register_module(registration, source.authority());
        if (!handle.ok()) {
          reader_failures.fetch_add(1);
          continue;
        }
        const Status status = registry.publish_capability(source.authority(), handle.value(),
                                                          CapabilityKey::LaneCount, {}, CapabilityValue::count(8),
                                                          synthetic_provenance("writer"), MutationPolicy::AutoRetry);
        if (!status.ok()) {
          reader_failures.fetch_add(1);
        }
      }
    });
  }
  for (std::thread& writer : writers) {
    writer.join();
  }
  stop.store(true);
  for (std::thread& reader : readers) {
    reader.join();
  }

  CHECK_EQ(reader_failures.load(), 0);
  CHECK(reads.load() > 0);
  CHECK_EQ(registry.stats().modules, std::uint64_t{kWriters * kModulesPerWriter});
}

// The state digest is a pure function of the committed state, so it is stable
// while nothing mutates and changes exactly when something does.
TRXREG_TEST(concurrency_generation_and_digest_advance_together) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay3");

  const Generation generation = registry.generation();
  const Digest digest = registry.state_digest();
  CHECK_EQ(registry.state_digest().to_hex(), digest.to_hex());
  CHECK_EQ(registry.generation(), generation);

  REQUIRE_OK(registry.publish_capability(source.authority(), module, CapabilityKey::LaneCount, {},
                                         CapabilityValue::count(4), synthetic_provenance("probe-agent"),
                                         MutationPolicy::AutoRetry));
  CHECK_EQ(registry.generation().value(), generation.value() + 1);
  CHECK_NE(registry.state_digest().to_hex(), digest.to_hex());
}

// A refused mutation must not consume a generation or change the state.
TRXREG_TEST(concurrency_refusals_do_not_advance_the_generation) {
  Registry registry;
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), "chassis0/bay4");
  const Generation generation = registry.generation();
  const Digest digest = registry.state_digest();

  REQUIRE_FAILS(registry.transition(source.authority(), module, LifecycleState::Active, "illegal",
                                    MutationPolicy::AutoRetry),
                StatusCode::InvalidTransition);
  REQUIRE_FAILS(registry.publish_capability(source.authority(), module, CapabilityKey::ModuleFamily, {},
                                            CapabilityValue::count(3), synthetic_provenance("probe-agent"),
                                            MutationPolicy::AutoRetry),
                StatusCode::InvalidArgument);
  REQUIRE_FAILS(registry.update_identity(AuthorityToken{SourceId{999}, SourceEpoch{1}}, module,
                                         IdentityFieldValue{IdentityField::Vendor, {}, "X"},
                                         synthetic_provenance("nobody"), MutationPolicy::AutoRetry),
                StatusCode::StaleAuthority);

  CHECK_EQ(registry.generation(), generation);
  CHECK_EQ(registry.state_digest().to_hex(), digest.to_hex());
  // Two of the three attempts reached the mutation path and were refused there;
  // the third was rejected by argument validation before any mutation was
  // attempted, which is why the counter reports two.
  CHECK_EQ(registry.stats().refusals, std::uint64_t{2});
}
