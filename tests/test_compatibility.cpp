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

#include <string>
#include <vector>

namespace {

using namespace trxreg;
using namespace trxreg::test;

constexpr const char* kPort = "switch0/ethernet1/1";

Requirement satisfied_requirement() {
  return module_requirement(CapabilityKey::MediaClass, RequirementOp::Equals,
                            CapabilityValue::of(MediaClass::MultimodeFiber));
}

Requirement violated_requirement() {
  return module_requirement(CapabilityKey::MediaClass, RequirementOp::Equals,
                            CapabilityValue::of(MediaClass::SingleModeFiber));
}

/// Nothing publishes the module's reach class, so this requirement can never be
/// established: it is the indeterminate case.
Requirement indeterminate_requirement() {
  return module_requirement(CapabilityKey::ReachClass, RequirementOp::Equals,
                            CapabilityValue::of(ReachClass::ShortReach));
}

struct Fixture {
  ModuleHandle module;
  AuthorityToken authority;
};

Fixture prepare(Registry& registry, const std::string& key = "chassis0/bay1") {
  const SourceHandle source = register_source(registry, "probe-agent");
  const ModuleHandle module = register_module(registry, source.authority(), key);
  publish_capability(registry, source.authority(), module, CapabilityKey::MediaClass,
                     CapabilityValue::of(MediaClass::MultimodeFiber));
  publish_port_capability(registry, source.authority(), kPort, CapabilityKey::MediaClass,
                          CapabilityValue::of(MediaClass::MultimodeFiber));
  return Fixture{module, source.authority()};
}

CompatDecision decide(Registry& registry, const ModuleHandle& module) {
  CompatQuery query;
  query.port = TRXREG_FIXTURE(PortKey::parse(kPort, "port key"));
  query.uid = module.uid;
  query.incarnation = module.incarnation;
  query.require_latest_generation = false;
  return TRXREG_FIXTURE(registry.query_compatibility(query));
}

std::string outcome_text(CompatOutcome outcome) {
  switch (outcome) {
    case CompatOutcome::Compatible:
      return "compatible";
    case CompatOutcome::Incompatible:
      return "incompatible";
    case CompatOutcome::Unsupported:
      return "unsupported";
    case CompatOutcome::Unknown:
      return "unknown";
  }
  return "?";
}

}  // namespace

// The absence of a rule is not approval.
TRXREG_TEST(compatibility_without_rules_is_unknown) {
  Registry registry;
  const Fixture fixture = prepare(registry);
  const CompatDecision decision = decide(registry, fixture.module);
  CHECK(decision.outcome == CompatOutcome::Unknown);
  CHECK(decision.closure == KnowledgeClosure::Open);
  CHECK_EQ(decision.considered_rules, std::uint32_t{0});
  CHECK(decision.undecided());
  CHECK(!decision.compatible());
  CHECK(decision.explanation.find("UNKNOWN") != std::string::npos);
}

TRXREG_TEST(compatibility_allow_and_deny_rules) {
  Registry registry;
  const Fixture fixture = prepare(registry);

  const Result<CompatRuleHandle> allow = registry.publish_rule(
      fixture.authority, allow_rule("allow-multimode", {satisfied_requirement()}, 10), MutationPolicy::AutoRetry);
  REQUIRE_OK(allow);
  const CompatDecision allowed = decide(registry, fixture.module);
  CHECK(allowed.outcome == CompatOutcome::Compatible);
  CHECK(allowed.closure == KnowledgeClosure::Closed);
  REQUIRE_EQ(allowed.matched_rules.size(), std::size_t{1});
  CHECK_EQ(allowed.matched_rules.front().name, std::string("allow-multimode"));
  CHECK(allowed.compatible());

  // A deny rule with higher priority wins over the matching allow rule.
  CompatRule deny = allow_rule("deny-high-power", {violated_requirement()}, 20);
  deny.verdict = CompatVerdict::Incompatible;
  deny.requirements = {module_requirement(CapabilityKey::MediaClass, RequirementOp::Equals,
                                          CapabilityValue::of(MediaClass::MultimodeFiber))};
  REQUIRE_OK(registry.publish_rule(fixture.authority, deny, MutationPolicy::AutoRetry));

  const CompatDecision denied = decide(registry, fixture.module);
  CHECK(denied.outcome == CompatOutcome::Incompatible);
  CHECK(denied.closure == KnowledgeClosure::Closed);
  REQUIRE_EQ(denied.matched_rules.size(), std::size_t{1});
  CHECK_EQ(denied.matched_rules.front().name, std::string("deny-high-power"));

  // Retirement is explicit and returns the pair to UNKNOWN.
  REQUIRE_OK(registry.retire_rule(fixture.authority, allow.value().id, MutationPolicy::AutoRetry));
  REQUIRE_OK(registry.retire_rule(fixture.authority, denied.matched_rules.front().id, MutationPolicy::AutoRetry));
  const CompatDecision retired = decide(registry, fixture.module);
  CHECK(retired.outcome == CompatOutcome::Unknown);
}

// An allow rule whose guard cannot be evaluated is UNKNOWN, never COMPATIBLE.
TRXREG_TEST(compatibility_indeterminate_requirement_is_unknown) {
  Registry registry;
  const Fixture fixture = prepare(registry);
  REQUIRE_OK(registry.publish_rule(fixture.authority,
                                   allow_rule("needs-reach", {satisfied_requirement(), indeterminate_requirement()}, 5),
                                   MutationPolicy::AutoRetry));

  const CompatDecision decision = decide(registry, fixture.module);
  CHECK(decision.outcome == CompatOutcome::Unknown);
  CHECK(decision.closure == KnowledgeClosure::Partial);
  CHECK_EQ(decision.indeterminate_rules, std::uint32_t{1});
  CHECK(!decision.compatible());
  REQUIRE(!decision.unmet_requirements.empty());
  bool saw_reach = false;
  for (const RequirementEvaluation& evaluation : decision.unmet_requirements) {
    if (evaluation.requirement.key == CapabilityKey::ReachClass) {
      saw_reach = true;
      CHECK(evaluation.state == RequirementState::Indeterminate);
    }
  }
  CHECK(saw_reach);
}

// An indeterminate *deny* rule blocks a matching allow rule: the deny might fire
// once the missing knowledge arrives.
TRXREG_TEST(compatibility_indeterminate_deny_blocks_approval) {
  Registry registry;
  const Fixture fixture = prepare(registry);
  REQUIRE_OK(registry.publish_rule(fixture.authority, allow_rule("allow-multimode", {satisfied_requirement()}, 1),
                                   MutationPolicy::AutoRetry));
  CompatRule deny = allow_rule("deny-without-reach", {indeterminate_requirement()}, 1);
  deny.verdict = CompatVerdict::Incompatible;
  REQUIRE_OK(registry.publish_rule(fixture.authority, deny, MutationPolicy::AutoRetry));

  const CompatDecision decision = decide(registry, fixture.module);
  CHECK(decision.outcome == CompatOutcome::Unknown);
  CHECK(!decision.compatible());
}

// Two sources that disagree about a capability make every requirement on it
// indeterminate.
TRXREG_TEST(compatibility_conflicting_capability_is_indeterminate) {
  Registry registry;
  const SourceHandle first = register_source(registry, "probe-agent");
  const SourceHandle second = register_source(registry, "vendor-tool");
  const ModuleHandle module = register_module(registry, first.authority(), "chassis0/bay2");
  publish_capability(registry, first.authority(), module, CapabilityKey::MediaClass,
                     CapabilityValue::of(MediaClass::MultimodeFiber));
  publish_capability(registry, second.authority(), module, CapabilityKey::MediaClass,
                     CapabilityValue::of(MediaClass::SingleModeFiber));
  publish_port_capability(registry, first.authority(), kPort, CapabilityKey::MediaClass,
                          CapabilityValue::of(MediaClass::MultimodeFiber));
  REQUIRE_OK(registry.publish_rule(first.authority(), allow_rule("allow-multimode", {satisfied_requirement()}, 1),
                                   MutationPolicy::AutoRetry));

  const CompatDecision decision = decide(registry, module);
  CHECK(decision.outcome == CompatOutcome::Unknown);
  CHECK(!decision.compatible());
  REQUIRE(!decision.unmet_requirements.empty());
  CHECK(decision.unmet_requirements.front().consensus == ConsensusOutcome::Conflicting);
}

TRXREG_TEST(compatibility_unsupported_verdict_is_reported) {
  Registry registry;
  const Fixture fixture = prepare(registry);
  CompatRule unsupported = allow_rule("unsupported-pairing", {satisfied_requirement()}, 5);
  unsupported.verdict = CompatVerdict::Unsupported;
  REQUIRE_OK(registry.publish_rule(fixture.authority, unsupported, MutationPolicy::AutoRetry));

  const CompatDecision decision = decide(registry, fixture.module);
  CHECK(decision.outcome == CompatOutcome::Unsupported);
  CHECK(decision.closure == KnowledgeClosure::Closed);
  CHECK(!decision.compatible());
  CHECK(!decision.undecided());
}

// Decisions are generation-fenced, and a fenced decision is refused rather than
// silently re-evaluated.
TRXREG_TEST(compatibility_decisions_are_generation_fenced) {
  Registry registry;
  const Fixture fixture = prepare(registry);
  REQUIRE_OK(registry.publish_rule(fixture.authority, allow_rule("allow-multimode", {satisfied_requirement()}, 1),
                                   MutationPolicy::AutoRetry));

  CompatQuery query;
  query.port = TRXREG_FIXTURE(PortKey::parse(kPort, "port key"));
  query.uid = fixture.module.uid;
  query.incarnation = fixture.module.incarnation;
  query.expected_generation = registry.generation();
  const Result<CompatDecision> decision = registry.query_compatibility(query);
  REQUIRE_OK(decision);
  CHECK_EQ(decision.value().generation, registry.generation());
  REQUIRE_OK(registry.verify_decision(decision.value()));

  // Any committed mutation invalidates the fence.
  REQUIRE_OK(registry.publish_rule(fixture.authority, allow_rule("second", {satisfied_requirement()}, 0),
                                   MutationPolicy::AutoRetry));
  REQUIRE_FAILS(registry.verify_decision(decision.value()), StatusCode::StaleGeneration);
  REQUIRE_FAILS(registry.query_compatibility(query), StatusCode::StaleGeneration);

  query.require_latest_generation = false;
  REQUIRE_OK(registry.query_compatibility(query));
}

TRXREG_TEST(compatibility_rejects_fenced_module_incarnations) {
  Registry registry;
  const Fixture fixture = prepare(registry, "chassis0/bay3");
  REQUIRE_OK(registry.publish_rule(fixture.authority, allow_rule("allow-multimode", {satisfied_requirement()}, 1),
                                   MutationPolicy::AutoRetry));
  const ModuleHandle replacement = register_module(registry, fixture.authority, "chassis0/bay3",
                                                   RegisterIntent::NewIncarnation, "Other Vendor", "OV-100G-LR4",
                                                   "SN-NEW");
  (void)replacement;

  CompatQuery query;
  query.port = TRXREG_FIXTURE(PortKey::parse(kPort, "port key"));
  query.uid = fixture.module.uid;
  query.incarnation = fixture.module.incarnation;
  query.require_latest_generation = false;
  REQUIRE_FAILS(registry.query_compatibility(query), StatusCode::Fenced);
}

// Rule publication order must not matter, and the explanation must name the
// rules that decided the outcome.
TRXREG_TEST(compatibility_rule_order_does_not_change_the_outcome) {
  const auto build = [](bool reverse) {
    Registry registry;
    const Fixture fixture = prepare(registry, "chassis0/bay4");
    CompatRule allow = allow_rule("allow-multimode", {satisfied_requirement()}, 1);
    CompatRule deny = allow_rule("deny-multimode", {satisfied_requirement()}, 9);
    deny.verdict = CompatVerdict::Incompatible;
    if (reverse) {
      TRXREG_FIXTURE(registry.publish_rule(fixture.authority, deny, MutationPolicy::AutoRetry));
      TRXREG_FIXTURE(registry.publish_rule(fixture.authority, allow, MutationPolicy::AutoRetry));
    } else {
      TRXREG_FIXTURE(registry.publish_rule(fixture.authority, allow, MutationPolicy::AutoRetry));
      TRXREG_FIXTURE(registry.publish_rule(fixture.authority, deny, MutationPolicy::AutoRetry));
    }
    return std::make_pair(decide(registry, fixture.module), registry.rules().size());
  };

  const auto forward = build(false);
  const auto backward = build(true);
  CHECK_EQ(forward.second, backward.second);
  CHECK(forward.first.outcome == backward.first.outcome);
  CHECK(forward.first.outcome == CompatOutcome::Incompatible);
  CHECK(forward.first.closure == backward.first.closure);
  REQUIRE_EQ(forward.first.matched_rules.size(), std::size_t{1});
  CHECK_EQ(forward.first.matched_rules.front().name, backward.first.matched_rules.front().name);
}

// Differential test against a small independent reference model.
//
// The model is written directly from the specification of the decision rule and
// shares no code with the library, so agreement is evidence rather than a
// restatement. Each generated rule is built from tokens that are known to be
// satisfied (S), violated (V), or indeterminate (I) on the fixture.
TRXREG_TEST(compatibility_matches_the_reference_model) {
  Random random(0x5eed1234ull);
  note("compatibility reference-model seed=" + std::to_string(0x5eed1234ull));

  for (int iteration = 0; iteration < 60; ++iteration) {
    const std::uint64_t seed = random.next();
    Random case_random(seed);

    struct RuleSpec {
      CompatVerdict verdict;
      std::vector<char> tokens;
      std::int32_t priority;
    };
    std::vector<RuleSpec> specs;
    const std::size_t rule_count = static_cast<std::size_t>(case_random.range(1, 5));
    for (std::size_t i = 0; i < rule_count; ++i) {
      RuleSpec spec;
      const int verdict_roll = static_cast<int>(case_random.range(0, 2));
      spec.verdict = verdict_roll == 0   ? CompatVerdict::Compatible
                     : verdict_roll == 1 ? CompatVerdict::Incompatible
                                         : CompatVerdict::Unsupported;
      spec.priority = static_cast<std::int32_t>(case_random.range(0, 5));
      const std::size_t requirement_count = static_cast<std::size_t>(case_random.range(1, 3));
      for (std::size_t r = 0; r < requirement_count; ++r) {
        static constexpr char kTokens[] = {'S', 'V', 'I'};
        spec.tokens.push_back(kTokens[case_random.below(3)]);
      }
      specs.push_back(std::move(spec));
    }

    // Reference model.
    bool deny_matched = false;
    bool unsupported_matched = false;
    bool allow_matched = false;
    bool any_indeterminate = false;
    for (const RuleSpec& spec : specs) {
      bool all_satisfied = true;
      bool any_indeterminate_token = false;
      for (const char token : spec.tokens) {
        if (token == 'V') {
          all_satisfied = false;
        } else if (token == 'I') {
          all_satisfied = false;
          any_indeterminate_token = true;
        }
      }
      if (all_satisfied) {
        if (spec.verdict == CompatVerdict::Incompatible) {
          deny_matched = true;
        } else if (spec.verdict == CompatVerdict::Unsupported) {
          unsupported_matched = true;
        } else {
          allow_matched = true;
        }
      } else if (any_indeterminate_token) {
        any_indeterminate = true;
      }
    }
    CompatOutcome expected = CompatOutcome::Unknown;
    if (deny_matched) {
      expected = CompatOutcome::Incompatible;
    } else if (unsupported_matched) {
      expected = CompatOutcome::Unsupported;
    } else if (allow_matched && !any_indeterminate) {
      expected = CompatOutcome::Compatible;
    }

    // The same rule set expressed against the real registry.
    Registry registry;
    const Fixture fixture = prepare(registry, "chassis0/bay5");
    bool expect_any_rule = false;
    for (std::size_t i = 0; i < specs.size(); ++i) {
      std::vector<Requirement> requirements;
      for (const char token : specs[i].tokens) {
        if (token == 'S') {
          requirements.push_back(satisfied_requirement());
        } else if (token == 'V') {
          requirements.push_back(violated_requirement());
        } else {
          requirements.push_back(indeterminate_requirement());
        }
      }
      CompatRule rule = allow_rule("rule-" + std::to_string(i), std::move(requirements), specs[i].priority);
      rule.verdict = specs[i].verdict;
      TRXREG_FIXTURE(registry.publish_rule(fixture.authority, rule, MutationPolicy::AutoRetry));
      expect_any_rule = true;
    }
    CHECK(expect_any_rule);

    const CompatDecision decision = decide(registry, fixture.module);
    if (decision.outcome != expected) {
      report_failure(__FILE__, __LINE__,
                     "case seed=" + std::to_string(seed) + " expected=" + outcome_text(expected) +
                         " observed=" + outcome_text(decision.outcome) + " rules=" + std::to_string(specs.size()));
    }
    // UNKNOWN never collapses to COMPATIBLE.
    if (expected == CompatOutcome::Unknown) {
      CHECK(!decision.compatible());
    }
  }
}
