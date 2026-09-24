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
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "trxreg/capability.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/digest.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/taxonomy.hpp"

namespace trxreg {

/// One condition a compatibility rule tests.
struct Requirement {
  RequirementSubject subject{RequirementSubject::Module};
  CapabilityKey key{CapabilityKey::Unknown};
  std::string subkey;
  RequirementOp op{RequirementOp::Unknown};
  CapabilityValue operand{};
  std::string note;

  friend bool operator==(const Requirement& lhs, const Requirement& rhs) noexcept = default;
};

/// Three-valued evaluation of a requirement. `Indeterminate` means the runtime
/// cannot establish the attribute; it is never treated as satisfied.
enum class RequirementState : std::uint8_t {
  Satisfied = 0,
  Violated,
  Indeterminate,
};

/// A declared compatibility rule. Rules are published by sources, versioned by
/// registry generation, and never overwrite each other: two rules with the same
/// name but different ids are distinct knowledge.
struct CompatRule {
  std::string name;
  std::vector<Requirement> requirements;
  /// Verdict asserted when every requirement is satisfied.
  CompatVerdict verdict{CompatVerdict::Compatible};
  /// Higher priority is evaluated first; ties are broken by rule id.
  std::int32_t priority{0};
  std::string rationale;
  Provenance provenance{};
  bool enabled{true};

  friend bool operator==(const CompatRule& lhs, const CompatRule& rhs) noexcept = default;
};

/// A published rule with its registry identity and authority.
struct CompatRuleRecord {
  RuleId id{};
  CompatRule rule{};
  SourceId source{};
  SourceEpoch source_epoch{};
  Generation generation{};
  Sequence sequence{};
  bool live{true};

  friend bool operator==(const CompatRuleRecord& lhs, const CompatRuleRecord& rhs) noexcept = default;
};

struct CompatRuleHandle {
  RuleId id{};
  Generation generation{};
};

/// Outcome of a compatibility query. `Unknown` is the answer whenever the
/// knowledge needed to decide is absent, incomplete, or conflicted.
enum class CompatOutcome : std::uint8_t {
  Unknown = 0,
  Compatible,
  Incompatible,
  Unsupported,
};

/// Whether the rule set closed the question.
enum class KnowledgeClosure : std::uint8_t {
  /// No rule addressed the question at all.
  Open = 0,
  /// Rules addressed the question but at least one could not be evaluated.
  Partial,
  /// The deciding rules were fully evaluated.
  Closed,
};

std::string_view to_string(CompatOutcome outcome) noexcept;
std::string_view to_string(KnowledgeClosure closure) noexcept;
std::string_view to_string(RequirementState state) noexcept;
bool compat_outcome_from_string(std::string_view text, CompatOutcome& out) noexcept;
bool knowledge_closure_from_string(std::string_view text, KnowledgeClosure& out) noexcept;
bool requirement_state_from_string(std::string_view text, RequirementState& out) noexcept;

struct RequirementEvaluation {
  Requirement requirement{};
  RequirementState state{RequirementState::Indeterminate};
  ConsensusOutcome consensus{ConsensusOutcome::Unknown};
  bool has_observed{false};
  CapabilityValue observed{};
  std::string detail;

  friend bool operator==(const RequirementEvaluation& lhs, const RequirementEvaluation& rhs) noexcept = default;
};

struct MatchedRule {
  RuleId id{};
  std::string name;
  CompatVerdict verdict{CompatVerdict::Compatible};
  std::int32_t priority{0};
  Generation generation{};
  std::string rationale;
  std::vector<RequirementEvaluation> requirements;

  friend bool operator==(const MatchedRule& lhs, const MatchedRule& rhs) noexcept = default;
};

/// Complete, explainable compatibility answer.
struct CompatDecision {
  CompatOutcome outcome{CompatOutcome::Unknown};
  KnowledgeClosure closure{KnowledgeClosure::Open};
  PortKey port{};
  ModuleUid uid{};
  IncarnationId incarnation{};
  Generation generation{};
  std::uint32_t considered_rules{0};
  std::uint32_t indeterminate_rules{0};
  std::vector<MatchedRule> matched_rules;
  /// Requirements the deciding rules could not establish.
  std::vector<RequirementEvaluation> unmet_requirements;
  /// Requirements that evaluated false for considered rules.
  std::vector<RequirementEvaluation> violated_requirements;
  Digest inputs_digest{};
  Digest decision_digest{};
  WallNs evaluated_at_wall_ns{0};
  ClockDomainId clock_domain{};
  std::string explanation;

  friend bool operator==(const CompatDecision& lhs, const CompatDecision& rhs) noexcept = default;

  /// True when the decision is Compatible.
  [[nodiscard]] bool compatible() const noexcept { return outcome == CompatOutcome::Compatible; }
  /// True when the runtime could not decide; callers must not read this as approval.
  [[nodiscard]] bool undecided() const noexcept { return outcome == CompatOutcome::Unknown; }
};

struct CompatQuery {
  PortKey port{};
  ModuleUid uid{};
  IncarnationId incarnation{};
  /// When set, the query is fenced: it is refused if the registry has moved on.
  bool require_latest_generation{true};
  Generation expected_generation{};
  bool explain{true};
  std::uint32_t max_rules{1024};
};

/// Resolver used by the decision algorithm to read one attribute of one subject.
using AttributeResolver =
    std::function<const CapabilityConsensus*(RequirementSubject subject, CapabilityKey key, std::string_view subkey)>;

/// Evaluate one requirement against the resolved attributes.
RequirementEvaluation evaluate_requirement(const Requirement& requirement, const AttributeResolver& resolver);

/// Deterministic rule evaluation. This is a pure function of its inputs: the
/// rule set order does not matter, only (priority, rule id) ordering does.
CompatDecision evaluate_compatibility(const CompatQuery& query, const std::vector<CompatRuleRecord>& rules,
                                      const AttributeResolver& resolver, Generation generation, WallNs now,
                                      ClockDomainId domain);

/// Human-readable rendering of a decision, used by the CLI and the tests.
std::string explain_decision(const CompatDecision& decision);

}  // namespace trxreg
