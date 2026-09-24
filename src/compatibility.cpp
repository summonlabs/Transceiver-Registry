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

#include "trxreg/compatibility.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "domain.hpp"

namespace trxreg {
namespace {

using EnumSet = CapabilityValue::EnumSet;
using TextSet = CapabilityValue::TextSet;

bool is_set_kind(CapabilityValueKind kind) noexcept {
  return kind == CapabilityValueKind::EnumSet || kind == CapabilityValueKind::TextSet ||
         kind == CapabilityValueKind::Spectrum;
}

std::string format_number(double value) {
  char buffer[40];
  const int written = std::snprintf(buffer, sizeof(buffer), "%.6g", value);
  return written > 0 ? std::string(buffer, static_cast<std::size_t>(written)) : std::string("nan");
}

RequirementEvaluation indeterminate(const Requirement& requirement, std::string detail) {
  RequirementEvaluation evaluation;
  evaluation.requirement = requirement;
  evaluation.state = RequirementState::Indeterminate;
  evaluation.detail = std::move(detail);
  return evaluation;
}

/// Set intersection test for the set-valued operators.
bool sets_intersect(const CapabilityValue& lhs, const CapabilityValue& rhs, bool& comparable) {
  comparable = true;
  if (lhs.kind() == CapabilityValueKind::EnumSet && rhs.kind() == CapabilityValueKind::EnumSet) {
    const EnumSet& left = *lhs.as_enum_set();
    const EnumSet& right = *rhs.as_enum_set();
    for (const std::int64_t value : left) {
      if (std::find(right.begin(), right.end(), value) != right.end()) {
        return true;
      }
    }
    return false;
  }
  if (lhs.kind() == CapabilityValueKind::TextSet && rhs.kind() == CapabilityValueKind::TextSet) {
    const TextSet& left = *lhs.as_text_set();
    const TextSet& right = *rhs.as_text_set();
    for (const std::string& value : left) {
      if (std::find(right.begin(), right.end(), value) != right.end()) {
        return true;
      }
    }
    return false;
  }
  comparable = false;
  return false;
}

bool set_contains(const CapabilityValue& superset, const CapabilityValue& subset, bool& comparable) {
  comparable = true;
  if (superset.kind() == CapabilityValueKind::EnumSet && subset.kind() == CapabilityValueKind::EnumSet) {
    const EnumSet& left = *superset.as_enum_set();
    const EnumSet& right = *subset.as_enum_set();
    for (const std::int64_t value : right) {
      if (std::find(left.begin(), left.end(), value) == left.end()) {
        return false;
      }
    }
    return true;
  }
  if (superset.kind() == CapabilityValueKind::TextSet && subset.kind() == CapabilityValueKind::TextSet) {
    const TextSet& left = *superset.as_text_set();
    const TextSet& right = *subset.as_text_set();
    for (const std::string& value : right) {
      if (std::find(left.begin(), left.end(), value) == left.end()) {
        return false;
      }
    }
    return true;
  }
  comparable = false;
  return false;
}

RequirementEvaluation apply_operator(const Requirement& requirement, const CapabilityValue& observed,
                                     RequirementEvaluation evaluation) {
  switch (requirement.op) {
    case RequirementOp::Equals:
    case RequirementOp::NotEquals: {
      const bool equal = detail::capability_values_equal(observed, requirement.operand);
      const bool satisfied = requirement.op == RequirementOp::Equals ? equal : !equal;
      evaluation.state = satisfied ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = satisfied ? "attribute equals the required value" : "attribute differs from the required value";
      return evaluation;
    }
    case RequirementOp::In:
    case RequirementOp::NotIn: {
      bool comparable = false;
      const bool contained = set_contains(requirement.operand, observed, comparable);
      if (!comparable) {
        return indeterminate(requirement, "operator 'in' requires a set operand and a scalar attribute");
      }
      const bool satisfied = requirement.op == RequirementOp::In ? contained : !contained;
      evaluation.state = satisfied ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = satisfied ? "attribute is a member of the required set"
                                    : "attribute is not a member of the required set";
      return evaluation;
    }
    case RequirementOp::SupersetOf: {
      bool comparable = false;
      const bool superset = set_contains(observed, requirement.operand, comparable);
      if (!comparable) {
        return indeterminate(requirement, "operator 'superset_of' requires set-valued attribute and operand");
      }
      evaluation.state = superset ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = superset ? "attribute covers every required member" : "attribute is missing a required member";
      return evaluation;
    }
    case RequirementOp::SubsetOf: {
      bool comparable = false;
      const bool subset = set_contains(requirement.operand, observed, comparable);
      if (!comparable) {
        return indeterminate(requirement, "operator 'subset_of' requires set-valued attribute and operand");
      }
      evaluation.state = subset ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = subset ? "attribute is contained in the allowed set"
                                 : "attribute contains a member outside the allowed set";
      return evaluation;
    }
    case RequirementOp::Overlaps:
    case RequirementOp::DisjointFrom: {
      bool comparable = false;
      const bool intersects = sets_intersect(observed, requirement.operand, comparable);
      if (!comparable) {
        return indeterminate(requirement, "operator requires set-valued attribute and operand");
      }
      const bool satisfied = requirement.op == RequirementOp::Overlaps ? intersects : !intersects;
      evaluation.state = satisfied ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = satisfied ? "attribute sets satisfy the relation" : "attribute sets do not satisfy the relation";
      return evaluation;
    }
    case RequirementOp::AtMost:
    case RequirementOp::AtLeast: {
      double left = 0.0;
      double right = 0.0;
      if (!observed.number_as_double(left) || !requirement.operand.number_as_double(right)) {
        return indeterminate(requirement, "comparison operators require numeric attribute and operand");
      }
      const bool satisfied =
          requirement.op == RequirementOp::AtMost ? left <= right : left >= right;
      evaluation.state = satisfied ? RequirementState::Satisfied : RequirementState::Violated;
      evaluation.detail = std::string("attribute ") + format_number(left) +
                          (satisfied ? " satisfies " : " violates ") +
                          (requirement.op == RequirementOp::AtMost ? "at_most " : "at_least ") + format_number(right);
      return evaluation;
    }
    case RequirementOp::Unknown:
    default:
      return indeterminate(requirement, "requirement operator is not modelled");
  }
}

}  // namespace

namespace detail {

Status validate_rule(const CompatRule& rule) {
  if (rule.name.empty()) {
    return Status(StatusCode::InvalidArgument, "compatibility rule must have a name");
  }
  if (rule.name.size() > 128) {
    return Status(StatusCode::InvalidArgument, "compatibility rule name is too long");
  }
  if (rule.requirements.empty()) {
    return Status(StatusCode::InvalidArgument, "compatibility rule must declare at least one requirement");
  }
  if (rule.verdict == CompatVerdict::Unknown) {
    return Status(StatusCode::InvalidArgument, "compatibility rule must declare a verdict");
  }
  for (const Requirement& requirement : rule.requirements) {
    if (requirement.key == CapabilityKey::Unknown || requirement.key == CapabilityKey::Unsupported) {
      return Status(StatusCode::InvalidArgument, "requirement must name a modelled capability key");
    }
    if (requirement.op == RequirementOp::Unknown) {
      return Status(StatusCode::InvalidArgument, "requirement must name a modelled operator");
    }
    const CapabilityValueKind expected = capability_value_kind(requirement.key);
    const CapabilityValueKind operand_kind = requirement.operand.kind();
    switch (requirement.op) {
      case RequirementOp::Equals:
      case RequirementOp::NotEquals:
        TRXREG_TRY(requirement.operand.validate_for(requirement.key));
        break;
      case RequirementOp::In:
      case RequirementOp::NotIn:
      case RequirementOp::SupersetOf:
      case RequirementOp::SubsetOf:
      case RequirementOp::Overlaps:
      case RequirementOp::DisjointFrom:
        if (!is_set_kind(operand_kind)) {
          return Status(StatusCode::InvalidArgument, "set operators require a set-valued operand");
        }
        if (expected != operand_kind && !(expected == CapabilityValueKind::Enum && operand_kind == CapabilityValueKind::EnumSet)) {
          return Status(StatusCode::InvalidArgument, "operand shape does not match the capability key");
        }
        break;
      case RequirementOp::AtMost:
      case RequirementOp::AtLeast:
        if (operand_kind != CapabilityValueKind::Count && operand_kind != CapabilityValueKind::Real) {
          return Status(StatusCode::InvalidArgument, "comparison operators require a numeric operand");
        }
        break;
      case RequirementOp::Unknown:
        break;
    }
    if (requirement.subkey.size() > 128) {
      return Status(StatusCode::InvalidArgument, "requirement subkey is too long");
    }
  }
  return ok_status();
}

}  // namespace detail

RequirementEvaluation evaluate_requirement(const Requirement& requirement, const AttributeResolver& resolver) {
  RequirementEvaluation evaluation;
  evaluation.requirement = requirement;
  if (!resolver) {
    return indeterminate(requirement, "no attribute resolver is available");
  }
  const CapabilityConsensus* attribute = resolver(requirement.subject, requirement.key, requirement.subkey);
  if (attribute == nullptr) {
    return indeterminate(requirement, "no source has declared this attribute");
  }
  evaluation.consensus = attribute->outcome;
  if (attribute->outcome == ConsensusOutcome::Conflicting) {
    // Keep the consensus outcome on the evaluation so the caller can explain
    // *why* the requirement is undecided.
    evaluation.state = RequirementState::Indeterminate;
    evaluation.detail = "live sources disagree about this attribute";
    return evaluation;
  }
  if (!attribute->established()) {
    evaluation.state = RequirementState::Indeterminate;
    evaluation.detail = "this attribute is not established by live evidence";
    return evaluation;
  }
  evaluation.has_observed = true;
  evaluation.observed = attribute->value;
  return apply_operator(requirement, attribute->value, evaluation);
}

namespace {

void write_attribute_reference(CanonicalWriter& writer, RequirementSubject subject, CapabilityKey key,
                               std::string_view subkey, const CapabilityConsensus* attribute) {
  writer.begin_object(6);
  writer.field("key");
  writer.integer(static_cast<std::int64_t>(key));
  writer.field("outcome");
  writer.integer(static_cast<std::int64_t>(attribute != nullptr ? attribute->outcome : ConsensusOutcome::Unknown));
  writer.field("subject");
  writer.integer(static_cast<std::int64_t>(subject));
  writer.field("subkey");
  writer.text(subkey);
  writer.field("has_value");
  writer.boolean(attribute != nullptr && attribute->has_value);
  writer.field("value");
  if (attribute != nullptr && attribute->has_value) {
    write_canonical(writer, attribute->value);
  } else {
    writer.null_value();
  }
  writer.end_object();
}

Digest digest_inputs(const CompatQuery& query, const std::vector<CompatRuleRecord>& rules,
                     const AttributeResolver& resolver) {
  // Collect the distinct attribute references the rule set depends on, in a
  // deterministic order, so the digest is a pure function of the knowledge used.
  std::set<std::tuple<std::uint8_t, std::uint8_t, std::string>> references;
  for (const CompatRuleRecord& record : rules) {
    for (const Requirement& requirement : record.rule.requirements) {
      references.insert({static_cast<std::uint8_t>(requirement.subject), static_cast<std::uint8_t>(requirement.key),
                         requirement.subkey});
    }
  }

  CanonicalWriter writer;
  writer.begin_object(4);
  writer.field("incarnation");
  writer.integer(static_cast<std::int64_t>(query.incarnation.value()));
  writer.field("port");
  writer.text(query.port.str());
  writer.field("attributes");
  writer.begin_array(static_cast<std::uint64_t>(references.size()));
  for (const auto& reference : references) {
    const auto subject = static_cast<RequirementSubject>(std::get<0>(reference));
    const auto key = static_cast<CapabilityKey>(std::get<1>(reference));
    const std::string& subkey = std::get<2>(reference);
    const CapabilityConsensus* attribute = resolver ? resolver(subject, key, subkey) : nullptr;
    write_attribute_reference(writer, subject, key, subkey, attribute);
  }
  writer.end_array();
  writer.field("uid");
  writer.integer(static_cast<std::int64_t>(query.uid.value()));
  writer.end_object();
  return writer.digest();
}

}  // namespace

CompatDecision evaluate_compatibility(const CompatQuery& query, const std::vector<CompatRuleRecord>& rules,
                                      const AttributeResolver& resolver, Generation generation, WallNs now,
                                      ClockDomainId domain) {
  CompatDecision decision;
  decision.port = query.port;
  decision.uid = query.uid;
  decision.incarnation = query.incarnation;
  decision.generation = generation;
  decision.evaluated_at_wall_ns = now;
  decision.clock_domain = domain;

  // Deterministic ordering: priority first, then rule id. The caller's vector
  // order can never change the outcome.
  std::vector<const CompatRuleRecord*> ordered;
  ordered.reserve(rules.size());
  for (const CompatRuleRecord& record : rules) {
    if (record.live && record.rule.enabled) {
      ordered.push_back(&record);
    }
  }
  std::sort(ordered.begin(), ordered.end(), [](const CompatRuleRecord* lhs, const CompatRuleRecord* rhs) {
    if (lhs->rule.priority != rhs->rule.priority) {
      return lhs->rule.priority > rhs->rule.priority;
    }
    return lhs->id < rhs->id;
  });

  if (ordered.size() > query.max_rules) {
    ordered.resize(query.max_rules);
  }

  std::vector<MatchedRule> matched_denies;
  std::vector<MatchedRule> matched_unsupported;
  std::vector<MatchedRule> matched_allows;
  std::vector<MatchedRule> indeterminate_rules;

  for (const CompatRuleRecord* record : ordered) {
    ++decision.considered_rules;
    MatchedRule evaluated;
    evaluated.id = record->id;
    evaluated.name = record->rule.name;
    evaluated.verdict = record->rule.verdict;
    evaluated.priority = record->rule.priority;
    evaluated.generation = record->generation;
    evaluated.rationale = record->rule.rationale;

    bool all_satisfied = true;
    bool any_indeterminate = false;
    for (const Requirement& requirement : record->rule.requirements) {
      RequirementEvaluation evaluation = evaluate_requirement(requirement, resolver);
      if (evaluation.state == RequirementState::Violated) {
        all_satisfied = false;
        decision.violated_requirements.push_back(evaluation);
      } else if (evaluation.state == RequirementState::Indeterminate) {
        all_satisfied = false;
        any_indeterminate = true;
      }
      evaluated.requirements.push_back(std::move(evaluation));
    }

    if (all_satisfied) {
      switch (record->rule.verdict) {
        case CompatVerdict::Incompatible:
          matched_denies.push_back(std::move(evaluated));
          break;
        case CompatVerdict::Unsupported:
          matched_unsupported.push_back(std::move(evaluated));
          break;
        case CompatVerdict::Compatible:
          matched_allows.push_back(std::move(evaluated));
          break;
        case CompatVerdict::Unknown:
          break;
      }
    } else if (any_indeterminate) {
      // A rule whose guard cannot be evaluated is not "not applicable": it is
      // undecided, and it may never be read as approval.
      for (const RequirementEvaluation& evaluation : evaluated.requirements) {
        if (evaluation.state == RequirementState::Indeterminate) {
          decision.unmet_requirements.push_back(evaluation);
        }
      }
      indeterminate_rules.push_back(std::move(evaluated));
    }
  }

  decision.indeterminate_rules = static_cast<std::uint32_t>(indeterminate_rules.size());
  decision.inputs_digest = digest_inputs(query, rules, resolver);

  if (!matched_denies.empty()) {
    decision.outcome = CompatOutcome::Incompatible;
    decision.closure = KnowledgeClosure::Closed;
    decision.matched_rules = std::move(matched_denies);
  } else if (!matched_unsupported.empty()) {
    decision.outcome = CompatOutcome::Unsupported;
    decision.closure = KnowledgeClosure::Closed;
    decision.matched_rules = std::move(matched_unsupported);
  } else if (!matched_allows.empty() && indeterminate_rules.empty()) {
    decision.outcome = CompatOutcome::Compatible;
    decision.closure = KnowledgeClosure::Closed;
    decision.matched_rules = std::move(matched_allows);
  } else {
    // Either nothing addressed the question, or something that addressed it
    // could not be evaluated. Both answers are UNKNOWN, distinguished by the
    // knowledge closure so the caller can tell "no rules" from "incomplete".
    decision.outcome = CompatOutcome::Unknown;
    // Open means no rule addressed the pair in a way that could approve it and
    // none is waiting on missing knowledge: the knowledge base simply does not
    // cover the question. Partial means some rule is waiting for evidence.
    decision.closure = indeterminate_rules.empty() ? KnowledgeClosure::Open : KnowledgeClosure::Partial;
    decision.matched_rules = std::move(matched_allows);
    for (MatchedRule& rule : indeterminate_rules) {
      decision.matched_rules.push_back(std::move(rule));
    }
    if (decision.closure == KnowledgeClosure::Open) {
      decision.explanation =
          "no compatibility rule approves this port/module pair: absence of a rule is UNKNOWN, not approval";
    }
  }

  if (query.explain) {
    decision.explanation = explain_decision(decision);
  }

  CanonicalWriter writer;
  writer.begin_object(8);
  writer.field("closure");
  writer.integer(static_cast<std::int64_t>(decision.closure));
  writer.field("considered_rules");
  writer.integer(decision.considered_rules);
  writer.field("generation");
  writer.integer(static_cast<std::int64_t>(generation.value()));
  writer.field("inputs_digest");
  writer.binary(std::as_bytes(std::span<const std::uint8_t>(decision.inputs_digest.bytes.data(),
                                                           decision.inputs_digest.bytes.size())));
  writer.field("matched");
  writer.begin_array(static_cast<std::uint64_t>(decision.matched_rules.size()));
  for (const MatchedRule& rule : decision.matched_rules) {
    writer.begin_object(3);
    writer.field("id");
    writer.integer(static_cast<std::int64_t>(rule.id.value()));
    writer.field("name");
    writer.text(rule.name);
    writer.field("verdict");
    writer.integer(static_cast<std::int64_t>(rule.verdict));
    writer.end_object();
  }
  writer.end_array();
  writer.field("outcome");
  writer.integer(static_cast<std::int64_t>(decision.outcome));
  writer.field("uid");
  writer.integer(static_cast<std::int64_t>(decision.uid.value()));
  writer.field("incarnation");
  writer.integer(static_cast<std::int64_t>(decision.incarnation.value()));
  writer.end_object();
  decision.decision_digest = writer.digest();

  return decision;
}

std::string explain_decision(const CompatDecision& decision) {
  std::string out;
  out += "outcome=";
  switch (decision.outcome) {
    case CompatOutcome::Compatible:
      out += "COMPATIBLE";
      break;
    case CompatOutcome::Incompatible:
      out += "INCOMPATIBLE";
      break;
    case CompatOutcome::Unsupported:
      out += "UNSUPPORTED";
      break;
    case CompatOutcome::Unknown:
      out += "UNKNOWN";
      break;
  }
  out += " closure=";
  switch (decision.closure) {
    case KnowledgeClosure::Open:
      out += "open";
      break;
    case KnowledgeClosure::Partial:
      out += "partial";
      break;
    case KnowledgeClosure::Closed:
      out += "closed";
      break;
  }
  out += " generation=";
  out += std::to_string(decision.generation.value());
  out += " port=";
  out += decision.port.str();
  out += " module=";
  out += std::to_string(decision.uid.value());
  out += "/";
  out += std::to_string(decision.incarnation.value());
  out += "\n";
  out += "considered_rules=";
  out += std::to_string(decision.considered_rules);
  out += " indeterminate_rules=";
  out += std::to_string(decision.indeterminate_rules);
  out += "\n";
  for (const MatchedRule& rule : decision.matched_rules) {
    out += "  rule ";
    out += std::to_string(rule.id.value());
    out += " '";
    out += rule.name;
    out += "' verdict=";
    out += std::string(to_string(rule.verdict));
    out += " priority=";
    out += std::to_string(rule.priority);
    if (!rule.rationale.empty()) {
      out += " rationale='";
      out += rule.rationale;
      out += "'";
    }
    out += "\n";
    for (const RequirementEvaluation& evaluation : rule.requirements) {
      out += "    requirement ";
      out += std::string(to_string(evaluation.requirement.subject));
      out += ".";
      out += std::string(to_string(evaluation.requirement.key));
      out += " ";
      out += std::string(to_string(evaluation.requirement.op));
      out += " -> ";
      switch (evaluation.state) {
        case RequirementState::Satisfied:
          out += "satisfied";
          break;
        case RequirementState::Violated:
          out += "violated";
          break;
        case RequirementState::Indeterminate:
          out += "indeterminate";
          break;
      }
      if (evaluation.has_observed) {
        out += " (observed=";
        out += evaluation.observed.describe(evaluation.requirement.key);
        out += ")";
      }
      if (!evaluation.detail.empty()) {
        out += ": ";
        out += evaluation.detail;
      }
      out += "\n";
    }
  }
  for (const RequirementEvaluation& evaluation : decision.unmet_requirements) {
    out += "  unmet requirement ";
    out += std::string(to_string(evaluation.requirement.key));
    out += ": ";
    out += evaluation.detail.empty() ? std::string("not established") : evaluation.detail;
    out += "\n";
  }
  if (decision.matched_rules.empty() && decision.closure == KnowledgeClosure::Open) {
    out += "  no rule approves this pair: absence of a rule is UNKNOWN, not approval\n";
  }
  return out;
}

}  // namespace trxreg
