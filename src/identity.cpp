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

#include "trxreg/identity.hpp"

#include <algorithm>
#include <map>
#include <span>
#include <utility>

#include "domain.hpp"

namespace trxreg {
namespace detail {
namespace {

void write_claim_canonical(CanonicalWriter& writer, const IdentityClaim& claim) {
  writer.begin_object(8);
  writer.field("epoch");
  writer.integer(static_cast<std::int64_t>(claim.source_epoch.value()));
  writer.field("generation");
  writer.integer(static_cast<std::int64_t>(claim.generation.value()));
  writer.field("observed_at");
  writer.integer(claim.observed_at_wall_ns);
  writer.field("origin");
  writer.text(claim.provenance.origin);
  writer.field("sequence");
  writer.integer(static_cast<std::int64_t>(claim.sequence.value()));
  writer.field("source");
  writer.integer(static_cast<std::int64_t>(claim.source.value()));
  writer.field("value");
  writer.text(claim.value);
  writer.field("provenance_kind");
  writer.integer(static_cast<std::int64_t>(claim.provenance.kind));
  writer.end_object();
}

Digest digest_live_claims(const std::vector<IdentityClaim>& claims) {
  CanonicalWriter writer;
  writer.begin_array(static_cast<std::uint64_t>(claims.size()));
  for (const IdentityClaim& claim : claims) {
    write_claim_canonical(writer, claim);
  }
  writer.end_array();
  return writer.digest();
}

}  // namespace

std::vector<FieldConsensus> build_identity_consensus(std::vector<IdentityClaim> claims) {
  // Group by (field, subkey) so the caller's ordering can never influence the
  // result. std::map gives the canonical ordering for free.
  std::map<std::pair<std::uint8_t, std::string>, std::vector<IdentityClaim>> grouped;
  for (IdentityClaim& claim : claims) {
    grouped[{static_cast<std::uint8_t>(claim.field), claim.subkey}].push_back(std::move(claim));
  }

  std::vector<FieldConsensus> result;
  result.reserve(grouped.size());
  for (auto& entry : grouped) {
    FieldConsensus consensus;
    consensus.field = static_cast<IdentityField>(entry.first.first);
    consensus.subkey = entry.first.second;

    std::vector<IdentityClaim> live;
    std::vector<IdentityClaim> superseded;
    for (IdentityClaim& claim : entry.second) {
      if (claim.live) {
        live.push_back(std::move(claim));
      } else {
        superseded.push_back(std::move(claim));
      }
    }

    const auto by_sequence = [](const IdentityClaim& lhs, const IdentityClaim& rhs) {
      return lhs.sequence < rhs.sequence;
    };
    std::stable_sort(live.begin(), live.end(), by_sequence);
    std::stable_sort(superseded.begin(), superseded.end(), by_sequence);

    // A source revising its own claim supersedes its earlier claim; it does not
    // conflict with it. Only claims from *different* sources are compared.
    std::vector<IdentityClaim> newest_per_source;
    for (IdentityClaim& claim : live) {
      const auto existing = std::find_if(newest_per_source.begin(), newest_per_source.end(),
                                         [&claim](const IdentityClaim& other) {
                                           return other.source == claim.source &&
                                                  other.source_epoch == claim.source_epoch;
                                         });
      if (existing == newest_per_source.end()) {
        newest_per_source.push_back(std::move(claim));
      } else {
        superseded.push_back(std::move(*existing));
        *existing = std::move(claim);
      }
    }
    std::stable_sort(superseded.begin(), superseded.end(), by_sequence);
    live = std::move(newest_per_source);

    if (live.empty()) {
      consensus.outcome = superseded.empty() ? ConsensusOutcome::Unknown : ConsensusOutcome::Superseded;
    } else if (live.size() == 1) {
      consensus.outcome = ConsensusOutcome::SingleSource;
      consensus.has_value = true;
      consensus.value = live.front().value;
    } else {
      bool agrees = true;
      for (std::size_t i = 1; i < live.size(); ++i) {
        if (live[i].value != live.front().value) {
          agrees = false;
          break;
        }
      }
      consensus.outcome = agrees ? ConsensusOutcome::Agreed : ConsensusOutcome::Conflicting;
      if (agrees) {
        consensus.has_value = true;
        consensus.value = live.front().value;
      }
    }

    consensus.digest = digest_live_claims(live);
    consensus.claims = std::move(live);
    consensus.superseded_claims = std::move(superseded);
    result.push_back(std::move(consensus));
  }
  return result;
}

}  // namespace detail

const FieldConsensus* IdentityView::find(IdentityField field, std::string_view subkey) const noexcept {
  for (const FieldConsensus& consensus : fields) {
    if (consensus.field == field && consensus.subkey == subkey) {
      return &consensus;
    }
  }
  return nullptr;
}

Digest digest_identity_fields(const std::vector<FieldConsensus>& fields) {
  CanonicalWriter writer;
  writer.begin_array(static_cast<std::uint64_t>(fields.size()));
  for (const FieldConsensus& consensus : fields) {
    writer.begin_object(4);
    writer.field("digest");
    writer.binary(std::as_bytes(std::span<const std::uint8_t>(consensus.digest.bytes.data(),
                                                             consensus.digest.bytes.size())));
    writer.field("field");
    writer.integer(static_cast<std::int64_t>(consensus.field));
    writer.field("outcome");
    writer.integer(static_cast<std::int64_t>(consensus.outcome));
    writer.field("subkey");
    writer.text(consensus.subkey);
    writer.end_object();
  }
  writer.end_array();
  return writer.digest();
}

}  // namespace trxreg
