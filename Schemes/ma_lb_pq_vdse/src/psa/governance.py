"""``AA(PID_i)`` — which Attribute Authorities govern a policy.

The manuscript leans on this set everywhere in Phases IV, VI and VII: the
policy-relevant version state is ``V_{P_i} = {(ID_k, v_k) : AA_k ∈ AA(PID_i)}``
(eq:policy-version-state), Policy-State Non-Interference is the statement that
``AA_k ∉ AA(PID_i) ⟹ PV_i' = PV_i`` (eq:unaffected-policy), and DIAS's
dependency closure starts from ``P_k^aff = {P_ℓ : AA_k ∈ AA(PID_ℓ)}``.

**Section V never states how large that set is**, so its size is a `benchmark`
choice here, not a `published` one — the same provenance class as
``authorities.attributes_per_authority`` in ``global.yaml``, and recorded for
the same reason.

WHY THE DEFAULT IS NOT 1
------------------------
The deployed topology is one AA per administrative domain
(``global.yaml: authority_to_domain: one_to_one``) and every policy id is
``"<domain>/pol<N>"`` — scoped to a single domain. Read literally, that makes
``AA(PID_i)`` a **singleton**, and with a singleton the manuscript's central
claim is vacuous rather than true: with one governing authority there is no
"unrelated authority" whose update could have invalidated the index, so
non-interference holds trivially and measures nothing. Exp. 6's affected-policy
ratio would likewise be pinned to 1/N_AA.

So a policy is governed by ``authorities_per_policy`` AAs: its own domain's
authority, plus further authorities drawn deterministically from the roster by
hashing the policy id. This is exactly the cross-domain sharing the paper
motivates in §I ("a cardiologist may query ... across multiple domains", "a
research AA should not update emergency records governed only by hospital and
emergency AAs") — that second example only makes sense when a policy names more
than one authority and *fewer* than all of them.

``authorities_per_policy = 1`` is still supported and reproduces the singleton
reading, so the degenerate case can be measured rather than assumed away.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Mapping, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

#: Benchmark default. Two of four AAs governs each policy, which is the smallest
#: value for which BOTH halves of the manuscript's claim have something to say:
#: an update by a governing AA must propagate, and an update by a non-governing
#: AA must not. At 1 the second half is vacuous; at N_AA the first half is.
DEFAULT_AUTHORITIES_PER_POLICY = 2


class GovernanceError(RuntimeError):
    """Raised when a policy cannot be mapped to a governing authority set."""


@dataclass(frozen=True, eq=False)
class PolicyGovernance:
    """``PID_i ↦ AA(PID_i)``, deterministic and reproducible.

    ``authority_ids`` is the full roster; ``domain_of`` names the authority that
    owns each domain, so a policy always includes its own domain's AA. The rest
    are drawn by hashing the policy id, which makes the assignment stable across
    processes and runs without storing a table.
    """

    authority_ids: Tuple[str, ...]
    domain_authority: Mapping[str, str]
    authorities_per_policy: int = DEFAULT_AUTHORITIES_PER_POLICY
    #: Policies whose governing set is stated outright rather than derived.
    #: Exp. 6 sweeps the AFFECTED-POLICY RATIO (D8), which means it must be able
    #: to say "this authority governs exactly 30% of the population". The hash
    #: draw cannot be asked for a target ratio -- it produces whatever it
    #: produces (see `coverage`) -- so the experiment states the mapping and
    #: everything downstream, including PV_i, follows from it unchanged.
    overrides: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.authority_ids:
            raise GovernanceError("the authority roster must not be empty")
        if list(self.authority_ids) != sorted(self.authority_ids):
            raise GovernanceError(
                "authority_ids must be sorted so AA(PID) is order-independent"
            )
        if len(set(self.authority_ids)) != len(self.authority_ids):
            raise GovernanceError("duplicate authority id in the roster")
        if not 1 <= self.authorities_per_policy <= len(self.authority_ids):
            raise GovernanceError(
                f"authorities_per_policy must be in 1..{len(self.authority_ids)} "
                f"(the roster size), got {self.authorities_per_policy}"
            )

    def with_overrides(
        self, overrides: Mapping[str, Tuple[str, ...]]
    ) -> "PolicyGovernance":
        """A copy whose named policies have a stated governing set."""
        return PolicyGovernance(
            authority_ids=self.authority_ids,
            domain_authority=self.domain_authority,
            authorities_per_policy=self.authorities_per_policy,
            overrides={**self.overrides, **overrides},
        )

    @classmethod
    def from_domains(
        cls,
        domain_authority: Mapping[str, str],
        *,
        authorities_per_policy: int = DEFAULT_AUTHORITIES_PER_POLICY,
    ) -> "PolicyGovernance":
        """Build from the harness's ``{domain: authority_id}`` mapping."""
        return cls(
            authority_ids=tuple(sorted(set(domain_authority.values()))),
            domain_authority=dict(domain_authority),
            authorities_per_policy=authorities_per_policy,
        )

    def governing(self, policy_id: str) -> Tuple[str, ...]:
        """``AA(PID_i)`` — sorted, so every digest over it is order-independent.

        The policy's own domain authority is always present. Determinism comes
        from hashing ``policy_id``: the same policy maps to the same authority
        set in every process, which is what lets an FSN and the AIM agree on
        ``PV_i`` without exchanging the set.
        """
        if not policy_id:
            raise GovernanceError("policy_id must not be empty")
        stated = self.overrides.get(policy_id)
        if stated is not None:
            unknown = [a for a in stated if a not in self.authority_ids]
            if unknown:
                raise GovernanceError(
                    f"policy {policy_id!r} is stated to be governed by "
                    f"{sorted(unknown)}, which are not on the roster"
                )
            if not stated:
                raise GovernanceError(
                    f"policy {policy_id!r} is stated to have an empty AA(PID); "
                    f"PV_i would then be a constant shared by every such policy"
                )
            return tuple(sorted(set(stated)))
        domain = policy_id.split("/", 1)[0]
        owner = self.domain_authority.get(domain)
        chosen = [owner] if owner is not None else []

        # Deterministic draw over the remaining roster. Walking a hash-ordered
        # permutation (rather than `hash % n` per slot) cannot pick a duplicate,
        # so the result always has exactly `authorities_per_policy` members.
        others = [a for a in self.authority_ids if a != owner]
        ranked = sorted(
            others,
            key=lambda a: hashes.sha256(
                policy_id.encode("utf-8"), a.encode("utf-8"),
                domain=b"psa-governance/v1",
            ),
        )
        for authority in ranked:
            if len(chosen) >= self.authorities_per_policy:
                break
            chosen.append(authority)

        if len(chosen) < self.authorities_per_policy:
            raise GovernanceError(
                f"policy {policy_id!r} needs {self.authorities_per_policy} "
                f"governing authorities but the roster holds "
                f"{len(self.authority_ids)}"
            )
        return tuple(sorted(chosen))

    def governs(self, policy_id: str, authority_id: str) -> bool:
        """Whether ``AA_k ∈ AA(PID_i)`` — the test eq:unaffected-policy turns on."""
        return authority_id in self.governing(policy_id)

    def affected_policies(
        self, authority_id: str, policies: Sequence[str]
    ) -> Tuple[str, ...]:
        """``P_k^aff = {P_ℓ : AA_k ∈ AA(PID_ℓ)}`` — DIAS Step 1's first closure."""
        return tuple(p for p in policies if self.governs(p, authority_id))

    def coverage(self, policies: Sequence[str]) -> Dict[str, int]:
        """How many of ``policies`` each authority governs.

        Exp. 6 sweeps the affected-policy RATIO, so it needs to choose an
        authority whose closure is a given fraction of the policy set. That is
        this map, and it is why the draw above must be inspectable rather than
        merely deterministic.
        """
        counts = {a: 0 for a in self.authority_ids}
        for policy in policies:
            for authority in self.governing(policy):
                counts[authority] += 1
        return counts


__all__ = [
    "DEFAULT_AUTHORITIES_PER_POLICY",
    "GovernanceError",
    "PolicyGovernance",
]
