"""Phase VIII under the policy-state-aware commitment — the D3 verifier.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`, Phase VIII:

    Step 1  MerkleVerify(L_{i,j}, pi_i, Root_i)
    Step 2  Commit_i* = H(CID_i ‖ Root_i ‖ PID_i ‖ PV_i ‖ AuthState_i)
            accept iff Commit_i* == Commit_i
    Step 3  chain consistency: the anchored AMeta_i matches

WHY THIS IS NOT ``verify/proof.py``
-----------------------------------
That module verifies Option D's commitment, ``H(Root ‖ PID ‖ VID ‖
AuthRoot_DO)``, and its Step 2 is an equality between two integer counters
(``VID_i == VID_U``). Three things change here, and each is a divergence
already recorded:

* ``CID_i`` is **inside** the commitment (D3), so a substituted ciphertext
  reference is caught without re-deriving the Merkle path.
* ``AuthRoot_DO`` becomes ``AuthState_i``, a digest over the **policy-governing**
  authorities' commitments — who the record's authorization currently depends
  on, rather than who outsourced it.
* Freshness stops being an ordering and becomes a digest equality: ``PV_i`` is
  ``H(Encode(V_{P_i}))``, so a verifier compares 32 bytes instead of asking
  whether one counter is at least another. That is strictly easier to get
  right, and it is why ``check_policy_state_equality`` has no
  ``require_version_match`` escape hatch — under Option D that flag existed
  because a client's ``VID_U`` legitimately lags a record's ``VID_i``.

Retrofitting ``verify/proof.py`` with a branch per difference would leave one
function implementing two acceptance tests, which is exactly how a verifier and
a committer come to disagree. ``psa/commit.py`` holds the single definition of
``Commit_i``; this module only ever calls it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402

from ..types import Record  # noqa: E402
from .commit import AuthenticatedMetadata, record_commitment  # noqa: E402
from .records import PolicyStateIndexEntry  # noqa: E402


class VerificationError(RuntimeError):
    """Raised when a bundle cannot be formed."""


@dataclass(frozen=True)
class StepResult:
    """One acceptance step, named so a failure says which one."""

    step: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class PsaVerificationBundle(Record):
    """``Pi_i`` under the PSA commitment — Phase VI Step 5, Phase VIII input.

    Carries ``AMeta_i`` whole rather than its fields loose: Phase VIII Step 2
    re-derives ``Commit_i`` from the other five, so the tuple is self-checking
    and cannot be assembled with a commitment that belongs to a different
    record.
    """

    DOMAIN: ClassVar[bytes] = b"psa-verification-bundle/v1"

    meta: AuthenticatedMetadata
    proof: merkle.MerkleProof
    entry: PolicyStateIndexEntry

    def __post_init__(self) -> None:
        if not isinstance(self.meta, AuthenticatedMetadata):
            raise TypeError("meta must be an AuthenticatedMetadata")
        if not isinstance(self.entry, PolicyStateIndexEntry):
            raise TypeError("entry must be a PolicyStateIndexEntry")
        if self.entry.cid != self.meta.cid:
            raise VerificationError(
                f"bundle entry names CID {self.entry.cid!r} but AMeta names "
                f"{self.meta.cid!r}; Commit_i binds one ciphertext reference"
            )

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (self.meta, self.proof.leaf_index, self.proof.leaf_hash,
                [[s, left] for s, left in self.proof.path], self.entry)

    @property
    def cid(self) -> str:
        return self.meta.cid

    @property
    def policy_id(self) -> str:
        return self.meta.policy_id

    @property
    def pv(self) -> bytes:
        """``PV_i`` — the record's policy state, as a digest."""
        return self.meta.pv

    @property
    def proof_size_bytes(self) -> int:
        return self.proof.size_bytes

    @property
    def proof_path_length(self) -> int:
        return self.proof.path_length


# ---------------------------------------------------------------------------
# Step 1 — Merkle membership
# ---------------------------------------------------------------------------
def verify_merkle_membership(bundle: PsaVerificationBundle) -> StepResult:
    """``MerkleVerify(L_{i,j}, pi_i, Root_i)`` — Phase VIII Step 1.

    Two things must hold, and checking only the first is the classic mistake:
    the path must reconstruct ``Root_i``, **and** the leaf it starts from must
    be the entry the bundle names. A proof that verifies against the root while
    starting from a different leaf proves membership of something else. The
    leaf is therefore re-derived from the ENTRY (note the tree stores
    ``hash_leaf(data)``, so comparing ``proof.leaf_hash`` to ``entry.leaf()``
    directly compares two different things and fails every valid bundle).

    BOTH CHECKS RUN, ALWAYS — deliberately not ``MerkleTree.verify_leaf``,
    which returns early when the leaf mismatches. Exp. 4's second arm tampers
    ``t`` of ``r`` records, and a tampered record fails exactly here; skipping
    the path walk for it would make a tampered record CHEAPER to reject under
    this construction than under Option D, whose ``verify/proof.py`` computes
    both unconditionally. The two Exp. 4 curves share an axis, so the tampered
    record has to cost the same work in both or the comparison is not
    like-for-like. Short-circuiting BETWEEN steps is a different matter and is
    kept: §VI rejects the ciphertext at the first failed step.
    """
    expected_leaf = merkle.hash_leaf(bundle.entry.leaf())
    leaf_matches = hashes.constant_time_equal(expected_leaf, bundle.proof.leaf_hash)
    root_matches = merkle.MerkleTree.verify(bundle.proof, bundle.meta.root)
    if not leaf_matches:
        detail = "the proof's leaf is not the entry this bundle names"
    elif not root_matches:
        detail = "the authentication path does not reconstruct Root_i"
    else:
        detail = ""
    return StepResult("merkle", leaf_matches and root_matches, detail)


# ---------------------------------------------------------------------------
# Step 2 — policy-state and commitment
# ---------------------------------------------------------------------------
def check_policy_state_equality(
    bundle: PsaVerificationBundle, pv_expected: bytes
) -> bool:
    """``PV_i == PV_U`` — a digest equality, constant-time."""
    return hashes.constant_time_equal(bundle.pv, pv_expected)


def recompute_commitment(bundle: PsaVerificationBundle) -> bytes:
    """``Commit_i*`` — delegates to the one definition in ``psa/commit.py``."""
    return record_commitment(
        cid=bundle.meta.cid,
        root=bundle.meta.root,
        policy_id=bundle.meta.policy_id,
        pv=bundle.meta.pv,
        auth_state=bundle.meta.auth_state,
    )


def verify_authorization_state(
    bundle: PsaVerificationBundle, *, pv_expected: Optional[bytes] = None
) -> StepResult:
    """Phase VIII Step 2.

    ``pv_expected`` is the Data User's ``PV`` for this record's policy, derived
    from their own ``VAP_U``. Omitting it verifies the commitment's internal
    consistency only — which is what an auditor without the user's profile can
    do, and is NOT freshness.
    """
    expected = recompute_commitment(bundle)
    if not hashes.constant_time_equal(expected, bundle.meta.commit):
        return StepResult(
            "authorization", False,
            "Commit_i* != Commit_i; the record's (CID, Root, PID, PV, "
            "AuthState) do not produce the anchored commitment",
        )
    if pv_expected is not None and not check_policy_state_equality(
        bundle, pv_expected
    ):
        return StepResult(
            "authorization", False,
            "PV_i != PV_U; the entry was committed under a policy state the "
            "user's profile does not carry (stale shard, or revoked access)",
        )
    return StepResult("authorization", True)


# ---------------------------------------------------------------------------
# The acceptance test
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VerificationResult:
    cid: str
    steps: Tuple[StepResult, ...]
    proof_size_bytes: int
    proof_path_length: int

    @property
    def accepted(self) -> bool:
        return bool(self.steps) and all(step.passed for step in self.steps)

    @property
    def failed_step(self) -> Optional[str]:
        for step in self.steps:
            if not step.passed:
                return step.step
        return None


def verify_bundle(
    bundle: PsaVerificationBundle,
    *,
    pv_expected: Optional[bytes] = None,
    chain_check: Optional[callable] = None,
) -> VerificationResult:
    """Phase VIII Steps 1-3 for one returned ciphertext.

    Short-circuits exactly as ``verify/proof.py`` does, and for the same
    measurement reason: a failed Step 1 means the ciphertext is rejected
    immediately, so the later steps are neither run nor timed. A verifier that
    always ran all three would report a per-record cost no real client pays —
    and Exp. 4 divides by ``r``.
    """
    steps = [verify_merkle_membership(bundle)]
    if steps[-1].passed:
        steps.append(verify_authorization_state(bundle, pv_expected=pv_expected))
    if steps[-1].passed and chain_check is not None:
        steps.append(chain_check(bundle))
    return VerificationResult(
        cid=bundle.cid,
        steps=tuple(steps),
        proof_size_bytes=bundle.proof_size_bytes,
        proof_path_length=bundle.proof_path_length,
    )


def build_response(
    commitment, entries: Sequence[PolicyStateIndexEntry]
) -> Tuple[PsaVerificationBundle, ...]:
    """One bundle per returned RECORD's entry set — Phase VI Step 5.

    **The caller decides what "one returned result" is, and Exp. 4 counts
    RECORDS.** This emits one bundle per index ENTRY, so a caller that
    ``extend``s the whole list inflates its sweep by ``|W_i|``. That is defect
    ``d1cdf9c``, which has now cost two re-runs; ``harness/psa_experiments.py``
    takes ``[0]`` per record for exactly this reason.
    """
    return tuple(
        PsaVerificationBundle(
            meta=commitment.meta, proof=commitment.prove(index), entry=entry
        )
        for index, entry in enumerate(entries)
    )


__all__ = [
    "PsaVerificationBundle",
    "StepResult",
    "VerificationError",
    "VerificationResult",
    "build_response",
    "check_policy_state_equality",
    "recompute_commitment",
    "verify_authorization_state",
    "verify_bundle",
    "verify_merkle_membership",
]
