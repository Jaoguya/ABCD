"""Phase VIII Steps 1-2 — verification bundle and authorization-state checks.

The bundle comes from Phase VI Step 5:

    Pi_i = ( CID_i, Root_i, Commit_i, pi_i )
    Resp = { (CID_i, Pi_i) }_{i=1..|R|}

Phase VIII Step 1 (`:1143`):

    VerifyMerkle(Root_i, pi_i, CID_i) = 1

"If the verification fails, the corresponding ciphertext is immediately
rejected."

Phase VIII Step 2 (`:1167`):

    VID_i = VID_U
    Commit_i* = H( Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot_U )
    accept iff Commit_i* = Commit_i

**This is the Exp. 4 measured path.** README §5: "client-side verification only:
Merkle proof, ``Commit_i*`` recomputation, chain consistency. IPFS fetch and
decryption excluded." Steps 4-6 (retrieval, decryption, audit logging) are
therefore not implemented here, and the timings this module reports cover only
what Exp. 4 is allowed to count.

---

**Two blockers in Step 2 as published.** Both are recorded in ``SCHEME.md``; both
would make Exp. 4 report a 0% acceptance rate if implemented literally.

1. ``Commit_i*`` is recomputed with **``AuthRoot_U``**, the *Data User's*
   authorization root, while Phase IV Step 5 binds **``AuthRoot_DO``**, the *Data
   Owner's*. Those differ for every user who is not the owner, so
   ``Commit_i* = Commit_i`` can never hold. The only coherent reading is that
   Step 2 means ``AuthRoot_DO``: a record is indexed once, before any user
   searches it, so its commitment cannot bind a searcher's root. This module
   therefore takes the root to verify against as an explicit parameter, and
   :func:`verify_authorization_state` refuses to guess which one the caller meant.
   ``AuthRoot_DO`` must also reach the user somehow — the published ``Pi_i`` does
   not carry it, so it comes from the blockchain metadata of Step 3 or from the
   catalog.

2. ``VID_i = VID_U`` equates a **record's** version with a **user's** profile
   version — two of the four distinct counters ``VID`` denotes (``SCHEME.md``).
   Requiring equality makes verification fail whenever they differ, which is the
   normal case. Implemented as :func:`check_version_equality` so it can be
   measured, with the alternative (verify the record's version against the
   authorization state the *owner* committed under) available as the
   ``require_version_match=False`` path.

**What the Merkle proof actually proves.** Step 1 writes
``VerifyMerkle(Root_i, pi_i, CID_i)``, but the leaves of a record's tree are
``L_j = H(I_j)`` over index *entries* (Phase IV Step 4) — the ``CID`` is a field of
every entry, not a leaf. So the proof establishes that a specific entry is in the
tree, and the bundle must carry that entry (or its leaf hash) for the check to be
possible at all. ``Common/crypto/merkle.py``'s ``MerkleProof`` carries
``leaf_hash``, so it is self-contained; :meth:`VerificationBundle.for_entry` binds
the entry explicitly so a bundle cannot be checked against a leaf it does not name.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Iterable, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402

from ..index.commit import RecordCommitment, policy_commitment  # noqa: E402
from ..types import IndexEntry, Record  # noqa: E402


class VerificationError(RuntimeError):
    """Raised when a bundle is malformed — distinct from failing verification.

    A failed *check* is a result (``accepted = False``); a malformed bundle is a
    protocol error. Conflating them would let a rejected ciphertext and an
    unparseable response report the same way, and Exp. 4 would be timing both.
    """


@dataclass(frozen=True)
class VerificationBundle(Record):
    """``Pi_i = (CID_i, Root_i, Commit_i, pi_i)`` — Phase VI Step 5.

    ``entry`` is the index entry whose membership ``pi_i`` proves. Not in the
    published tuple, and required: the tree's leaves are ``H(I_j)`` over entries,
    so a proof cannot be checked against a ``CID`` alone. Carrying it explicitly
    also means the bundle states which leaf it is about rather than leaving the
    verifier to infer it.
    """

    DOMAIN: ClassVar[bytes] = b"verification-bundle/v1"

    cid: str
    root: bytes
    commit: bytes
    proof: merkle.MerkleProof
    entry: IndexEntry

    def __post_init__(self) -> None:
        if not self.cid:
            raise ValueError("cid must not be empty")
        for name in ("root", "commit"):
            if len(getattr(self, name)) != merkle.DIGEST_BYTES:
                raise ValueError(f"{name} must be a 32-byte digest")
        if self.entry.cid != self.cid:
            raise VerificationError(
                f"bundle names CID {self.cid!r} but its entry references "
                f"{self.entry.cid!r}"
            )

    def _encoded_fields(self):
        # The proof is encoded by its leaf and sibling path so the bundle's digest
        # covers the evidence, not just the claims.
        return (
            self.cid,
            self.root,
            self.commit,
            self.proof.leaf_index,
            self.proof.leaf_hash,
            [[sibling, is_left] for sibling, is_left in self.proof.path],
            self.entry,
        )

    @property
    def policy_id(self) -> str:
        """``PID_i`` — from the entry, which is what ``Commit_i`` was built over."""
        return self.entry.policy_id

    @property
    def vid(self) -> int:
        """``VID_i`` — the record's version."""
        return self.entry.vid

    @property
    def proof_size_bytes(self) -> int:
        """Exp. 4 secondary metric: proof size, reported in KB by the harness."""
        return self.proof.size_bytes

    @property
    def proof_path_length(self) -> int:
        """Exp. 4 secondary metric, measured — odd-node promotion makes log2(N) wrong."""
        return self.proof.path_length

    @classmethod
    def for_entry(
        cls, commitment: RecordCommitment, entry_index: int, entry: IndexEntry
    ) -> "VerificationBundle":
        """Build ``Pi_i`` for one entry of a committed record — Phase VI Step 5."""
        return cls(
            cid=entry.cid,
            root=commitment.root,
            commit=commitment.commit,
            proof=commitment.prove(entry_index),
            entry=entry,
        )


@dataclass(frozen=True)
class StepResult:
    """One verification step's outcome, with its own elapsed time.

    Timed per step because Exp. 4 sweeps returned records ``r`` and the three
    steps scale differently — the Merkle check is per record, the chain lookup can
    be amortised. A single total would hide which one drives the curve.
    """

    name: str
    passed: bool
    elapsed_ns: int
    detail: str = ""

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1e6


@dataclass(frozen=True)
class VerificationResult:
    """The full Phase VIII Steps 1-3 outcome for one returned ciphertext."""

    cid: str
    steps: Tuple[StepResult, ...]
    proof_size_bytes: int
    proof_path_length: int

    @property
    def accepted(self) -> bool:
        """Accept only if every step passed — Step 1 rejects "immediately"."""
        return all(step.passed for step in self.steps)

    @property
    def elapsed_ns(self) -> int:
        return sum(step.elapsed_ns for step in self.steps)

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1e6

    @property
    def proof_size_kb(self) -> float:
        """README §9 reports sizes in KB."""
        return self.proof_size_bytes / 1024.0

    def step(self, name: str) -> StepResult:
        for step in self.steps:
            if step.name == name:
                return step
        raise KeyError(name)

    @property
    def failed_step(self) -> Optional[str]:
        for step in self.steps:
            if not step.passed:
                return step.name
        return None


# ===========================================================================
# Step 1 — verification bundle validation
# ===========================================================================
def verify_merkle_membership(bundle: VerificationBundle) -> StepResult:
    """``VerifyMerkle(Root_i, pi_i, CID_i) = 1`` — Phase VIII Step 1.

    Two things must hold, and checking only the first is the classic mistake: the
    path must reconstruct ``Root_i``, **and** the leaf the path starts from must be
    the entry the bundle names. A proof that verifies against the root while
    starting from a different leaf proves membership of something else.
    """
    from ..index.commit import entry_leaf

    started = time.perf_counter_ns()
    expected_leaf = merkle.hash_leaf(entry_leaf(bundle.entry))
    leaf_matches = hashes.constant_time_equal(
        expected_leaf, bundle.proof.leaf_hash
    )
    root_matches = merkle.MerkleTree.verify(bundle.proof, bundle.root)
    elapsed = time.perf_counter_ns() - started

    if not leaf_matches:
        detail = "the proof's leaf is not the entry this bundle names"
    elif not root_matches:
        detail = "the authentication path does not reconstruct Root_i"
    else:
        detail = ""
    return StepResult(
        name="merkle",
        passed=leaf_matches and root_matches,
        elapsed_ns=elapsed,
        detail=detail,
    )


# ===========================================================================
# Step 2 — authorization-state verification
# ===========================================================================
def check_version_equality(bundle: VerificationBundle, vid_u: int) -> bool:
    """``VID_i = VID_U`` as published — see the module docstring on why this is
    an equality between two different counters."""
    return bundle.vid == vid_u


def recompute_commitment(bundle: VerificationBundle, auth_root: bytes) -> bytes:
    """``Commit_i* = H(Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot)``.

    Delegates to ``index/commit.py::policy_commitment``, the single definition
    Phase IV Step 5 used. Recomputing it here with a second copy of the
    concatenation is exactly how a verifier and a committer come to disagree.
    """
    return policy_commitment(
        root=bundle.root,
        policy_id=bundle.policy_id,
        vid=bundle.vid,
        auth_root_do=auth_root,
    )


def verify_authorization_state(
    bundle: VerificationBundle,
    *,
    auth_root: bytes,
    vid_u: Optional[int] = None,
    require_version_match: bool = True,
) -> StepResult:
    """Phase VIII Step 2: version check, then ``Commit_i*`` recomputation.

    ``auth_root`` is **required and explicit**. Step 2 writes ``AuthRoot_U`` while
    Phase IV Step 5 binds ``AuthRoot_DO``; passing the wrong one fails every
    verification, so this function does not choose for the caller. See the module
    docstring.

    ``require_version_match=False`` skips the ``VID_i = VID_U`` equality — the
    published check compares a record's version against a user's profile version,
    and the two are different counters.
    """
    started = time.perf_counter_ns()
    version_ok = True
    if require_version_match:
        if vid_u is None:
            raise VerificationError(
                "require_version_match needs VID_U; Phase VIII Step 2 checks "
                "VID_i = VID_U"
            )
        version_ok = check_version_equality(bundle, vid_u)

    recomputed = recompute_commitment(bundle, auth_root)
    commit_ok = hashes.constant_time_equal(recomputed, bundle.commit)
    elapsed = time.perf_counter_ns() - started

    if not version_ok:
        detail = f"VID_i={bundle.vid} != VID_U={vid_u}"
    elif not commit_ok:
        detail = "Commit_i* != Commit_i (wrong AuthRoot, policy, version, or root)"
    else:
        detail = ""
    return StepResult(
        name="authorization",
        passed=version_ok and commit_ok,
        elapsed_ns=elapsed,
        detail=detail,
    )


# ===========================================================================
# Steps 1-3 together — the Exp. 4 path
# ===========================================================================
def verify_bundle(
    bundle: VerificationBundle,
    *,
    auth_root: bytes,
    vid_u: Optional[int] = None,
    require_version_match: bool = True,
    chain_check: Optional[callable] = None,
) -> VerificationResult:
    """Client-side verification of one returned ciphertext.

    Short-circuits: Step 1 failing means "the corresponding ciphertext is
    immediately rejected" (`:1143`), so the later steps are not run and — more to
    the point for Exp. 4 — not timed. A verifier that always ran all three would
    report a per-record cost that no real client pays.

    ``chain_check`` is Step 3, injected so this module does not depend on the
    ledger; ``verify/ledger.py`` supplies it.
    """
    steps = [verify_merkle_membership(bundle)]
    if steps[-1].passed:
        steps.append(
            verify_authorization_state(
                bundle,
                auth_root=auth_root,
                vid_u=vid_u,
                require_version_match=require_version_match,
            )
        )
    if steps[-1].passed and chain_check is not None:
        steps.append(chain_check(bundle))

    return VerificationResult(
        cid=bundle.cid,
        steps=tuple(steps),
        proof_size_bytes=bundle.proof_size_bytes,
        proof_path_length=bundle.proof_path_length,
    )


@dataclass(frozen=True)
class BatchVerification:
    """``Resp`` verified — the shape Exp. 4 reports over ``r`` records."""

    results: Tuple[VerificationResult, ...]

    @property
    def record_count(self) -> int:
        """``r`` — the Exp. 4 sweep variable."""
        return len(self.results)

    @property
    def accepted_count(self) -> int:
        return sum(1 for result in self.results if result.accepted)

    @property
    def rejected(self) -> Tuple[str, ...]:
        return tuple(r.cid for r in self.results if not r.accepted)

    @property
    def elapsed_ns(self) -> int:
        return sum(result.elapsed_ns for result in self.results)

    @property
    def elapsed_ms(self) -> float:
        """Exp. 4 primary metric: client-side verification latency in ms."""
        return self.elapsed_ns / 1e6

    @property
    def total_proof_bytes(self) -> int:
        return sum(result.proof_size_bytes for result in self.results)

    @property
    def total_proof_kb(self) -> float:
        """Exp. 4 secondary metric: proof size in KB."""
        return self.total_proof_bytes / 1024.0

    @property
    def mean_path_length(self) -> float:
        """Exp. 4 secondary metric, averaged over the batch."""
        if not self.results:
            return 0.0
        return sum(r.proof_path_length for r in self.results) / len(self.results)


def verify_response(
    bundles: Sequence[VerificationBundle],
    *,
    auth_root: bytes,
    vid_u: Optional[int] = None,
    require_version_match: bool = True,
    chain_check: Optional[callable] = None,
) -> BatchVerification:
    """Verify a whole search response — the Exp. 4 measurement.

    Every bundle is verified even after one fails: a client checking ``r`` results
    must know which are usable, and stopping at the first rejection would make the
    measured cost depend on where the failure happened to be.
    """
    if not bundles:
        raise VerificationError("a response with no bundles has nothing to verify")
    return BatchVerification(
        results=tuple(
            verify_bundle(
                bundle,
                auth_root=auth_root,
                vid_u=vid_u,
                require_version_match=require_version_match,
                chain_check=chain_check,
            )
            for bundle in bundles
        )
    )


def build_response(
    commitment: RecordCommitment, entries: Sequence[IndexEntry]
) -> Tuple[VerificationBundle, ...]:
    """Phase VI Step 5: ``Resp = {(CID_i, Pi_i)}`` for a record's entries."""
    if len(entries) != commitment.entry_count:
        raise VerificationError(
            f"{len(entries)} entries but the commitment covers "
            f"{commitment.entry_count}; the proofs would index the wrong leaves"
        )
    return tuple(
        VerificationBundle.for_entry(commitment, index, entry)
        for index, entry in enumerate(entries)
    )


__all__ = [
    "VerificationError",
    "VerificationBundle",
    "StepResult",
    "VerificationResult",
    "BatchVerification",
    "verify_merkle_membership",
    "check_version_equality",
    "recompute_commitment",
    "verify_authorization_state",
    "verify_bundle",
    "verify_response",
    "build_response",
]
