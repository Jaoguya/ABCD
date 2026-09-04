"""Phase VIII Step 3 — Blockchain Consistency Verification.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:1203`:

    BC_i = ( CID_i, Commit_i, Root_i, VID_i, TS_i )

"the user retrieves the corresponding blockchain metadata… and verifies that the
locally computed values match the immutable blockchain commitment. This step
ensures that neither the searchable index nor the integrity commitment has been
modified after publication."

Two distinct checks, and the manuscript names only the first:

1. **Agreement.** The bundle's ``Root_i`` and ``Commit_i`` equal the anchored
   ones. This catches a Fog Search Node that served a well-formed bundle over an
   index state it never published — the bundle would pass Steps 1 and 2, because
   both are computed *from* the values the node supplied.
2. **Chain integrity.** The anchor is genuinely part of the ledger's hash chain.
   Without it, "immutable blockchain commitment" is an assumption rather than a
   verified property: an adversary who could rewrite an anchor would make check 1
   agree with whatever it liked. ``chain/ledger.py``'s ``verify_chain`` recomputes
   every link, which is the work Exp. 4 times.

**The anchor record is Phase VII's** ``BlockchainAnchor`` (``sync/ias.py``), whose
fields are exactly ``BC_i``. Phase V Step 3 — which should write the *initial*
``BC_i`` when a record is first outsourced — is not implemented, so a record that
has never been updated has no anchor. :func:`verify_blockchain_consistency`
reports that as a failed check rather than silently passing: an unanchored record
is precisely what Step 3 exists to detect.

Exp. 4 counts this step (README §5: "Merkle proof, ``Commit_i*`` recomputation,
**chain consistency**"), while IPFS fetch and decryption are excluded.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..chain.ledger import (  # noqa: E402
    Ledger,
    NS_VERSION_IDENTIFIERS,
    NotFoundError,
)
from ..types import BlockchainAnchor  # noqa: E402
from .proof import StepResult, VerificationBundle  # noqa: E402


class ChainVerificationError(RuntimeError):
    """Raised when the ledger cannot be queried, as distinct from a mismatch."""


@dataclass(frozen=True)
class AnchorLookup:
    """The anchored ``BC_i`` for one record, and how it was found."""

    anchor: BlockchainAnchor
    key: str
    versions_available: Tuple[int, ...]

    @property
    def vid(self) -> int:
        return self.anchor.vid


def anchor_key(cid: str, vid: int) -> str:
    """Ledger key for ``BC_i`` at one version.

    Matches ``sync/ias.anchor_update``: zero-padded, so lexicographic order is
    version order and "latest" is the last key rather than a numeric scan.
    """
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return f"{cid}#{vid:012d}"


def anchored_versions(ledger: Ledger, cid: str) -> Tuple[int, ...]:
    """Every anchored version for a record, oldest first."""
    keys = ledger.keys(NS_VERSION_IDENTIFIERS, prefix=f"{cid}#")
    return tuple(int(key.split("#", 1)[1]) for key in keys)


def lookup_anchor(
    ledger: Ledger, cid: str, *, vid: Optional[int] = None
) -> AnchorLookup:
    """Retrieve ``BC_i``, at ``vid`` or the latest anchored version.

    Raises :class:`ChainVerificationError` when nothing is anchored — which for a
    record that has never been updated means Phase V Step 3 has not run, not that
    verification failed. The distinction matters: one is a missing
    implementation, the other is a detected tamper.
    """
    versions = anchored_versions(ledger, cid)
    if not versions:
        raise ChainVerificationError(
            f"no BC_i anchored for CID {cid!r}. Phase VII Step 7 anchors updates; "
            f"the initial anchor is Phase V Step 3, which is not implemented, so a "
            f"record that has never been updated has none."
        )
    target = versions[-1] if vid is None else vid
    key = anchor_key(cid, target)
    try:
        entry = ledger.get(NS_VERSION_IDENTIFIERS, key)
    except NotFoundError:
        raise ChainVerificationError(
            f"CID {cid!r} has anchors at versions {list(versions)} but not at "
            f"{target}"
        ) from None
    anchor = entry.record
    if not isinstance(anchor, BlockchainAnchor):
        raise ChainVerificationError(
            f"the record anchored at {key!r} is not an BlockchainAnchor"
        )
    return AnchorLookup(anchor=anchor, key=key, versions_available=versions)


def verify_blockchain_consistency(
    ledger: Ledger,
    bundle: VerificationBundle,
    *,
    vid: Optional[int] = None,
    check_chain_integrity: bool = True,
) -> StepResult:
    """Phase VIII Step 3 for one bundle.

    Compares ``Root_i`` and ``Commit_i`` against the anchor in constant time, then
    (by default) recomputes the ledger's hash chain. ``check_chain_integrity`` is a
    parameter because Exp. 4 sweeps ``r`` returned records: the per-record
    comparison scales with ``r`` while a whole-chain recomputation does not, so a
    harness measuring the per-record cost must be able to separate them rather
    than reporting one number that mixes both.
    """
    started = time.perf_counter_ns()
    detail = ""
    try:
        lookup = lookup_anchor(ledger, bundle.cid, vid=vid)
    except ChainVerificationError as exc:
        return StepResult(
            name="chain",
            passed=False,
            elapsed_ns=time.perf_counter_ns() - started,
            detail=str(exc),
        )

    anchor = lookup.anchor
    root_ok = hashes.constant_time_equal(anchor.root, bundle.root)
    commit_ok = hashes.constant_time_equal(anchor.commit, bundle.commit)
    cid_ok = anchor.cid == bundle.cid
    chain_ok = ledger.verify_chain() if check_chain_integrity else True
    elapsed = time.perf_counter_ns() - started

    if not cid_ok:
        detail = f"anchor names CID {anchor.cid!r}, bundle names {bundle.cid!r}"
    elif not root_ok:
        detail = "Root_i does not match the anchored root"
    elif not commit_ok:
        detail = "Commit_i does not match the anchored commitment"
    elif not chain_ok:
        detail = "the ledger's hash chain does not verify"

    return StepResult(
        name="chain",
        passed=cid_ok and root_ok and commit_ok and chain_ok,
        elapsed_ns=elapsed,
        detail=detail,
    )


def chain_checker(
    ledger: Ledger,
    *,
    vid: Optional[int] = None,
    check_chain_integrity: bool = True,
) -> Callable[[VerificationBundle], StepResult]:
    """A Step 3 check bound to one ledger, for ``proof.verify_bundle``.

    ``proof.py`` takes Step 3 as an injected callable so it does not depend on the
    ledger — which is what lets Steps 1-2 be tested with no chain at all, and what
    will let Fabric replace the in-process adapter without touching them.
    """

    def check(bundle: VerificationBundle) -> StepResult:
        return verify_blockchain_consistency(
            ledger,
            bundle,
            vid=vid,
            check_chain_integrity=check_chain_integrity,
        )

    return check


@dataclass(frozen=True)
class AnchorHistory:
    """A record's anchored versions — the "tamper-evident history" of Step 7."""

    cid: str
    anchors: Tuple[BlockchainAnchor, ...]

    @property
    def versions(self) -> Tuple[int, ...]:
        return tuple(anchor.vid for anchor in self.anchors)

    @property
    def latest(self) -> BlockchainAnchor:
        return self.anchors[-1]

    def is_monotone(self) -> bool:
        """Versions advance by one, with no gaps.

        Phase VII Step 3 increments by exactly one, so a gap means an update was
        never anchored — the history is incomplete even though every anchor in it
        is individually valid, and the hash chain cannot reveal that because
        nothing was tampered with. Only the version sequence can.
        """
        versions = self.versions
        return all(b - a == 1 for a, b in zip(versions, versions[1:]))


def anchor_history(ledger: Ledger, cid: str) -> AnchorHistory:
    """Every anchored ``BC_i`` for a record, oldest first."""
    keys = ledger.keys(NS_VERSION_IDENTIFIERS, prefix=f"{cid}#")
    if not keys:
        raise ChainVerificationError(f"no anchors for CID {cid!r}")
    anchors = []
    for key in keys:
        record = ledger.get(NS_VERSION_IDENTIFIERS, key).record
        if not isinstance(record, BlockchainAnchor):
            raise ChainVerificationError(f"{key!r} is not an BlockchainAnchor")
        anchors.append(record)
    return AnchorHistory(cid=cid, anchors=tuple(anchors))


__all__ = [
    "ChainVerificationError",
    "AnchorLookup",
    "AnchorHistory",
    "anchor_key",
    "anchored_versions",
    "lookup_anchor",
    "verify_blockchain_consistency",
    "chain_checker",
    "batched_chain_checker",
    "lookup_anchors",
    "anchor_history",
]


# ===========================================================================
# Batched Step 3 — one namespace pass for a whole response
# ===========================================================================
def lookup_anchors(
    ledger: Ledger, cids: Sequence[str]
) -> Tuple[dict, Tuple[str, ...]]:
    """Every named CID's latest ``BC_i``, resolved in ONE namespace pass.

    WHY THIS EXISTS. :func:`lookup_anchor` calls ``ledger.keys(prefix=...)``,
    which walks and sorts the whole namespace, so verifying ``r`` records walked
    it ``r`` times -- O(r^2), and measured at 99.6% of the chain step's cost
    against 0.4% for the three comparisons that step actually makes. The
    comparisons are per record BY CONSTRUCTION (``BC_i`` carries subscript i, and
    per-record anchoring is what lets a rejected record be NAMED); the retrieval
    never had to be.

    WHAT IS AND IS NOT UNCHANGED. Every returned record is still checked against
    its OWN anchor, at the latest anchored version, exactly as
    :func:`lookup_anchor` resolves it. Nothing is skipped, sampled or shared
    between records. Only the number of namespace walks changes, from ``r`` to
    one. That is why this needs no change to Phase VIII and no change to the
    security argument.

    Returns ``(anchors, missing)``: a ``cid -> AnchorLookup`` map, and the CIDs
    with no anchor at all. Missing CIDs are RETURNED rather than raised on,
    because an unanchored record is a verification FAILURE for that record --
    not an error that should abandon the other ``r-1``.
    """
    latest: dict = {}
    wanted = set(cids)
    for key in ledger.keys(NS_VERSION_IDENTIFIERS):
        cid, _, raw_vid = key.partition("#")
        if cid not in wanted:
            continue
        try:
            vid = int(raw_vid)
        except ValueError:
            continue
        if vid > latest.get(cid, (-1, ""))[0]:
            latest[cid] = (vid, key)

    anchors: dict = {}
    for cid, (vid, key) in latest.items():
        entry = ledger.get(NS_VERSION_IDENTIFIERS, key)
        anchor = entry.record
        if not isinstance(anchor, BlockchainAnchor):
            raise ChainVerificationError(
                f"the record anchored at {key!r} is not a BlockchainAnchor"
            )
        anchors[cid] = AnchorLookup(
            anchor=anchor, key=key, versions_available=(vid,)
        )
    return anchors, tuple(sorted(wanted - set(anchors)))


def batched_chain_checker(
    ledger: Ledger,
    cids: Sequence[str],
    *,
    check_chain_integrity: bool = True,
) -> Callable[[VerificationBundle], StepResult]:
    """Step 3 for a whole response, with the anchors fetched once.

    Drop-in for :func:`chain_checker` in ``proof.verify_response``. The fetch is
    LAZY -- it happens on the first bundle checked, inside whatever region the
    caller is timing, so a harness cannot make the cost disappear by resolving
    anchors during an untimed ``prepare``. Its full cost is therefore charged to
    the first record, which is correct: a client pays it once per response.
    """
    resolved: dict = {}
    missing: set = set()
    done = False

    def check(bundle: VerificationBundle) -> StepResult:
        nonlocal done
        started = time.perf_counter_ns()
        if not done:
            anchors, absent = lookup_anchors(ledger, cids)
            resolved.update(anchors)
            missing.update(absent)
            done = True

        lookup = resolved.get(bundle.cid)
        if lookup is None:
            return StepResult(
                name="chain",
                passed=False,
                elapsed_ns=time.perf_counter_ns() - started,
                detail=(
                    f"no BC_i anchored for CID {bundle.cid!r}. Phase VII Step 7 "
                    f"anchors updates; the initial anchor is Phase V Step 3."
                ),
            )

        anchor = lookup.anchor
        root_ok = hashes.constant_time_equal(anchor.root, bundle.root)
        commit_ok = hashes.constant_time_equal(anchor.commit, bundle.commit)
        cid_ok = anchor.cid == bundle.cid
        chain_ok = ledger.verify_chain() if check_chain_integrity else True
        elapsed = time.perf_counter_ns() - started

        if not cid_ok:
            detail = f"anchor names CID {anchor.cid!r}, bundle names {bundle.cid!r}"
        elif not root_ok:
            detail = "Root_i does not match the anchored root"
        elif not commit_ok:
            detail = "Commit_i does not match the anchored commitment"
        elif not chain_ok:
            detail = "the ledger's hash chain does not verify"
        else:
            detail = ""

        return StepResult(
            name="chain",
            passed=cid_ok and root_ok and commit_ok and chain_ok,
            elapsed_ns=elapsed,
            detail=detail,
        )

    return check
