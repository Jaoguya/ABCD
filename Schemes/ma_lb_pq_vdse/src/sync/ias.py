"""Phase VII — Dynamic Index Evolution and Incremental Authorization Sync.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:997`, seven steps:

    Step 1 (:1007)  U_i = (Op, CID_i, Delta_i),  Op in {Insert, Modify, Delete, Revoke}
    Step 2 (:1020)  localized searchable-index evolution; "Unchanged index
                    entries are not rebuilt"
    Step 3 (:1045)  VID_k' = VID_k + 1, RevRoot_k', C_k^auth'
    Step 4 (:1074)  Root_i' = MerkleUpdate(Root_i, L_Delta),  Commit_i'
    Step 5 (:1092)  IAS_i = (CID_i, dVID_i, dC_i^auth, dI_i, dRoot_i, Commit_i')
    Step 6 (:1111)  Shard_j' = ApplyIAS(Shard_j, IAS_i), only to affected FSNs
    Step 7 (:1127)  BC_i' = (CID_i, Commit_i', Root_i', VID_i', TS_i')

This is the phase Exp. 5 and Exp. 6 measure, so what it must *not* do matters as
much as what it does. README §5: "Exp. 5 — incremental update only. A global
rebuild means Phase VII is implemented wrong."

**Option D removes Step 2's re-tokenization entirely.** As published, Step 2
recomputes ``T_j' = H(w_j ‖ PID_i' ‖ VID_i' ‖ Dom_i)`` for every affected
keyword. Under the matching relation chosen on 2026-08-10 the token is ``H(w)``
alone, so a policy or version change **touches no token and no posting list** —
only the entry payload and two bitmap bits move. That is the difference between
Exp. 5 measuring an incremental update and Exp. 5 measuring a re-tokenization of
the whole domain (``PHASE_IV_PLAN.md`` §1.3 put that at ~9.0M entries per
authority version bump).

**Revocation touches no index entry at all.** A revoke changes the authority's
``RevRoot_k`` and ``VID_k`` and therefore ``C_k^auth``, which propagates to the
FSNs as authorization state. The record entries are untouched, because the
authority's version and a record's version are different counters
(``PHASE_IV_PLAN.md`` §1.4). This is what lets Exp. 6 measure the IAS mechanism
rather than re-indexing.

**Notation caveat in Step 5.** The three ``Delta`` terms are not the same kind of
thing: ``dVID_i = VID_i' - VID_i`` is genuine arithmetic on integers, ``dC_i^auth``
is described as "the updated authority commitment" (a value, not a difference),
and ``dRoot_i = Root_i' - Root_i`` is *written* as a subtraction but cannot be one
— hash digests do not subtract. This module carries ``delta_vid`` as an integer
and the other two as the updated values, which is the only reading that
type-checks. Worth correcting in §V.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import ClassVar, Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..aim.aim import AuthorizationIndexManager  # noqa: E402
from ..authority.authority import Authority  # noqa: E402
from ..chain.ledger import Ledger, NS_VERSION_IDENTIFIERS  # noqa: E402
from ..fsn.fsn import FogSearchNode  # noqa: E402
from ..index.commit import (  # noqa: E402
    RecordCommitment,
    commit_record,
    policy_commitment,
    update_record_commitment,
)
from ..types import AuthorizationMeta, IndexEntry, Record, canonical  # noqa: E402


class IASError(RuntimeError):
    """Raised when an incremental update cannot be applied."""


class Operation(Enum):
    """``Op in {Insert, Modify, Delete, Revoke}`` — Step 1 (`:1007`)."""

    INSERT = "Insert"
    MODIFY = "Modify"
    DELETE = "Delete"
    REVOKE = "Revoke"

    @property
    def touches_index(self) -> bool:
        """Whether the operation rewrites searchable-index entries.

        ``Revoke`` does not: it changes authorization state only. Making that
        explicit here is what keeps Exp. 6 measuring the IAS mechanism instead of
        re-indexing a domain.
        """
        return self is not Operation.REVOKE

    @property
    def touches_authorization(self) -> bool:
        """Whether the operation advances the authority's version.

        Step 3 conditions on "if the update affects access policies, user
        attributes, or revocation state" — so a pure keyword insertion or
        deletion does not bump ``VID_k``, while a policy change or a revocation
        does.
        """
        return self in (Operation.MODIFY, Operation.REVOKE)


@dataclass(frozen=True)
class UpdateDelta:
    """``Delta_i`` — "the affected keywords, policy changes, metadata changes, or
    revocation information" (`:1007`).

    All fields optional because one ``Delta_i`` shape serves four operations; each
    operation validates the fields it needs in :meth:`UpdateRequest.validate`.
    """

    keywords_added: Tuple[str, ...] = ()
    keywords_removed: Tuple[str, ...] = ()
    policy_id: Optional[str] = None
    revoked: Tuple[str, ...] = ()
    restored: Tuple[str, ...] = ()

    @property
    def keyword_pair_count(self) -> int:
        """``k`` — the (keyword, document) pairs Exp. 5 sweeps."""
        return len(self.keywords_added) + len(self.keywords_removed)


@dataclass(frozen=True)
class UpdateRequest:
    """``U_i = (Op, CID_i, Delta_i)`` — Step 1."""

    operation: Operation
    cid: str
    delta: UpdateDelta = field(default_factory=UpdateDelta)

    def __post_init__(self) -> None:
        if not self.cid:
            raise ValueError("cid must not be empty")
        self.validate()

    def validate(self) -> None:
        op, delta = self.operation, self.delta
        if op is Operation.INSERT and not delta.keywords_added:
            raise IASError("Insert requires at least one added keyword")
        if op is Operation.DELETE and not delta.keywords_removed:
            raise IASError("Delete requires at least one removed keyword")
        if op is Operation.MODIFY and delta.policy_id is None:
            raise IASError("Modify requires the new policy identifier")
        if op is Operation.REVOKE and not (delta.revoked or delta.restored):
            raise IASError(
                "Revoke requires at least one revoked or restored identifier"
            )
        if op is not Operation.REVOKE and (delta.revoked or delta.restored):
            raise IASError(
                f"{op.value} carries revocation information; revocation state "
                f"evolves through Revoke so that Exp. 6 measures one mechanism"
            )


# ===========================================================================
# Step 3 — Authorization-State Evolution
# ===========================================================================
@dataclass(frozen=True)
class AuthorizationEvolution:
    """Before and after of one authority's state — Step 3 (`:1045`)."""

    authority_id: str
    domain: str
    previous_vid: int
    new_vid: int
    previous_commitment: bytes
    new_commitment: bytes
    previous_revocation_root: bytes
    new_revocation_root: bytes

    @property
    def delta_vid(self) -> int:
        """``dVID_i = VID_i' - VID_i`` — genuine arithmetic, unlike the others."""
        return self.new_vid - self.previous_vid

    @property
    def meta(self) -> AuthorizationMeta:
        """``Meta_i`` for the evolved state, as the AIM will synchronise it."""
        return AuthorizationMeta(
            domain=self.domain, vid=self.new_vid, commitment=self.new_commitment
        )


def evolve_authorization_state(
    authority: Authority,
    *,
    revoke: Sequence[str] = (),
    restore: Sequence[str] = (),
) -> AuthorizationEvolution:
    """Step 3: ``VID_k' = VID_k + 1``, ``RevRoot_k'``, ``C_k^auth'``.

    Exactly one increment. The manuscript writes ``VID_k' = VID_k + 1``, and a
    version that could jump would break Phase VI's ``C_j^sync`` as a distance
    measure — a node one update behind and a node five behind must not look alike.

    Only this authority changes. "Only the affected authority updates its
    commitment, while all other authorities retain their existing authorization
    states" (`:1045`) — which is the property Exp. 6's selective propagation
    depends on, so there is deliberately no batch form of this function that
    could sweep the federation.
    """
    previous_vid = authority.vid
    previous_commitment = authority.commitment()
    previous_root = authority.revocation_root()

    for identifier in restore:
        authority.revocation.restore(identifier)
    authority.revocation.revoke_many(revoke)
    authority.vid = previous_vid + 1

    return AuthorizationEvolution(
        authority_id=authority.authority_id,
        domain=authority.domain,
        previous_vid=previous_vid,
        new_vid=authority.vid,
        previous_commitment=previous_commitment,
        new_commitment=authority.commitment(),
        previous_revocation_root=previous_root,
        new_revocation_root=authority.revocation_root(),
    )


# ===========================================================================
# Step 2 — Localized Searchable-Index Evolution
# ===========================================================================
@dataclass(frozen=True)
class IndexEvolution:
    """What Step 2 changed, with the Exp. 5 secondary metrics.

    ``entries_rewritten`` and ``tokens_rewritten`` are reported separately because
    under Option D they differ: a policy change rewrites payload on every entry of
    a record while rewriting **no** token. A single combined figure would hide
    exactly the property Exp. 5 is asked to demonstrate.
    """

    cid: str
    entries: Tuple[IndexEntry, ...]
    entries_rewritten: int
    entries_inserted: int
    entries_removed: int
    tokens_rewritten: int

    @property
    def entries_touched(self) -> int:
        return self.entries_rewritten + self.entries_inserted + self.entries_removed


def evolve_index_entries(
    entries: Sequence[IndexEntry],
    request: UpdateRequest,
    *,
    token_for: Optional[callable] = None,
    new_vid: Optional[int] = None,
) -> IndexEvolution:
    """Step 2: rewrite only the affected entries of one record.

    ``token_for`` builds a token for a newly added keyword — injected rather than
    imported so this module never constructs a token itself; ``index/tokens.py``
    remains the single definition.

    No re-tokenization on Modify. As published Step 2 recomputes ``T_j'`` from the
    policy and version; under Option D the token is ``H(w)``, so only payload
    changes and ``tokens_rewritten`` stays 0. That is asserted by a test, because
    it is the whole basis of Exp. 5's incrementality.
    """
    op, delta = request.operation, request.delta
    remaining = list(entries)
    rewritten = inserted = removed = tokens = 0

    if op is Operation.REVOKE:
        # Authorization state only — the record's entries are untouched.
        #
        # This early return is a STATEMENT OF INTENT, not load-bearing logic:
        # every branch below is guarded on Modify/Delete/Insert, so a revoke
        # falling through would leave `remaining` untouched and produce the same
        # result. A mutation removing this return is therefore unobservable, and
        # no test pins it. It stays because "a revocation rewrites no index entry"
        # is the property Exp. 6 depends on, and a reader should not have to
        # derive it from three negative guards.
        return IndexEvolution(
            cid=request.cid,
            entries=tuple(remaining),
            entries_rewritten=0,
            entries_inserted=0,
            entries_removed=0,
            tokens_rewritten=0,
        )

    if op is Operation.MODIFY:
        policy_id = delta.policy_id
        vid = entries[0].vid if new_vid is None else new_vid
        remaining = [
            entry.with_policy(policy_id=policy_id, vid=vid) for entry in remaining
        ]
        rewritten = len(remaining)
        # tokens stays 0: the token does not encode policy or version.

    if op is Operation.DELETE:
        doomed = set(delta.keywords_removed)
        if token_for is None:
            raise IASError("Delete needs token_for to identify the doomed entries")
        doomed_tokens = {token_for(keyword) for keyword in doomed}
        before = len(remaining)
        remaining = [e for e in remaining if e.token not in doomed_tokens]
        removed = before - len(remaining)
        if removed != len(doomed):
            raise IASError(
                f"Delete named {len(doomed)} keywords but matched {removed} "
                f"entries for CID {request.cid!r}"
            )

    if op is Operation.INSERT:
        if token_for is None:
            raise IASError("Insert needs token_for to build the new entries")
        template = entries[0]
        for keyword in delta.keywords_added:
            token = token_for(keyword)
            if any(e.token == token for e in remaining):
                raise IASError(
                    f"keyword {keyword!r} is already indexed for CID "
                    f"{request.cid!r}"
                )
            remaining.append(
                IndexEntry(
                    token=token,
                    cid=template.cid,
                    policy_id=delta.policy_id or template.policy_id,
                    vid=template.vid,
                )
            )
            inserted += 1

    if not remaining:
        raise IASError(
            f"the update would leave CID {request.cid!r} with no index entries; "
            f"a record with no entries has no Merkle root (Phase IV Step 4)"
        )

    return IndexEvolution(
        cid=request.cid,
        entries=tuple(remaining),
        entries_rewritten=rewritten,
        entries_inserted=inserted,
        entries_removed=removed,
        tokens_rewritten=tokens,
    )


# ===========================================================================
# Step 4 — Incremental Merkle Commitment Update
# ===========================================================================
@dataclass(frozen=True)
class CommitmentEvolution:
    """``Root_i'`` and ``Commit_i'``, with the Exp. 5 node count."""

    commitment: RecordCommitment
    previous_root: bytes
    nodes_recomputed: int
    rebuilt: bool


def evolve_commitment(
    commitment: RecordCommitment,
    evolution: IndexEvolution,
    *,
    policy_id: str,
    vid: int,
    auth_root_do: bytes,
) -> CommitmentEvolution:
    """Step 4: ``Root_i' = MerkleUpdate(Root_i, L_Delta)`` then ``Commit_i'``.

    Path-updates when the leaf **count** is unchanged, which is the Modify case
    and the one Exp. 5's "Merkle nodes recomputed" metric is about.

    Insert and Delete change the leaf count, and a Merkle tree cannot grow or
    shrink by a path update — so that record's tree is rebuilt. Bounded by
    ``|W_i|`` (mean 31.7, capped at 64), **not** by the index: README §5's rule
    forbids a global rebuild, and a per-record rebuild of ~32 leaves is not one.
    ``rebuilt`` says which happened, so a reported figure can never silently
    conflate the two.
    """
    previous_root = commitment.root
    same_shape = len(evolution.entries) == commitment.entry_count

    if same_shape and evolution.entries_rewritten:
        updated = commitment
        recomputed = 0
        for index, entry in enumerate(evolution.entries):
            updated, nodes = update_record_commitment(
                updated,
                entry_index=index,
                entry=entry,
                policy_id=policy_id,
                vid=vid,
                auth_root_do=auth_root_do,
            )
            recomputed += nodes
        return CommitmentEvolution(
            commitment=updated,
            previous_root=previous_root,
            nodes_recomputed=recomputed,
            rebuilt=False,
        )

    rebuilt = commit_record(
        record_id=commitment.record_id,
        entries=evolution.entries,
        policy_id=policy_id,
        vid=vid,
        auth_root_do=auth_root_do,
    )
    return CommitmentEvolution(
        commitment=rebuilt,
        previous_root=previous_root,
        nodes_recomputed=rebuilt.tree.node_count,
        rebuilt=True,
    )


# ===========================================================================
# Step 5 — the IAS message
# ===========================================================================
@dataclass(frozen=True)
class IASMessage(Record):
    """``IAS_i = (CID_i, dVID_i, dC_i^auth, dI_i, dRoot_i, Commit_i')`` — Step 5.

    ``authority_id`` and ``domain`` are routing fields carried alongside the
    published six-tuple: ``dC_i^auth`` alone does not say *whose* commitment it
    is, and Step 6 has to reach the nodes serving that authority's domain.

    See the module docstring on the ``Delta`` notation: ``delta_vid`` is a
    difference, ``authority_commitment`` and ``root`` are updated values.
    """

    DOMAIN: ClassVar[bytes] = b"ias-message/v1"

    cid: str
    delta_vid: int
    authority_commitment: bytes
    entries: Tuple[IndexEntry, ...]
    root: bytes
    commit: bytes
    authority_id: str
    domain: str

    def __post_init__(self) -> None:
        for name in ("cid", "authority_id", "domain"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if self.delta_vid < 0:
            raise ValueError(
                f"dVID_i must be non-negative; authorization versions only "
                f"advance (got {self.delta_vid})"
            )
        for name in ("authority_commitment", "root", "commit"):
            if len(getattr(self, name)) != 32:
                raise ValueError(f"{name} must be a 32-byte digest")

    def _encoded_fields(self):
        return (
            self.cid,
            self.delta_vid,
            self.authority_commitment,
            list(self.entries),
            self.root,
            self.commit,
            self.authority_id,
            self.domain,
        )

    @property
    def size_bytes(self) -> int:
        """IAS message size — the Exp. 6 secondary metric, in bytes."""
        return len(self.encode())

    @property
    def size_kb(self) -> float:
        """README §9 reports sizes in KB."""
        return self.size_bytes / 1024.0

    @property
    def carries_index_delta(self) -> bool:
        """False for a revocation, which changes authorization state only."""
        return bool(self.entries)


def build_ias_message(
    *,
    cid: str,
    authorization: AuthorizationEvolution,
    index_evolution: IndexEvolution,
    commitment_evolution: CommitmentEvolution,
) -> IASMessage:
    """Step 5: assemble ``IAS_i``.

    ``dI_i`` carries **only** the modified entries. For a revocation that is the
    empty set, which is why the message stays small no matter how many records the
    authority governs — the property Exp. 6's message-size metric reports.
    """
    modified = (
        index_evolution.entries if index_evolution.entries_touched else ()
    )
    return IASMessage(
        cid=cid,
        delta_vid=authorization.delta_vid,
        authority_commitment=authorization.new_commitment,
        entries=tuple(modified),
        root=commitment_evolution.commitment.root,
        commit=commitment_evolution.commitment.commit,
        authority_id=authorization.authority_id,
        domain=authorization.domain,
    )


# ===========================================================================
# Step 6 — Selective Synchronization to FSNs
# ===========================================================================
@dataclass(frozen=True)
class ApplyResult:
    """What one node did with an IAS message."""

    node_id: str
    entries_rewritten: int
    authorization_updated: bool
    new_vid: int


def apply_ias(
    node: FogSearchNode, message: IASMessage, *, domain: Optional[str] = None
) -> ApplyResult:
    """``Shard_j' = ApplyIAS(Shard_j, IAS_i)`` — Step 6, on one node.

    Two effects, and the second is the one Phase VI reads: the shard's entries are
    repolicied to the message's payload, and the node's authorization state
    advances to the new ``(VID, C^auth)``. Without the second, "FSNs that have not
    yet applied the latest IAS message are assigned a higher
    version-synchronization cost" would have nothing to measure.

    **Observation on the published design.** ``IAS_i`` carries ``dVID_i``, a
    *difference*, so a node's new version is ``VID_j + dVID_i``. A node that
    missed an earlier IAS message therefore **cannot** reach the authority's
    current version from this one — delta-based synchronisation requires in-order,
    gap-free delivery. :func:`synchronize` checks the postcondition and reports the
    gap rather than letting a node silently settle on a version nobody published.
    Carrying ``VID_i'`` absolutely would make the message idempotent and
    gap-tolerant, at the cost of departing from the published tuple.
    """
    domain = domain or message.domain
    if not node.serves_domain(domain):
        raise IASError(
            f"{node.node_id} serves {sorted(node.domains)} and is not an "
            f"affected node for domain {domain!r}"
        )

    rewritten = 0
    if message.carries_index_delta:
        by_token = {entry.token: entry for entry in message.entries}
        for ordinal in node.index.ordinals_for_cid(message.cid):
            existing = node.index.entry(ordinal)
            replacement = by_token.get(existing.token)
            if replacement is None:
                continue
            if (
                replacement.policy_id != existing.policy_id
                or replacement.vid != existing.vid
            ):
                node.index.repolicy(
                    ordinal,
                    policy_id=replacement.policy_id,
                    vid=replacement.vid,
                )
                rewritten += 1

    # A node holding no state for this authority is at the honest floor of 0,
    # matching FogSearchNode.vid()'s treatment of an unsynchronized node.
    current = (
        node.vid_for_authority(message.authority_id)
        if message.authority_id in node.synced_authorities()
        else 0
    )
    updated = node.apply_meta(
        message.authority_id,
        AuthorizationMeta(
            domain=domain,
            vid=current + message.delta_vid,
            commitment=message.authority_commitment,
        ),
    )
    return ApplyResult(
        node_id=node.node_id,
        entries_rewritten=rewritten,
        authorization_updated=updated,
        new_vid=node.vid_for_authority(message.authority_id),
    )


def affected_nodes(
    message: IASMessage, nodes: Sequence[FogSearchNode]
) -> Tuple[FogSearchNode, ...]:
    """Nodes maintaining a shard for the affected domain — Step 6's recipients.

    "Rather than broadcasting the complete index state, the AIM forwards ``IAS_i``
    **only** to FSNs that maintain the affected searchable-index shards" (`:1111`).
    With the §V defaults that is one node in four, and it is what Exp. 6 reports as
    FSNs touched.
    """
    targets = tuple(node for node in nodes if node.serves_domain(message.domain))
    if not targets:
        raise IASError(
            f"no Fog Search Node serves domain {message.domain!r}; the update "
            f"would be applied nowhere"
        )
    return targets


@dataclass(frozen=True)
class IASReceipt:
    """One end-to-end Phase VII cycle, with the Exp. 5 and Exp. 6 metrics."""

    message: IASMessage
    authorization: AuthorizationEvolution
    index_evolution: IndexEvolution
    commitment_evolution: CommitmentEvolution
    applied: Tuple[ApplyResult, ...]
    elapsed_ns: int

    # -- Exp. 6 -------------------------------------------------------------
    @property
    def fsns_touched(self) -> Tuple[str, ...]:
        return tuple(result.node_id for result in self.applied)

    @property
    def touched_count(self) -> int:
        return len(self.applied)

    @property
    def message_size_kb(self) -> float:
        return self.message.size_kb

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1e6

    # -- Exp. 5 -------------------------------------------------------------
    @property
    def merkle_nodes_recomputed(self) -> int:
        return self.commitment_evolution.nodes_recomputed

    @property
    def entries_rewritten(self) -> int:
        return sum(result.entries_rewritten for result in self.applied)

    @property
    def tokens_rewritten(self) -> int:
        """0 under Option D for every operation that is not an Insert/Delete."""
        return self.index_evolution.tokens_rewritten


def synchronize(
    request: UpdateRequest,
    *,
    authority: Authority,
    nodes: Sequence[FogSearchNode],
    commitment: RecordCommitment,
    entries: Sequence[IndexEntry],
    auth_root_do: bytes,
    aim: Optional[AuthorizationIndexManager] = None,
    ledger: Optional[Ledger] = None,
    token_for: Optional[callable] = None,
) -> IASReceipt:
    """Phase VII Steps 2-7 end to end — the path Exp. 6 times.

    README §5: "IAS end-to-end: commitment recomputation → Merkle path update →
    IAS message → selective FSN propagation **until all affected FSNs report the
    new VID**." The final clause is a postcondition, so this verifies it rather
    than assuming delivery succeeded.
    """
    started = time.perf_counter_ns()

    # Step 3 — only the affected authority evolves.
    authorization = evolve_authorization_state(
        authority,
        revoke=request.delta.revoked,
        restore=request.delta.restored,
    ) if request.operation.touches_authorization else _unchanged(authority)

    # Step 2 — only the affected entries.
    index_evolution = evolve_index_entries(
        entries, request, token_for=token_for
    )

    # Step 4 — path update where the shape allows it.
    policy_id = request.delta.policy_id or entries[0].policy_id
    commitment_evolution = evolve_commitment(
        commitment,
        index_evolution,
        policy_id=policy_id,
        vid=index_evolution.entries[0].vid,
        auth_root_do=auth_root_do,
    )

    # Step 5 — the message.
    message = build_ias_message(
        cid=request.cid,
        authorization=authorization,
        index_evolution=index_evolution,
        commitment_evolution=commitment_evolution,
    )

    # Step 6 — selective propagation.
    targets = affected_nodes(message, nodes)
    applied = tuple(apply_ias(node, message) for node in targets)

    # The postcondition README §5 states: propagation continues "until all
    # affected FSNs report the new VID". Verified rather than assumed — a node
    # with a delivery gap cannot reach the current version from a delta alone
    # (see apply_ias), and that must surface here rather than leaving a node on a
    # version nobody published.
    for result in applied:
        if result.new_vid != authorization.new_vid:
            raise IASError(
                f"{result.node_id} reports VID {result.new_vid} after applying "
                f"IAS_i for {authorization.authority_id!r}, expected "
                f"{authorization.new_vid}. IAS_i carries dVID (a difference), so "
                f"a node that missed an earlier message cannot catch up from this "
                f"one — it needs the intervening IAS messages in order."
            )

    if aim is not None:
        aim.register_meta(authorization.authority_id, authorization.meta)
    if ledger is not None:
        anchor_update(ledger, message=message, vid=authorization.new_vid)

    return IASReceipt(
        message=message,
        authorization=authorization,
        index_evolution=index_evolution,
        commitment_evolution=commitment_evolution,
        applied=applied,
        elapsed_ns=time.perf_counter_ns() - started,
    )


def _unchanged(authority: Authority) -> AuthorizationEvolution:
    """A no-op evolution, for operations Step 3 does not apply to.

    A keyword insertion or deletion touches neither policies, attributes, nor
    revocation state, so ``VID_k`` must NOT advance — bumping it would make
    Exp. 6's version-skew metric respond to plain index churn.
    """
    commitment = authority.commitment()
    root = authority.revocation_root()
    return AuthorizationEvolution(
        authority_id=authority.authority_id,
        domain=authority.domain,
        previous_vid=authority.vid,
        new_vid=authority.vid,
        previous_commitment=commitment,
        new_commitment=commitment,
        previous_revocation_root=root,
        new_revocation_root=root,
    )


# ===========================================================================
# Step 7 — Blockchain Anchoring
# ===========================================================================
@dataclass(frozen=True)
class UpdateAnchor(Record):
    """``BC_i' = (CID_i, Commit_i', Root_i', VID_i', TS_i')`` — Step 7 (`:1127`)."""

    DOMAIN: ClassVar[bytes] = b"update-anchor/v1"

    cid: str
    commit: bytes
    root: bytes
    vid: int
    timestamp_ns: int

    def __post_init__(self) -> None:
        if not self.cid:
            raise ValueError("cid must not be empty")
        if self.vid < 0:
            raise ValueError(f"VID must be non-negative, got {self.vid}")
        for name in ("commit", "root"):
            if len(getattr(self, name)) != 32:
                raise ValueError(f"{name} must be a 32-byte digest")

    def _encoded_fields(self):
        return (self.cid, self.commit, self.root, self.vid, self.timestamp_ns)


def anchor_update(
    ledger: Ledger,
    *,
    message: IASMessage,
    vid: int,
    timestamp_ns: Optional[int] = None,
) -> UpdateAnchor:
    """Step 7: anchor ``BC_i'``, creating "a tamper-evident history".

    Keyed by ``CID_i`` and version, so each update is a new append rather than an
    overwrite — the ledger is append-only, and a history that could be rewritten
    would not be tamper-evident.
    """
    anchor = UpdateAnchor(
        cid=message.cid,
        commit=message.commit,
        root=message.root,
        vid=vid,
        timestamp_ns=time.time_ns() if timestamp_ns is None else timestamp_ns,
    )
    ledger.append(
        NS_VERSION_IDENTIFIERS, f"{message.cid}#{vid:012d}", anchor
    )
    return anchor


__all__ = [
    "IASError",
    "Operation",
    "UpdateDelta",
    "UpdateRequest",
    "AuthorizationEvolution",
    "IndexEvolution",
    "CommitmentEvolution",
    "IASMessage",
    "ApplyResult",
    "IASReceipt",
    "UpdateAnchor",
    "evolve_authorization_state",
    "evolve_index_entries",
    "evolve_commitment",
    "build_ias_message",
    "apply_ias",
    "affected_nodes",
    "synchronize",
    "anchor_update",
]
