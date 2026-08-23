"""Authorization Index Manager — Phase II Step 4.

Phase II Step 4: the authority publishes
``State_i = (ID_i, PK_i, C_i^auth, VID_i)`` to the consortium blockchain, and
"simultaneously, the Authorization Index Manager (AIM) synchronizes the latest
authorization metadata ``Meta_i = (Dom_i, VID_i, C_i^auth)`` across all
cloud--fog search infrastructures."

The AIM is the off-chain service the rest of the protocol reads from, so this
registry is built once here with the accessors later phases need:

* ``C_U``, the set of authority commitments for a user's authorities —
  Phase III Step 4's ``AuthRoot_U``;
* domain to authority, for the shard authorization of Phase VI Step 2;
* the version table, for ``C_j^sync = |VID_U - VID_j|`` in Phase VI Step 3;
* the affected-FSN set, for the selective propagation of Phase VII Step 6.

**The AIM's view derives from the ledger.** :meth:`AuthorizationIndexManager
.synchronize_from_ledger` reads ``Reg_i`` and the latest ``State_i`` and builds
``Meta_i`` from them, rather than accepting metadata from the authority object
directly. An AIM whose commitments came from a side channel could disagree with
the chain and nobody would notice; deriving them means the two agree by
construction, and :meth:`verify_against_ledger` re-checks it.

**Propagation always takes an explicit FSN set.** Phase II is the *initial*
synchronization and legitimately reaches every node, but Phase VII Step 6's
selectivity — "the AIM forwards ``IAS_i`` only to FSNs that maintain the affected
searchable-index shards" — is the claim Exp. 6 measures. If Phase II wired a
broadcast that later phases inherited, Exp. 6 would measure a broadcast. So
there is no broadcast method: :meth:`propagate` takes the nodes to reach, and
:meth:`affected_fsns` computes which those are.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..chain.ledger import Ledger, NotFoundError  # noqa: E402
from ..fsn.fsn import FogSearchNode  # noqa: E402
from ..types import AuthorizationMeta  # noqa: E402


class AIMError(RuntimeError):
    """Raised on an invalid AIM operation."""


class AuthorizationStateMismatchError(AIMError):
    """Raised when the AIM's view disagrees with the ledger."""


@dataclass(frozen=True)
class PropagationResult:
    """Outcome of one synchronization push.

    ``fsns_touched`` is the Exp. 6 secondary metric — README §5: "Report FSNs
    touched; selective propagation is the claim." It counts nodes the AIM
    *contacted*, not nodes whose state changed, because contacting a node is the
    cost the metric is about; ``fsns_updated`` records the subset that actually
    moved.
    """

    authority_id: str
    vid: int
    fsns_touched: Tuple[str, ...]
    fsns_updated: Tuple[str, ...]

    @property
    def touched_count(self) -> int:
        return len(self.fsns_touched)

    @property
    def updated_count(self) -> int:
        return len(self.fsns_updated)


class AuthorizationIndexManager:
    """The AIM's authorization registry and synchronization engine."""

    def __init__(self) -> None:
        self._meta: Dict[str, AuthorizationMeta] = {}

    # -- registry -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._meta)

    @property
    def authorities(self) -> Tuple[str, ...]:
        return tuple(sorted(self._meta))

    def register_meta(self, authority_id: str, meta: AuthorizationMeta) -> None:
        """Record ``Meta_i`` for an authority.

        Refuses a version older than the one held, for the same reason a Fog
        Search Node does: authorization versions only advance, so an older one is
        a replay, and accepting it would roll the AIM's view backwards while the
        ledger still held the newer state.
        """
        if not authority_id:
            raise ValueError("authority_id must not be empty")
        existing = self._meta.get(authority_id)
        if existing is not None and meta.vid < existing.vid:
            raise AIMError(
                f"refusing Meta for {authority_id!r} at VID {meta.vid}; the AIM "
                f"already holds VID {existing.vid}"
            )
        self._meta[authority_id] = meta

    def synchronize_from_ledger(
        self, ledger: Ledger, authority_id: str
    ) -> AuthorizationMeta:
        """Build and record ``Meta_i`` from the anchored ``Reg_i`` and ``State_i``.

        ``Dom_i`` comes from the registration of Phase II Step 1 and
        ``(VID_i, C_i^auth)`` from the latest state of Phase II Step 4, which is
        exactly the decomposition the manuscript publishes.
        """
        try:
            registration = ledger.get_registration(authority_id)
        except NotFoundError:
            raise AIMError(
                f"authority {authority_id!r} is not registered on the ledger; "
                f"Phase II Step 1 must precede synchronization"
            ) from None
        try:
            state = ledger.latest_authorization_state(authority_id)
        except NotFoundError:
            raise AIMError(
                f"authority {authority_id!r} has published no authorization "
                f"state; Phase II Step 3 must precede synchronization"
            ) from None

        meta = AuthorizationMeta(
            domain=registration.domain, vid=state.vid, commitment=state.commitment
        )
        self.register_meta(authority_id, meta)
        return meta

    def meta_for_authority(self, authority_id: str) -> AuthorizationMeta:
        try:
            return self._meta[authority_id]
        except KeyError:
            raise AIMError(
                f"the AIM holds no authorization metadata for {authority_id!r}"
            ) from None

    def authorities_for_domain(self, domain: str) -> Tuple[str, ...]:
        """Which authorities administer ``domain`` — Phase VI Step 2 shard scope."""
        return tuple(
            sorted(
                authority_id
                for authority_id, meta in self._meta.items()
                if meta.domain == domain
            )
        )

    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted({meta.domain for meta in self._meta.values()}))

    def version_table(self) -> Mapping[str, int]:
        """``VID_i`` per authority — the AIM side of Phase VI's ``C_j^sync``."""
        return {authority_id: meta.vid for authority_id, meta in self._meta.items()}

    def commitments(
        self, authority_ids: Optional[Iterable[str]] = None
    ) -> Tuple[bytes, ...]:
        """``C_U`` — the commitments of the given authorities, in ID order.

        Phase III Step 4 hashes this set into ``AuthRoot_U``. Returned in sorted
        authority-ID order so ``H(C_U)`` does not depend on the order the user's
        authorities were enumerated in.
        """
        selected = sorted(self._meta) if authority_ids is None else sorted(authority_ids)
        missing = [a for a in selected if a not in self._meta]
        if missing:
            raise AIMError(
                f"the AIM holds no authorization metadata for {missing}"
            )
        return tuple(self._meta[authority_id].commitment for authority_id in selected)

    # -- propagation --------------------------------------------------------
    def affected_fsns(
        self, authority_id: str, fsns: Sequence[FogSearchNode]
    ) -> Tuple[FogSearchNode, ...]:
        """The nodes maintaining shards for this authority's domain.

        Phase VII Step 6 forwards only to these. With the §V default of ``d = 4``
        domains over ``m = 4`` nodes this is one node in four, which is what makes
        the selectivity visible in Exp. 6.
        """
        domain = self.meta_for_authority(authority_id).domain
        return tuple(node for node in fsns if node.serves_domain(domain))

    def propagate(
        self,
        authority_id: str,
        fsns: Sequence[FogSearchNode],
    ) -> PropagationResult:
        """Push ``Meta_i`` to exactly the nodes given.

        The caller decides the recipient set: Phase II Step 4 passes every node
        (initial synchronization), Phase VII Step 6 passes
        :meth:`affected_fsns`. There is deliberately no method that fans out to
        all nodes on its own.
        """
        meta = self.meta_for_authority(authority_id)
        touched: List[str] = []
        updated: List[str] = []
        for node in fsns:
            touched.append(node.node_id)
            if node.apply_meta(authority_id, meta):
                updated.append(node.node_id)
        return PropagationResult(
            authority_id=authority_id,
            vid=meta.vid,
            fsns_touched=tuple(touched),
            fsns_updated=tuple(updated),
        )

    def propagate_selectively(
        self, authority_id: str, fsns: Sequence[FogSearchNode]
    ) -> PropagationResult:
        """Push ``Meta_i`` only to the affected nodes — Phase VII Step 6."""
        return self.propagate(authority_id, self.affected_fsns(authority_id, fsns))

    # -- verification -------------------------------------------------------
    def verify_against_ledger(self, ledger: Ledger) -> None:
        """Check every held ``Meta_i`` against the chain.

        The AIM is off-chain, so its view can drift from the anchored state. This
        is the check that says it has not: same commitment, same version, same
        domain, for every authority the AIM knows.
        """
        for authority_id, meta in sorted(self._meta.items()):
            state = ledger.latest_authorization_state(authority_id)
            registration = ledger.get_registration(authority_id)
            if meta.commitment != state.commitment:
                raise AuthorizationStateMismatchError(
                    f"{authority_id}: AIM commitment "
                    f"{meta.commitment.hex()[:16]}... != ledger "
                    f"{state.commitment.hex()[:16]}..."
                )
            if meta.vid != state.vid:
                raise AuthorizationStateMismatchError(
                    f"{authority_id}: AIM VID {meta.vid} != ledger {state.vid}"
                )
            if meta.domain != registration.domain:
                raise AuthorizationStateMismatchError(
                    f"{authority_id}: AIM domain {meta.domain!r} != registered "
                    f"{registration.domain!r}"
                )

    def verify_fsn_synchronization(
        self, fsns: Sequence[FogSearchNode], *, authority_id: Optional[str] = None
    ) -> Tuple[str, ...]:
        """Node IDs whose state differs from the AIM's.

        Returns the stale nodes rather than raising: staleness is a normal
        operating condition the AASS scheduler is designed to route around
        (Phase VII Step 6 — "FSNs that have not yet applied the latest IAS
        message are assigned a higher version-synchronization cost"), not an
        error.
        """
        targets = [authority_id] if authority_id else list(self._meta)
        stale: List[str] = []
        for node in fsns:
            for target in targets:
                meta = self._meta[target]
                if not node.serves_domain(meta.domain):
                    continue
                try:
                    if node.meta_for_authority(target) != meta:
                        stale.append(node.node_id)
                        break
                except Exception:
                    stale.append(node.node_id)
                    break
        return tuple(stale)

    def __repr__(self) -> str:
        return (
            f"AuthorizationIndexManager(authorities={len(self._meta)}, "
            f"domains={list(self.domains())})"
        )


def initial_synchronization(
    aim: AuthorizationIndexManager,
    ledger: Ledger,
    authority_ids: Sequence[str],
    fsns: Sequence[FogSearchNode],
) -> Tuple[PropagationResult, ...]:
    """Phase II Step 4 for a whole federation.

    Synchronizes each authority's ``Meta_i`` from the ledger and pushes it to
    **every** node. Reaching every node is correct here and only here: this is
    the initial synchronization, before which the nodes hold no authorization
    state at all. Phase VII uses :meth:`AuthorizationIndexManager
    .propagate_selectively`.
    """
    results: List[PropagationResult] = []
    for authority_id in authority_ids:
        aim.synchronize_from_ledger(ledger, authority_id)
        results.append(aim.propagate(authority_id, fsns))
    return tuple(results)


__all__ = [
    "AIMError",
    "AuthorizationStateMismatchError",
    "PropagationResult",
    "AuthorizationIndexManager",
    "initial_synchronization",
]
