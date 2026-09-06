"""Consortium-blockchain adapter for MA-LB-PQ-VDSE.

The manuscript's ledger is Hyperledger Fabric v2.5 (§V), storing "compact
metadata, including ciphertext commitments, Merkle roots, version-delta
commitments, public parameters of multiple Attribute Authorities, revocation
records, and audit logs" — never the encrypted data itself.

**Staging (decision of 2026-08-08).** Phases I-II are untimed setup (README §2),
so they run against :class:`InProcessLedger`. Fabric implements the same
:class:`Ledger` interface and must land before Exp. 4, which is the first
experiment that *measures* a blockchain-consistency check (Phase VIII Step 2).
No reportable number depends on the adapter until then. To keep that swap
honest, the in-process adapter is a real append-only hash chain rather than a
dictionary: ``verify_chain`` does the work Exp. 4 will time, so the consistency
check cannot turn out to be a no-op that Fabric later makes expensive.

Two properties are enforced here rather than left to callers:

* **Append-only.** A key can be written once. Phase VII publishes a *new*
  version rather than overwriting a state (``VID' = VID + 1``), so versioned
  records embed their VID in the key and history is retained. An overwrite
  raises :class:`ImmutabilityError`.
* **No secret material.** Only :class:`~..types.Record` instances can be
  appended, and ``AuthorityMasterKey`` is deliberately not a ``Record``, so
  MSK_i cannot reach the ledger through this interface at all.
"""

from __future__ import annotations

import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import (  # noqa: E402
    AuthorityRegistration,
    AuthorityState,
    PublicParameters,
    Record,
)

# ---------------------------------------------------------------------------
# Namespaces. Phase I Step 4 initialises "the system metadata repository for
# storing authority public parameters, Merkle roots, version identifiers,
# revocation information, and audit logs"; Phase II Steps 1 and 4 add authority
# registrations and authorization states. Creating them all up front is what
# Step 4 asks for, so later phases append to an existing namespace rather than
# conjuring one at first use.
# ---------------------------------------------------------------------------
NS_SYSTEM_PARAMETERS = "system_parameters"          # Phase I  Step 3: PP
NS_AUTHORITY_REGISTRATIONS = "authority_registrations"  # Phase II Step 1: Reg_i
NS_AUTHORIZATION_STATES = "authorization_states"    # Phase II Step 4: State_i
NS_MERKLE_ROOTS = "merkle_roots"                    # Phase IV Step 4 / VII Step 4
NS_VERSION_IDENTIFIERS = "version_identifiers"      # Phase VII Step 5
NS_REVOCATION_RECORDS = "revocation_records"        # Phase II Step 3 / VII Step 3
NS_AUDIT_LOGS = "audit_logs"                        # Phase VIII Step 6

NAMESPACES: Tuple[str, ...] = (
    NS_SYSTEM_PARAMETERS,
    NS_AUTHORITY_REGISTRATIONS,
    NS_AUTHORIZATION_STATES,
    NS_MERKLE_ROOTS,
    NS_VERSION_IDENTIFIERS,
    NS_REVOCATION_RECORDS,
    NS_AUDIT_LOGS,
)

# Width of the zero-padded VID in a versioned key, so that lexicographic key
# order equals numeric version order and "latest" is the last key rather than a
# numeric scan.
_VID_KEY_DIGITS = 12

_GENESIS = hashes.sha256(b"MA-LB-PQ-VDSE/ledger/genesis", domain=b"ledger/v1")


class LedgerError(RuntimeError):
    """Base class for ledger failures."""


class ImmutabilityError(LedgerError):
    """Raised when a write would overwrite an existing key."""


class NotFoundError(LedgerError):
    """Raised when a required record is absent."""


class ChainIntegrityError(LedgerError):
    """Raised when the entry hash chain does not verify."""


@dataclass(frozen=True)
class LedgerEntry:
    """One committed entry, linked into the hash chain.

    ``payload`` is the canonical encoding of the record — the bytes that are
    hashed and anchored. ``record`` is the typed object, retained by adapters
    that hold their records in memory; a Fabric adapter reading an entry it did
    not write will need a canonical decoder before it can populate this, which
    is the one piece of work the interface swap still requires.
    """

    sequence: int
    namespace: str
    key: str
    payload: bytes
    domain: bytes
    timestamp_ns: int
    previous_hash: bytes
    entry_hash: bytes
    record: Optional[Record] = None

    def recompute_hash(self) -> bytes:
        """Recompute this entry's chain hash from its own contents."""
        return _entry_hash(
            sequence=self.sequence,
            namespace=self.namespace,
            key=self.key,
            payload=self.payload,
            domain=self.domain,
            timestamp_ns=self.timestamp_ns,
            previous_hash=self.previous_hash,
        )


def _entry_hash(
    *,
    sequence: int,
    namespace: str,
    key: str,
    payload: bytes,
    domain: bytes,
    timestamp_ns: int,
    previous_hash: bytes,
) -> bytes:
    """Chain hash over the entry and its predecessor.

    The record's domain tag is hashed alongside its payload so that two records
    with identical field bytes but different types cannot produce the same
    entry. ``previous_hash`` is what makes the sequence tamper-evident: editing
    any earlier entry invalidates every hash after it.
    """
    return hashes.sha256(
        sequence.to_bytes(8, "big"),
        namespace.encode("utf-8"),
        key.encode("utf-8"),
        domain,
        payload,
        timestamp_ns.to_bytes(8, "big"),
        previous_hash,
        domain=b"ledger/v1",
    )


def state_key(authority_id: str, vid: int) -> str:
    """Key for State_i at version ``vid``.

    Versioned rather than overwritten: Phase VII Step 2 increments the version
    (``VID_k' = VID_k + 1``) and the chain must retain the old state, both for
    the audit property and because Phase VI's ``C_j^sync = |VID_U - VID_j|``
    needs historical versions to remain addressable.
    """
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return f"{authority_id}#{vid:0{_VID_KEY_DIGITS}d}"


class Ledger(ABC):
    """Interface every ledger adapter implements.

    Subclasses provide the four storage primitives; the typed protocol methods
    below are concrete, so the Fabric adapter inherits Phase I-II semantics
    (append-only registration, versioned states, latest-version lookup) rather
    than reimplementing them and possibly diverging.
    """

    # -- storage primitives -------------------------------------------------
    @abstractmethod
    def initialize(self) -> None:
        """Create the namespaces of :data:`NAMESPACES`. Idempotent."""

    @abstractmethod
    def append(self, namespace: str, key: str, record: Record) -> LedgerEntry:
        """Commit ``record``. Raises :class:`ImmutabilityError` if ``key`` exists."""

    @abstractmethod
    def get(self, namespace: str, key: str) -> LedgerEntry:
        """Return the entry at ``key``. Raises :class:`NotFoundError`."""

    @abstractmethod
    def keys(self, namespace: str, *, prefix: str = "") -> List[str]:
        """Sorted keys in ``namespace``, optionally filtered by ``prefix``."""

    @abstractmethod
    def chain_head(self) -> bytes:
        """Hash of the most recent entry, or the genesis hash if empty."""

    @abstractmethod
    def verify_chain(self) -> bool:
        """Recompute every link. This is the work Exp. 4 times (Phase VIII Step 2)."""

    @abstractmethod
    def entry_count(self) -> int:
        """Total committed entries."""

    def exists(self, namespace: str, key: str) -> bool:
        try:
            self.get(namespace, key)
        except NotFoundError:
            return False
        return True

    # -- Phase I ------------------------------------------------------------
    def publish_public_parameters(self, pp: PublicParameters) -> LedgerEntry:
        """Phase I Step 3: publish PP.

        Keyed by the PP digest, so republishing identical parameters is a
        no-op-shaped duplicate-key error rather than a second copy, while any
        *change* to PP lands under a new key and both versions stay visible.
        """
        return self.append(NS_SYSTEM_PARAMETERS, pp.digest().hex(), pp)

    # -- Phase II -----------------------------------------------------------
    def register_authority(self, registration: AuthorityRegistration) -> LedgerEntry:
        """Phase II Step 1: anchor Reg_i = (ID_i, Dom_i, PK_i).

        One registration per authority identifier: a second one raises, which
        is what makes the anchor an identity a peer can rely on when deciding
        whether to accept the authority's attributes.
        """
        return self.append(
            NS_AUTHORITY_REGISTRATIONS, registration.authority_id, registration
        )

    def get_registration(self, authority_id: str) -> AuthorityRegistration:
        entry = self.get(NS_AUTHORITY_REGISTRATIONS, authority_id)
        record = entry.record
        if not isinstance(record, AuthorityRegistration):
            raise LedgerError(
                f"entry at {authority_id!r} is not an AuthorityRegistration"
            )
        return record

    def registered_authorities(self) -> List[str]:
        return self.keys(NS_AUTHORITY_REGISTRATIONS)

    def publish_authorization_state(self, state: AuthorityState) -> LedgerEntry:
        """Phase II Step 4: publish State_i = (ID_i, PK_i, C_i^auth, VID_i).

        The authority must already be registered — Phase II Step 1 precedes
        Step 4, and a state published for an unregistered authority would be a
        commitment no peer can authenticate.
        """
        if not self.exists(NS_AUTHORITY_REGISTRATIONS, state.authority_id):
            raise NotFoundError(
                f"authority {state.authority_id!r} is not registered; "
                f"Phase II Step 1 must precede Step 4"
            )
        return self.append(
            NS_AUTHORIZATION_STATES, state_key(state.authority_id, state.vid), state
        )

    def get_authorization_state(self, authority_id: str, vid: int) -> AuthorityState:
        entry = self.get(NS_AUTHORIZATION_STATES, state_key(authority_id, vid))
        record = entry.record
        if not isinstance(record, AuthorityState):
            raise LedgerError(
                f"entry for {authority_id!r}@{vid} is not an AuthorityState"
            )
        return record

    def latest_authorization_state(self, authority_id: str) -> AuthorityState:
        """Highest-VID state for ``authority_id``.

        Keys are zero-padded, so the highest version is the last key in sorted
        order and this needs no numeric scan.
        """
        keys = self.keys(NS_AUTHORIZATION_STATES, prefix=f"{authority_id}#")
        if not keys:
            raise NotFoundError(
                f"no authorization state published for authority {authority_id!r}"
            )
        entry = self.get(NS_AUTHORIZATION_STATES, keys[-1])
        record = entry.record
        if not isinstance(record, AuthorityState):
            raise LedgerError(f"entry at {keys[-1]!r} is not an AuthorityState")
        return record

    def authorization_state_history(self, authority_id: str) -> List[AuthorityState]:
        """Every published version for ``authority_id``, oldest first."""
        return [
            self.get(NS_AUTHORIZATION_STATES, key).record  # type: ignore[misc]
            for key in self.keys(NS_AUTHORIZATION_STATES, prefix=f"{authority_id}#")
        ]


class InProcessLedger(Ledger):
    """Single-process append-only hash chain.

    Correct for Phases I-III (untimed setup, one process) and for development.
    NOT a substitute for Fabric once Fog Search Nodes become independent
    processes: this holds its state in one interpreter's memory, so each process
    would get its own private chain. Phase VI is where that starts to matter,
    and Exp. 4 is where it starts to be measured.

    Locked because the AIM and the authorities will drive it from separate
    threads during Phase II synchronisation.
    """

    def __init__(self, *, clock=time.time_ns) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: List[LedgerEntry] = []
        self._by_key: Dict[Tuple[str, str], LedgerEntry] = {}
        self._namespaces: Dict[str, List[str]] = {}
        self.initialize()

    # -- storage primitives -------------------------------------------------
    def initialize(self) -> None:
        with self._lock:
            for namespace in NAMESPACES:
                self._namespaces.setdefault(namespace, [])

    def append(self, namespace: str, key: str, record: Record) -> LedgerEntry:
        if not isinstance(record, Record):
            # AuthorityMasterKey is not a Record precisely so that it lands
            # here rather than on the chain.
            raise TypeError(
                f"only Record instances can be committed, got "
                f"{type(record).__name__}"
            )
        if namespace not in self._namespaces:
            raise LedgerError(
                f"unknown namespace {namespace!r}; expected one of {NAMESPACES}"
            )
        if not key:
            raise ValueError("key must not be empty")

        with self._lock:
            if (namespace, key) in self._by_key:
                raise ImmutabilityError(
                    f"{namespace}/{key} already committed; the ledger is "
                    f"append-only (publish a new version instead of "
                    f"overwriting)"
                )
            sequence = len(self._entries)
            previous_hash = self.chain_head()
            payload = record.encode()
            timestamp_ns = self._clock()
            entry = LedgerEntry(
                sequence=sequence,
                namespace=namespace,
                key=key,
                payload=payload,
                domain=record.DOMAIN,
                timestamp_ns=timestamp_ns,
                previous_hash=previous_hash,
                entry_hash=_entry_hash(
                    sequence=sequence,
                    namespace=namespace,
                    key=key,
                    payload=payload,
                    domain=record.DOMAIN,
                    timestamp_ns=timestamp_ns,
                    previous_hash=previous_hash,
                ),
                record=record,
            )
            self._entries.append(entry)
            self._by_key[(namespace, key)] = entry
            self._namespaces[namespace].append(key)
            return entry

    def get(self, namespace: str, key: str) -> LedgerEntry:
        with self._lock:
            try:
                return self._by_key[(namespace, key)]
            except KeyError:
                raise NotFoundError(f"no entry at {namespace}/{key}") from None

    def keys(self, namespace: str, *, prefix: str = "") -> List[str]:
        with self._lock:
            if namespace not in self._namespaces:
                raise LedgerError(f"unknown namespace {namespace!r}")
            return sorted(
                key for key in self._namespaces[namespace] if key.startswith(prefix)
            )

    def chain_head(self) -> bytes:
        with self._lock:
            return self._entries[-1].entry_hash if self._entries else _GENESIS

    def verify_chain(self) -> bool:
        with self._lock:
            previous = _GENESIS
            for position, entry in enumerate(self._entries):
                if entry.sequence != position:
                    return False
                if entry.previous_hash != previous:
                    return False
                if entry.recompute_hash() != entry.entry_hash:
                    return False
                previous = entry.entry_hash
            return True

    def entry_count(self) -> int:
        with self._lock:
            return len(self._entries)

    # -- diagnostics --------------------------------------------------------
    def entries(self, namespace: Optional[str] = None) -> Sequence[LedgerEntry]:
        """Committed entries in commit order, optionally one namespace only."""
        with self._lock:
            if namespace is None:
                return tuple(self._entries)
            return tuple(e for e in self._entries if e.namespace == namespace)

    def namespace_sizes(self) -> Dict[str, int]:
        with self._lock:
            return {ns: len(keys) for ns, keys in self._namespaces.items()}


__all__ = [
    "NAMESPACES",
    "NS_SYSTEM_PARAMETERS",
    "NS_AUTHORITY_REGISTRATIONS",
    "NS_AUTHORIZATION_STATES",
    "NS_MERKLE_ROOTS",
    "NS_VERSION_IDENTIFIERS",
    "NS_REVOCATION_RECORDS",
    "NS_AUDIT_LOGS",
    "LedgerError",
    "ImmutabilityError",
    "NotFoundError",
    "ChainIntegrityError",
    "LedgerEntry",
    "Ledger",
    "InProcessLedger",
    "state_key",
]
