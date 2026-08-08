"""Canonical record types and byte encodings for MA-LB-PQ-VDSE.

Every integrity claim in the scheme is a hash over a concatenation of
heterogeneous fields:

    C_i^auth   = H(ID_i || Dom_i || H(A_i) || VID_i || RevRoot_i)   Phase II Step 3
    AuthRoot_U = H(UID || H(S_U) || VID_U || H(C_U))                Phase III Step 4
    T_j        = H(w_j || PID_i || VID_i || Dom_i)                  Phase IV Step 2
    Commit_i   = H(Root_i || PID_i || VID_i || AuthRoot_DO)         Phase IV Step 5

The manuscript's ``||`` is plain concatenation, which is ambiguous in two
separate ways: it cannot distinguish different splits of the same byte string
(``("ab","c")`` vs ``("a","bc")``), and it cannot distinguish a field's *type*
(the integer ``VID_i = 53`` from the string ``"53"``). Either ambiguity lets two
different authorization states produce one commitment, which would defeat the
binding property the commitments exist to provide.

This module therefore defines ONE canonical encoding, used by every record that
is hashed or published, and every protocol record as a frozen dataclass over
it. Two rules follow from the ambiguity above and are enforced here rather than
by convention:

* every field is length-prefixed and type-tagged (``canonical``);
* every record type carries its own domain tag, so two records with identical
  field values but different meanings cannot share a digest.

**Group elements are ``bytes`` at this layer.** Pairing elements are
backend-specific objects (charm), so serialising them is the pairing layer's
job, not this one's: ``abe/ma_cpabe.py`` converts backend elements to and from
bytes and everything here deals in the serialised form. That keeps this module
and ``chain/ledger.py`` fully testable on a host with no pairing backend
installed, which the macOS development host is.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from Common.crypto import hashes  # noqa: E402

# Digest width for every commitment in the scheme: §V specifies SHA-256 for
# hashing and Merkle-tree construction (crypto.yaml -> ma_lb_pq_vdse
# .hash_output_bits: 256). Records validate against this rather than accepting
# any byte string, so a truncated or wrong-algorithm digest fails at
# construction instead of silently producing a valid-looking commitment.
DIGEST_BYTES = 32


class EncodingError(TypeError):
    """A value cannot be canonically encoded."""


class SecretMaterialError(RuntimeError):
    """Raised on any attempt to encode or publish secret key material."""


# ===========================================================================
# Canonical encoding
# ===========================================================================
# Type tags. Distinct tags are what make the encoding injective ACROSS types:
# without them, canonical(b"") and canonical(0) and canonical("") would all be
# the empty string with a zero length prefix.
_T_BYTES = b"\x01"
_T_UINT = b"\x02"
_T_NEGINT = b"\x03"
_T_STR = b"\x04"
_T_SEQ = b"\x05"
_T_RECORD = b"\x06"
_T_BOOL = b"\x07"


def _u32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise EncodingError(f"length {n} does not fit in 4 bytes")
    return n.to_bytes(4, "big")


def _int_magnitude(n: int) -> bytes:
    """Minimal big-endian magnitude. Zero encodes as empty, so it is unique."""
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def canonical(value: Any) -> bytes:
    """Injective byte encoding of ``value``.

    Injective means: two values encode to the same bytes only if they are the
    same value. That is the property the commitments depend on.

    Supported: ``bytes``, ``bool``, ``int`` (any sign), ``str``, ``Sequence``,
    and :class:`Record`. ``dict`` is deliberately REJECTED — a mapping has no
    inherent order, and silently sorting one here would hide an ordering
    decision that belongs at the call site where its consequences are visible
    (see :class:`PublicParameters`, which holds sorted pairs).
    """
    # bool before int: bool is a subclass of int, and True would otherwise
    # encode identically to 1.
    if isinstance(value, bool):
        return _T_BOOL + (b"\x01" if value else b"\x00")
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return _T_BYTES + _u32(len(raw)) + raw
    if isinstance(value, int):
        magnitude = _int_magnitude(abs(value))
        tag = _T_NEGINT if value < 0 else _T_UINT
        return tag + _u32(len(magnitude)) + magnitude
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _T_STR + _u32(len(raw)) + raw
    if isinstance(value, Record):
        body = value.encode()
        return (
            _T_RECORD
            + _u32(len(value.DOMAIN))
            + value.DOMAIN
            + _u32(len(body))
            + body
        )
    if isinstance(value, dict):
        raise EncodingError(
            "dict is not canonically encodable: pass a sorted sequence of "
            "(key, value) pairs so the ordering is explicit"
        )
    if isinstance(value, Sequence):
        parts = [canonical(item) for item in value]
        return _T_SEQ + _u32(len(parts)) + b"".join(parts)
    raise EncodingError(f"cannot canonically encode {type(value).__name__}")


def digest(value: Any, *, domain: bytes) -> bytes:
    """Domain-separated SHA-256 over the canonical encoding of ``value``."""
    return hashes.sha256(canonical(value), domain=domain)


def _check_digest(name: str, value: bytes) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(value) != DIGEST_BYTES:
        raise ValueError(
            f"{name} must be {DIGEST_BYTES} bytes (SHA-256), got {len(value)}"
        )


def _check_identifier(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must not be empty")


def _check_vid(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"VID must be int, got {type(value).__name__}")
    # Phase VII Step 3 defines VID' = VID + 1, and Phase VI's synchronisation
    # cost is C_j^sync = |VID_U - VID_j|; both require a monotone counter, so a
    # negative version is a bug rather than an unusual input.
    if value < 0:
        raise ValueError(f"VID must be non-negative, got {value}")


# ===========================================================================
# Record base
# ===========================================================================
@dataclass(frozen=True)
class Record:
    """A protocol record with a canonical encoding and a domain tag.

    Frozen because these are published objects: a record whose fields could
    change after its digest was anchored on the ledger would break the binding
    the anchor is for.
    """

    DOMAIN: ClassVar[bytes] = b""

    def _encoded_fields(self) -> Tuple[Any, ...]:
        raise NotImplementedError

    def encode(self) -> bytes:
        """Canonical bytes for this record's fields (no domain tag)."""
        return canonical(self._encoded_fields())

    def digest(self) -> bytes:
        """Domain-separated SHA-256 of this record."""
        return hashes.sha256(self.encode(), domain=self.DOMAIN)


# ===========================================================================
# Phase I — System Initialization
# ===========================================================================
@dataclass(frozen=True)
class PrimitiveSuite(Record):
    """The primitive set P of Phase I Step 1, plus the resolved pairing.

    Phase I Step 1 fixes P = {H, SHA-256, AES-256-GCM, HKDF, ML-KEM}. This
    record does not implement any of them — they come from ``Common/crypto``
    (README §8: primitives a paper *cites* are shared). It records WHICH
    instantiation was resolved, so the choice lands in ``run_meta.json`` and a
    reader can tell whether a result came from liboqs ML-KEM or a pure-Python
    fallback, or from a Type-I curve substituted for the published Type-III.
    """

    DOMAIN: ClassVar[bytes] = b"suite/v1"

    hash_algorithm: str
    aead_algorithm: str
    kdf_algorithm: str
    kem_algorithm: str
    kem_backend: str
    pairing_type: str
    pairing_curve: str
    pairing_backend: str

    def __post_init__(self) -> None:
        for name in (
            "hash_algorithm",
            "aead_algorithm",
            "kdf_algorithm",
            "kem_algorithm",
            "kem_backend",
            "pairing_type",
            "pairing_curve",
            "pairing_backend",
        ):
            _check_identifier(name, getattr(self, name))
        # crypto.yaml -> ma_lb_pq_vdse.pairing.allow_symmetric_backend: false.
        # Phase I Step 1 publishes e : G_1 x G_2 -> G_T; a symmetric curve
        # changes both group-element sizes and pairing cost, so substituting
        # one is a construction change, not a backend detail.
        if self.pairing_type != "type-3":
            raise ValueError(
                f"the proposed scheme publishes a Type-III pairing "
                f"(e : G_1 x G_2 -> G_T); refusing pairing_type="
                f"{self.pairing_type!r}"
            )

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (
            self.hash_algorithm,
            self.aead_algorithm,
            self.kdf_algorithm,
            self.kem_algorithm,
            self.kem_backend,
            self.pairing_type,
            self.pairing_curve,
            self.pairing_backend,
        )


@dataclass(frozen=True)
class AuthorityPublicKey(Record):
    """PK_i = (g_1, g_2, e(g_1,g_2)^{alpha_i}, g_1^{beta_i}) — Phase I Step 2.

    Elements are serialised group elements; see the module docstring on why
    this layer holds bytes rather than backend objects.
    """

    DOMAIN: ClassVar[bytes] = b"authority-pk/v1"

    g1: bytes
    g2: bytes
    e_g1g2_alpha: bytes
    g1_beta: bytes

    def __post_init__(self) -> None:
        for name in ("g1", "g2", "e_g1g2_alpha", "g1_beta"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(f"{name} must be bytes")
            if not value:
                raise ValueError(f"{name} must not be empty")

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (self.g1, self.g2, self.e_g1g2_alpha, self.g1_beta)


@dataclass(frozen=True)
class AuthorityMasterKey:
    """MSK_i = (alpha_i, beta_i) — Phase I Step 2. NEVER published.

    Deliberately NOT a :class:`Record`: it has no canonical encoding and no
    digest, so it cannot be handed to the ledger, hashed into a commitment, or
    reached through any code path that publishes. ``encode`` exists only to
    raise, so an attempt to serialise it fails loudly at the call site instead
    of quietly leaking alpha_i into an anchored record.
    """

    alpha: bytes
    beta: bytes

    def __post_init__(self) -> None:
        for name in ("alpha", "beta"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(f"{name} must be bytes")
            if not value:
                raise ValueError(f"{name} must not be empty")

    def encode(self) -> bytes:  # pragma: no cover - exists to raise
        raise SecretMaterialError(
            "MSK_i = (alpha_i, beta_i) is master secret key material and has "
            "no published encoding"
        )

    def digest(self) -> bytes:  # pragma: no cover - exists to raise
        raise SecretMaterialError("refusing to digest master secret key material")

    def __repr__(self) -> str:
        return "AuthorityMasterKey(alpha=<redacted>, beta=<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class PublicParameters(Record):
    """PP = (G_1, G_2, G_T, e, g_1, g_2, {PK_i}, P) — Phase I Step 3.

    The groups and the map are identified by the suite's curve and backend
    rather than carried as objects: two runs agree on PP exactly when they
    resolved the same curve, and that is what the digest needs to capture.

    ``authority_public_keys`` is a tuple of ``(ID_i, PK_i)`` pairs sorted by
    ID, not a dict, so the PP digest does not depend on the order authorities
    happened to register in.
    """

    DOMAIN: ClassVar[bytes] = b"public-parameters/v1"

    suite: PrimitiveSuite
    g1: bytes
    g2: bytes
    authority_public_keys: Tuple[Tuple[str, AuthorityPublicKey], ...] = field(
        default=()
    )

    def __post_init__(self) -> None:
        ids = [authority_id for authority_id, _ in self.authority_public_keys]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate authority ID in PP")
        if list(ids) != sorted(ids):
            raise ValueError(
                "authority_public_keys must be sorted by authority ID so the "
                "PP digest is independent of registration order; use "
                "PublicParameters.build()"
            )

    @classmethod
    def build(
        cls,
        suite: PrimitiveSuite,
        g1: bytes,
        g2: bytes,
        authority_public_keys: Sequence[Tuple[str, AuthorityPublicKey]] = (),
    ) -> "PublicParameters":
        """Construct PP, sorting the authority keys by ID."""
        return cls(
            suite=suite,
            g1=g1,
            g2=g2,
            authority_public_keys=tuple(
                sorted(authority_public_keys, key=lambda pair: pair[0])
            ),
        )

    @property
    def authority_count(self) -> int:
        """N_AA — the number of participating Attribute Authorities."""
        return len(self.authority_public_keys)

    def public_key(self, authority_id: str) -> AuthorityPublicKey:
        for candidate_id, public_key in self.authority_public_keys:
            if candidate_id == authority_id:
                return public_key
        raise KeyError(f"no public key in PP for authority {authority_id!r}")

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (
            self.suite,
            self.g1,
            self.g2,
            [list(pair) for pair in self.authority_public_keys],
        )


# ===========================================================================
# Phase II — Multi-Authority Registration and Authorization-State Commitment
# ===========================================================================
@dataclass(frozen=True)
class AuthorityRegistration(Record):
    """Reg_i = (ID_i, Dom_i, PK_i) — Phase II Step 1."""

    DOMAIN: ClassVar[bytes] = b"authority-registration/v1"

    authority_id: str
    domain: str
    public_key: AuthorityPublicKey

    def __post_init__(self) -> None:
        _check_identifier("authority_id", self.authority_id)
        _check_identifier("domain", self.domain)

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (self.authority_id, self.domain, self.public_key)


@dataclass(frozen=True)
class AuthorityState(Record):
    """State_i = (ID_i, PK_i, C_i^auth, VID_i) — Phase II Step 4.

    ``commitment`` is C_i^auth as computed in Phase II Step 3. This record
    carries it; it does not compute it (that is ``authority/authority.py``, so
    that the commitment rule lives in one place and this layer cannot grow a
    second, divergent copy of it).
    """

    DOMAIN: ClassVar[bytes] = b"authority-state/v1"

    authority_id: str
    public_key: AuthorityPublicKey
    commitment: bytes
    vid: int

    def __post_init__(self) -> None:
        _check_identifier("authority_id", self.authority_id)
        _check_digest("commitment", self.commitment)
        _check_vid(self.vid)

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (self.authority_id, self.public_key, self.commitment, self.vid)


@dataclass(frozen=True)
class AuthorizationMeta(Record):
    """Meta_i = (Dom_i, VID_i, C_i^auth) — Phase II Step 4.

    What the AIM synchronises to the Fog Search Nodes. Strictly smaller than
    State_i: the FSNs receive the domain, version, and commitment, not the
    authority public key, which is the point of the AIM sitting between them.
    """

    DOMAIN: ClassVar[bytes] = b"authorization-meta/v1"

    domain: str
    vid: int
    commitment: bytes

    def __post_init__(self) -> None:
        _check_identifier("domain", self.domain)
        _check_vid(self.vid)
        _check_digest("commitment", self.commitment)

    def _encoded_fields(self) -> Tuple[Any, ...]:
        return (self.domain, self.vid, self.commitment)


__all__ = [
    "DIGEST_BYTES",
    "EncodingError",
    "SecretMaterialError",
    "canonical",
    "digest",
    "Record",
    "PrimitiveSuite",
    "AuthorityPublicKey",
    "AuthorityMasterKey",
    "PublicParameters",
    "AuthorityRegistration",
    "AuthorityState",
    "AuthorizationMeta",
]
