"""Phase IV Step 2 — keyword tokenization and the policy tag (Option D).

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:635` writes the index token as

    T_j = H( w_j ‖ PID_i ‖ VID_i ‖ Dom_i )

while Phase VI Step 1 `:829` writes the query token as
``T_Q = {H(w_i ‖ VID_U)}`` and Phase VI Step 4 leaves the matching relation
``T_Q → I_i`` undefined. ``PHASE_IV_PLAN.md`` §1 sets out why those cannot all
hold, and **Option D was chosen on 2026-08-10**:

    T_j = T_Q = H(w)                                   the lookup key
    PolicyTag_i = H( PID_i ‖ VID_i ‖ Dom_i )           the policy binding

Policy, version and domain leave the lookup key and become (a) payload on the
index entry, (b) the ``(domain, policy)`` bitmap key the FSN filters on, and
(c) this compact tag. §V `:1892` requires exactly this shape: "a single
authorization-bound trapdoor… reused across participating domains, while each fog
search node enforces domain-specific authorization locally… bitmap filtering
removes unauthorized ciphertexts before encrypted matching".

Three properties follow, each pinned by a test:

* **One trapdoor serves every domain** — ``index_token`` and ``query_token`` are
  the same function, which is the Exp. 3 claim.
* **A version bump does not change a token** — so version skew degrades results
  rather than zeroing them, and an authority version change does not re-tokenize
  its domain (the 9.0M-entry problem of ``PHASE_IV_PLAN.md`` §1.3).
* **A policy change does not change a token** — so Exp. 5 measures an incremental
  update rather than a re-tokenization.

---

**``H`` must be keyed, and this is the one decision Option D still leaves open.**

Option D reduces the lookup key to a function of the keyword alone. If that
function is an unkeyed hash, an honest-but-curious Fog Search Node recovers the
**entire** index contents by hashing the vocabulary — and the frozen corpus's
vocabulary is **2,006 keywords**. That is 2,006 hash evaluations to invert every
token in the index. Not a weakening introduced by Option D: the published
four-input token is dictionary-attackable too, since ``PID_i``, ``VID_i`` and
``Dom_i`` are all low-entropy and enumerable. Option D only makes it trivial.

Textual support for keying, from the manuscript itself: Phase I Step 1 `:380`
lists ``P = {H, SHA-256, AES-256-GCM, HKDF, ML-KEM}`` with **``H`` and SHA-256 as
separate members**, assigning SHA-256 to "constructs Merkle commitments" and
``H`` to "searchable-index generation". ``H`` is therefore *not* SHA-256, and the
standard instantiation for index generation is a keyed PRF —
``crypto.yaml → global.prf: hmac-sha256``, already fixed.

So :class:`TokenScheme` **requires an explicit choice**: ``TokenScheme.keyed(key)``
or ``TokenScheme.unkeyed()``. There is no default, because this is not a detail
that should be settled by whichever constructor happened to be convenient. It
also **affects a reported number** — HMAC-SHA256 costs roughly two SHA-256
compressions, and Exp. 1 measures exactly this operation ``q`` times per query.
Recorded as open decision 6 in ``PHASE_IV_PLAN.md``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import RecordMetadata, canonical  # noqa: E402

# Domain tags for the two values this module produces.
#
# The primary separation between a lookup key and a policy tag is NOT these tags:
# it is the canonical encoding's arity. A token hashes ``canonical([keyword])``, a
# one-element sequence; a tag hashes ``canonical([policy_id, vid, domain])``, a
# three-element one. No keyword can therefore produce a tag value, whatever the
# domain tags are — a mutation collapsing these two constants into one changes no
# observable behaviour, which is why no test pins it.
#
# They are kept as defence-in-depth: if either payload ever grew to match the
# other's arity, the tags would still keep the two apart.
_TOKEN_DOMAIN = b"pdsi-token/v1"
_POLICY_TAG_DOMAIN = b"pdsi-policy-tag/v1"

#: Full SHA-256 width, per ``index.yaml → dsi.token_bits: 256``. Truncating would
#: shrink the index and speed up search — a free win the paper does not claim.
DEFAULT_TOKEN_BITS = 256


class TokenError(RuntimeError):
    """Raised when a token or policy tag cannot be produced."""


@dataclass(frozen=True)
class TokenScheme:
    """The Phase IV Step 2 encoding, under Option D.

    Construct via :meth:`keyed` or :meth:`unkeyed` — see the module docstring on
    why there is no default.
    """

    search_key: Optional[bytes]
    token_bits: int = DEFAULT_TOKEN_BITS

    def __post_init__(self) -> None:
        if self.token_bits <= 0 or self.token_bits > 256:
            raise TokenError(
                f"token_bits must be in 1..256, got {self.token_bits}"
            )
        if self.token_bits % 8:
            raise TokenError(
                f"token_bits must be a whole number of bytes, got "
                f"{self.token_bits}"
            )
        if self.search_key is not None:
            if not isinstance(self.search_key, (bytes, bytearray)):
                raise TypeError("search_key must be bytes")
            # crypto.yaml -> global.prf.key_bits: 256.
            if len(self.search_key) < 32:
                raise TokenError(
                    f"search key must be at least 32 bytes (crypto.yaml "
                    f"prf.key_bits: 256), got {len(self.search_key)}"
                )

    # -- construction -------------------------------------------------------
    @classmethod
    def keyed(
        cls, search_key: bytes, *, token_bits: int = DEFAULT_TOKEN_BITS
    ) -> "TokenScheme":
        """``H`` as a keyed PRF — HMAC-SHA256, per ``crypto.yaml``.

        The instantiation the module docstring argues for: without a key, the
        2,006-keyword vocabulary inverts every token in the index.
        """
        return cls(search_key=bytes(search_key), token_bits=token_bits)

    @classmethod
    def unkeyed(cls, *, token_bits: int = DEFAULT_TOKEN_BITS) -> "TokenScheme":
        """``H`` as a bare SHA-256 — the literal reading of the published ``H``.

        Implemented so the published form can be measured rather than argued
        about. **Tokens produced this way are invertible** by hashing the keyword
        universe, so an index built with it is plaintext-equivalent to an
        honest-but-curious node.
        """
        return cls(search_key=None, token_bits=token_bits)

    @classmethod
    def from_config(cls, config, search_key: Optional[bytes]) -> "TokenScheme":
        """Take the token width from ``index.yaml`` rather than a literal."""
        if config.index.token_hash != "sha256":
            raise TokenError(
                f"index.yaml dsi.token_hash is {config.index.token_hash!r}; this "
                f"module instantiates H over SHA-256"
            )
        return cls(search_key=search_key, token_bits=config.index.token_bits)

    # -- properties ---------------------------------------------------------
    @property
    def is_keyed(self) -> bool:
        return self.search_key is not None

    @property
    def token_bytes(self) -> int:
        return self.token_bits // 8

    # -- Phase IV Step 2 / Phase VI Step 1 ----------------------------------
    def _evaluate(self, keyword: str) -> bytes:
        if not isinstance(keyword, str):
            raise TypeError(f"keyword must be str, got {type(keyword).__name__}")
        if not keyword:
            raise TokenError("keyword must not be empty")
        payload = canonical([keyword])
        if self.search_key is None:
            digest = hashes.sha256(payload, domain=_TOKEN_DOMAIN)
        else:
            digest = hashes.hmac_sha256(
                self.search_key, _TOKEN_DOMAIN, payload
            )
        return digest[: self.token_bytes]

    def index_token(self, keyword: str) -> bytes:
        """``T_j`` — the lookup key stored in the index (Phase IV Step 2)."""
        return self._evaluate(keyword)

    def query_token(self, keyword: str) -> bytes:
        """``T_Q`` element — the lookup key a query presents (Phase VI Step 1).

        Identical to :meth:`index_token` **by construction, not by coincidence**.
        That equality *is* Option D: it is what lets one trapdoor be reused across
        every participating domain, which is the Exp. 3 claim, and what makes the
        matching relation of Phase VI Step 4 an equality rather than an undefined
        arrow.
        """
        return self._evaluate(keyword)

    def index_tokens(self, keywords: Iterable[str]) -> Tuple[bytes, ...]:
        return tuple(self.index_token(keyword) for keyword in keywords)

    # -- the policy tag -----------------------------------------------------
    def policy_tag(self, *, policy_id: str, vid: int, domain: str) -> bytes:
        """``PolicyTag_i = H(PID_i ‖ VID_i ‖ Dom_i)``.

        What Option D keeps of "policy-bound": the binding moves off the lookup
        key and onto a compact value that any party holding
        ``(PID_i, VID_i, Dom_i)`` can recompute and check.

        **What this tag does and does not authenticate**, stated precisely because
        "authenticated" is easy to overclaim:

        * ``PID_i`` and ``VID_i`` are cryptographically bound already — they are
          fields of ``I_j``, and ``L_j = H(I_j)`` puts them under ``Root_i`` and
          hence under ``Commit_i``. An entry cannot have its policy or version
          altered without breaking the Merkle proof.
        * ``Dom_i`` is **not** a field of ``I_j`` (the published tuple is
          ``(T_j, CID_i, PID_i, VID_i)``), so its binding rests on the shard the
          entry lives in — shards are domain-keyed and ``dsi.py`` refuses a
          foreign-domain insert — plus Phase V Step 4's ``Sync_i``, which carries
          the routing. That is an *architectural* binding, not a cryptographic
          one.

        Closing that last gap would mean either adding ``Dom_i`` to ``I_j`` or
        folding this tag into ``L_j``, both of which change a published formula.
        Recorded as open decision 7 in ``PHASE_IV_PLAN.md`` rather than done
        quietly here.
        """
        if not policy_id:
            raise ValueError("policy_id must not be empty")
        if not domain:
            raise ValueError("domain must not be empty")
        if vid < 0:
            raise ValueError(f"VID must be non-negative, got {vid}")
        return hashes.sha256(
            canonical([policy_id, vid, domain]), domain=_POLICY_TAG_DOMAIN
        )

    def policy_tag_for(self, metadata: RecordMetadata) -> bytes:
        """The policy tag for a record's ``Meta_i``."""
        return self.policy_tag(
            policy_id=metadata.policy_id, vid=metadata.vid, domain=metadata.domain
        )

    def verify_policy_tag(
        self, tag: bytes, *, policy_id: str, vid: int, domain: str
    ) -> bool:
        """Recompute the tag and compare in constant time."""
        expected = self.policy_tag(policy_id=policy_id, vid=vid, domain=domain)
        return hashes.constant_time_equal(expected, tag)

    def __repr__(self) -> str:
        mode = "keyed" if self.is_keyed else "UNKEYED (invertible)"
        return f"TokenScheme({mode}, token_bits={self.token_bits})"


@dataclass(frozen=True)
class Trapdoor:
    """``T_Q`` — the search token's keyword component (Phase VI Step 1).

    One trapdoor per query, not one per domain: that is the Exp. 3 claim, and
    :attr:`size_bytes` is the Exp. 1 secondary metric.

    Only the keyword tokens live here. The full search token
    ``ST = (T_Q, AuthRoot_U, VID_U, ρ)`` is assembled in Phase VI Step 1, which
    also owns the nonce.
    """

    tokens: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not self.tokens:
            raise TokenError("a trapdoor must cover at least one keyword")

    @property
    def keyword_count(self) -> int:
        """``q`` — the Exp. 1 sweep variable."""
        return len(self.tokens)

    @property
    def size_bytes(self) -> int:
        """Exp. 1 secondary metric: trapdoor size in bytes."""
        return sum(len(token) for token in self.tokens)

    @property
    def is_domain_independent(self) -> bool:
        """True under Option D: nothing here names a domain, policy, or version.

        Structural rather than decorative — it is the property that makes
        ``d`` searches share one trapdoor in Exp. 3.
        """
        return True


def generate_trapdoor(scheme: TokenScheme, keywords: Sequence[str]) -> Trapdoor:
    """Phase VI Step 1's keyword tokens: ``q`` PRF evaluations, nothing else.

    This is the operation Exp. 1 times. It touches no pairing, no ML-KEM, and no
    per-domain state — ML-KEM encapsulation is a one-time session cost the Exp. 1
    rule excludes, and the absence of per-domain work is why one trapdoor serves
    ``d`` domains.

    Duplicate keywords are rejected rather than deduplicated: a conjunctive query
    repeating a keyword is a caller bug, and silently collapsing it would report a
    smaller ``q`` than the caller asked for, corrupting the Exp. 1 sweep.
    """
    if not keywords:
        raise TokenError("a query must contain at least one keyword")
    if len(set(keywords)) != len(keywords):
        raise TokenError(
            f"duplicate keyword in a {len(keywords)}-keyword query; a "
            f"conjunctive query over a repeated keyword is a caller error"
        )
    return Trapdoor(tokens=tuple(scheme.query_token(k) for k in keywords))


__all__ = [
    "DEFAULT_TOKEN_BITS",
    "TokenError",
    "TokenScheme",
    "Trapdoor",
    "generate_trapdoor",
]
