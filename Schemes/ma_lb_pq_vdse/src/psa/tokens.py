"""D1 — the manuscript's token: ``T = H(w ‖ PID ‖ PV ‖ Dom)``.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    T_{i,j}     = H( w_{i,j} ‖ PID_i ‖ PV_i ‖ Dom_i )      eq:policy-bound-token
    T^Q_{r,ℓ}   = H( w_r     ‖ PID_ℓ ‖ PV_ℓ ‖ Dom_ℓ )      eq:query-token

and Theorem "Policy-State Token Consistency" asserts the two are equal when the
keyword, policy, domain and policy-relevant authority state agree. Here that is
not an assertion but a single function called from both sides —
:meth:`PolicyStateTokenScheme.token` — so the theorem holds by construction and
cannot drift.

HOW THIS DIFFERS FROM ``index/tokens.py``
-----------------------------------------
Option D reduces both tokens to ``H(w)`` and moves policy, version and domain
onto a separate tag and a bitmap. Three properties flip as a result, and each is
a measurable cost rather than a matter of taste:

* **One trapdoor no longer serves every domain.** Option D's
  ``Trapdoor.is_domain_independent`` is ``True``; here a token names one
  ``(policy, domain, policy-state)``, so a query authorized under ``|P_U|``
  policies needs ``q·|P_U|`` tokens. That is exactly the manuscript's
  ``|T_Q| = q|P_U|`` (Exp. 1) and divergence D7.
* **An authority version bump re-tokenizes.** ``PV_i`` is an input, so Phase VII
  Step 2 recomputes ``T'`` for every affected entry where Option D touches none.
* **A policy change re-tokenizes**, for the same reason.

WHY ``H`` IS STILL KEYED
------------------------
The published inputs are all low-entropy: the frozen corpus has 2,006 keywords,
and ``PID_i``, ``PV_i`` and ``Dom_i`` are enumerable from any FSN's own shard
metadata. An unkeyed ``H`` therefore inverts the entire index by brute force,
and adding three enumerable fields to the preimage does not change that — it
only widens the loop. ``crypto.yaml → global.prf: hmac-sha256`` is what the
scheme actually fixes, so :meth:`keyed` is the reportable construction and
:meth:`unkeyed` exists so the literal published form can be measured.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import canonical  # noqa: E402

#: Distinct from ``index/tokens.py``'s ``pdsi-token/v1``. A PSA token and an
#: Option D token must never collide even for the same keyword: the two
#: constructions can coexist in one process (the harness builds both), and a
#: shared tag would let one construction's index answer the other's query.
_TOKEN_DOMAIN = b"psa-token/v1"

#: ``index.yaml → dsi.token_bits``. Matches Option D so the two constructions
#: produce equal-width tokens and their index sizes stay comparable.
DEFAULT_TOKEN_BITS = 256


class TokenError(RuntimeError):
    """Raised when a policy-state-bound token cannot be produced."""


@dataclass(frozen=True)
class PolicyStateTokenScheme:
    """eq:policy-bound-token / eq:query-token, as one function.

    Construct via :meth:`keyed` or :meth:`unkeyed`; there is no default, for the
    reason ``index/tokens.py`` gives at length — the choice changes both a
    security property and a reported number.
    """

    search_key: Optional[bytes]
    token_bits: int = DEFAULT_TOKEN_BITS

    def __post_init__(self) -> None:
        if self.token_bits <= 0 or self.token_bits > 256:
            raise TokenError(f"token_bits must be in 1..256, got {self.token_bits}")
        if self.token_bits % 8:
            raise TokenError(
                f"token_bits must be a whole number of bytes, got {self.token_bits}"
            )
        if self.search_key is not None:
            if not isinstance(self.search_key, (bytes, bytearray)):
                raise TypeError("search_key must be bytes")
            if len(self.search_key) < 32:
                raise TokenError(
                    f"search key must be at least 32 bytes (crypto.yaml "
                    f"prf.key_bits: 256), got {len(self.search_key)}"
                )

    @classmethod
    def keyed(
        cls, search_key: bytes, *, token_bits: int = DEFAULT_TOKEN_BITS
    ) -> "PolicyStateTokenScheme":
        return cls(search_key=bytes(search_key), token_bits=token_bits)

    @classmethod
    def unkeyed(cls, *, token_bits: int = DEFAULT_TOKEN_BITS) -> "PolicyStateTokenScheme":
        return cls(search_key=None, token_bits=token_bits)

    @classmethod
    def from_config(
        cls, config, search_key: Optional[bytes]
    ) -> "PolicyStateTokenScheme":
        if config.index.token_hash != "sha256":
            raise TokenError(
                f"index.yaml dsi.token_hash is {config.index.token_hash!r}; this "
                f"module instantiates H over SHA-256"
            )
        return cls(search_key=search_key, token_bits=config.index.token_bits)

    @property
    def is_keyed(self) -> bool:
        return self.search_key is not None

    @property
    def token_bytes(self) -> int:
        return self.token_bits // 8

    # -- the one function both sides call --------------------------------
    def token(
        self, keyword: str, *, policy_id: str, pv: bytes, domain: str
    ) -> bytes:
        """``H(w ‖ PID ‖ PV ‖ Dom)``.

        Used unchanged for the index token of Phase IV Step 2 and the query
        token of Phase VI Step 2 — see :meth:`index_token` and
        :meth:`query_token`, which are aliases rather than reimplementations.
        """
        if not isinstance(keyword, str):
            raise TypeError(f"keyword must be str, got {type(keyword).__name__}")
        if not keyword:
            raise TokenError("keyword must not be empty")
        if not policy_id:
            raise TokenError("policy_id must not be empty")
        if not domain:
            raise TokenError("domain must not be empty")
        if not isinstance(pv, (bytes, bytearray)) or not pv:
            raise TokenError("PV must be non-empty bytes (psa.state.PolicyVersionState)")

        payload = canonical([keyword, policy_id, bytes(pv), domain])
        if self.search_key is None:
            digest = hashes.sha256(payload, domain=_TOKEN_DOMAIN)
        else:
            digest = hashes.hmac_sha256(self.search_key, _TOKEN_DOMAIN, payload)
        return digest[: self.token_bytes]

    def index_token(
        self, keyword: str, *, policy_id: str, pv: bytes, domain: str
    ) -> bytes:
        """``T_{i,j}`` — Phase IV Step 2."""
        return self.token(keyword, policy_id=policy_id, pv=pv, domain=domain)

    def query_token(
        self, keyword: str, *, policy_id: str, pv: bytes, domain: str
    ) -> bytes:
        """``T^Q_{r,ℓ}`` — Phase VI Step 2. The same value, by construction."""
        return self.token(keyword, policy_id=policy_id, pv=pv, domain=domain)

    def index_tokens(
        self, keywords: Iterable[str], *, policy_id: str, pv: bytes, domain: str
    ) -> Tuple[bytes, ...]:
        return tuple(
            self.token(k, policy_id=policy_id, pv=pv, domain=domain) for k in keywords
        )

    def __repr__(self) -> str:
        mode = "keyed" if self.is_keyed else "UNKEYED (invertible)"
        return f"PolicyStateTokenScheme({mode}, token_bits={self.token_bits})"


@dataclass(frozen=True)
class PolicyScopedQuery:
    """One ``(policy, domain, PV)`` a query must be evaluated under."""

    policy_id: str
    domain: str
    pv: bytes


def generate_query_tokens(
    scheme: PolicyStateTokenScheme,
    keywords: Sequence[str],
    scopes: Sequence[PolicyScopedQuery],
) -> Tuple[bytes, ...]:
    """``T_Q = {T^Q_{r,ℓ}}`` over ``w_r ∈ Q`` and ``P_ℓ ∈ P_U`` — Phase VI Step 2.

    ``|T_Q| = q·|P_U|`` exactly, which is the quantity Exp. 1 sweeps (D7) and
    the ``|T_Q|`` that every proposed-scheme row of ``tab:cost`` is now written
    in terms of (D6).

    Duplicate keywords are rejected, matching ``index/tokens.py``: a conjunctive
    query repeating a keyword is a caller bug, and collapsing it silently would
    report a smaller ``q`` than the caller asked for.
    """
    if not keywords:
        raise TokenError("a query must contain at least one keyword")
    if len(set(keywords)) != len(keywords):
        raise TokenError(
            f"duplicate keyword in a {len(keywords)}-keyword query; a "
            f"conjunctive query over a repeated keyword is a caller error"
        )
    if not scopes:
        raise TokenError(
            "a query must name at least one authorized policy; an empty P_U "
            "means the user satisfies no policy and the request is rejected "
            "before token derivation (Phase VI Step 2)"
        )
    return tuple(
        scheme.token(
            keyword, policy_id=scope.policy_id, pv=scope.pv, domain=scope.domain
        )
        for scope in scopes
        for keyword in keywords
    )


__all__ = [
    "DEFAULT_TOKEN_BITS",
    "PolicyScopedQuery",
    "PolicyStateTokenScheme",
    "TokenError",
    "generate_query_tokens",
]
