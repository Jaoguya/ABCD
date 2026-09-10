"""Phase VI Step 1-2 — Search Request and Policy-State-Aware Token Derivation.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    Q  = {w_1, ..., w_q}
    ST = ( T_Q, AuthRoot_U, VID_U, rho )
    T_Q = { H(w_i ‖ VID_U) }_{i=1..q}

"``rho`` is a fresh random nonce preventing replay attacks. The search token is
transmitted to the Authorization Index Manager (AIM)."

**This is the Exp. 1 measured path**, and its cost boundary is set by global.yaml:
"online trapdoor generation only. ML-KEM encapsulation happens once at session
establishment; report it separately as a setup cost, not in the per-query curve."
So generating ``ST`` is ``q`` PRF evaluations plus a nonce draw — no pairing, no
KEM, no per-domain work. The absence of per-domain work is what makes Exp. 3's
single-trapdoor claim true.

**On the published ``T_Q = {H(w_i ‖ VID_U)}``.** Option D makes each token
``H(w)`` alone (``index/tokens.py``). Nothing is lost by dropping ``VID_U`` from
the hash, and the reason is visible in the tuple above: **``ST`` already transmits
``VID_U`` in the clear as its own field.** Hashing it into every token gave an
honest-but-curious AIM or FSN no information it did not already hold, while making
a trapdoor unusable across domains whose authorization versions differ — which is
exactly the property Exp. 3 needs. The version is still bound to the request; it
is bound once, where the AIM can read and check it, instead of ``q`` times where
nobody can.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import rng  # noqa: E402

from ..index.tokens import TokenScheme, generate_trapdoor  # noqa: E402
from ..types import SearchToken, VersionBoundAuthorizationProfile  # noqa: E402

#: Width of ``rho``. 128 bits of fresh randomness makes a collision — and so an
#: accidental replay rejection — negligible across the 5,000-concurrency workload
#: of Exp. 7-8.
NONCE_BYTES = 16


class TokenGenerationError(RuntimeError):
    """Raised when a search token cannot be generated."""


def fresh_nonce(size: int = NONCE_BYTES) -> bytes:
    """``rho`` — a fresh nonce from the OS CSPRNG.

    Not from ``DeterministicRNG``: a predictable ``rho`` would let an adversary
    precompute the replay it is supposed to prevent. The experiment harness's
    reproducibility comes from a recorded arrival trace (``workload/``), not from
    seeding this.
    """
    if size < NONCE_BYTES:
        raise TokenGenerationError(
            f"rho must be at least {NONCE_BYTES} bytes, got {size}"
        )
    return rng.secure_random_bytes(size)


def generate_search_token(
    scheme: TokenScheme,
    profile: VersionBoundAuthorizationProfile,
    keywords: Sequence[str],
    *,
    nonce: Optional[bytes] = None,
) -> SearchToken:
    """Phase VI Step 1: assemble ``ST = (T_Q, AuthRoot_U, VID_U, rho)``.

    ``AuthRoot_U`` and ``VID_U`` are read from the user's VAP rather than passed
    separately, so a token cannot claim an authorization state its profile does not
    hold — the AIM checks both against the authorities in Step 2, and a mismatch
    there would be indistinguishable from an attack.

    ``nonce`` is injectable for tests only; production draws a fresh one per call.
    """
    if not keywords:
        raise TokenGenerationError("a query must contain at least one keyword")
    trapdoor = generate_trapdoor(scheme, keywords)
    return SearchToken(
        tokens=trapdoor.tokens,
        auth_root=profile.auth_root,
        vid_u=profile.vid,
        nonce=fresh_nonce() if nonce is None else nonce,
    )


@dataclass(frozen=True)
class TrapdoorCost:
    """What Exp. 1 reports for one token generation.

    ``keyword_count`` is the sweep variable ``q`` (1→20) and ``size_bytes`` the
    secondary metric. Latency is timed by the harness around
    :func:`generate_search_token`, since timing inside would measure the
    instrumentation too.
    """

    keyword_count: int
    size_bytes: int
    token_bytes: int

    @property
    def overhead_bytes(self) -> int:
        """Bytes ``ST`` carries beyond the keyword tokens themselves.

        ``AuthRoot_U`` (32) + ``VID_U`` + ``rho`` (16) plus encoding framing. Fixed
        per query, so it flattens the Exp. 1 size curve at small ``q`` — worth
        reporting rather than letting a reader infer the tokens are larger than
        they are.
        """
        return self.size_bytes - self.token_bytes


def trapdoor_cost(token: SearchToken) -> TrapdoorCost:
    """Measure one ``ST`` for the Exp. 1 secondary metric."""
    return TrapdoorCost(
        keyword_count=token.keyword_count,
        size_bytes=token.size_bytes,
        token_bytes=sum(len(t) for t in token.tokens),
    )


__all__ = [
    "NONCE_BYTES",
    "TokenGenerationError",
    "TrapdoorCost",
    "fresh_nonce",
    "generate_search_token",
    "trapdoor_cost",
]
