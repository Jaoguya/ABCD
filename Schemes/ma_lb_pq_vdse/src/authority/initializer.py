"""Phase I: System Initialization — Steps 1 and 3.

Step 1 (Global Cryptographic Initialization) selects the bilinear groups
``G_1, G_2, G_T`` of prime order ``p`` with the map ``e : G_1 x G_2 -> G_T`` and
generators ``g_1 in G_1``, ``g_2 in G_2``, and initializes

    P = { H, SHA-256, AES-256-GCM, HKDF, ML-KEM }

Step 3 (Public Parameter Publication) assembles

    PP = ( G_1, G_2, G_T, e, g_1, g_2, {PK_i}_{i=1..N_AA}, P )

and publishes it to the consortium blockchain.

Step 2 — per-authority ``Setup(1^lambda)`` — is ``authority.py``, and it needs
the group this module resolves. Steps 1 and 3 therefore bracket it: the caller
runs :func:`initialize`, then Step 2 for each authority, then
:func:`publish_public_parameters` with the resulting ``PK_i``.

None of this is timed (README §2: Phases I-III are setup). The one figure Phase I
contributes is the ML-KEM session-establishment cost, which
:func:`measure_kem_setup_cost` reports separately — the Exp. 1 measurement rule
keeps encapsulation out of the per-query trapdoor curve.

**The group is not resolvable yet.** ``Common/crypto/pairing.py`` exposes a
Type-I charm backend (SS512) and a Type-III petrelic backend that does not
build; the Type-III charm backend this scheme needs does not exist, which
``crypto.yaml`` records as ``backend_implemented: false``. So
:func:`resolve_group` raises an actionable error rather than substituting the
Type-I curve that *is* installed. A caller may inject a ``group_provider`` — the
tests do — but any group not produced by a faithful backend sets
``faithful=False``, and :meth:`GlobalContext.assert_reportable` then refuses.
That way the code is runnable and testable today without a path that could emit
a reportable number from the wrong group.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, kem as kem_mod, symmetric  # noqa: E402
from Common.crypto.config import get as crypto_get  # noqa: E402

from .. import config as scheme_config  # noqa: E402
from ..chain.ledger import Ledger  # noqa: E402
from ..types import (  # noqa: E402
    AuthorityPublicKey,
    PrimitiveSuite,
    PublicParameters,
)


class InitializationError(RuntimeError):
    """Raised when Phase I cannot complete."""


class PairingBackendMissingError(InitializationError):
    """Raised when no faithful Type-III pairing backend is available."""


class UnfaithfulGroupError(InitializationError):
    """Raised when a reportable run would use a group from no real backend."""


@dataclass(frozen=True)
class GroupDescription:
    """The resolved bilinear group of Phase I Step 1.

    ``e_g1_g2`` is ``e(g_1, g_2)``, computed once here because every authority's
    ``PK_i`` contains ``e(g_1,g_2)^{alpha_i}`` (Phase I Step 2). Computing it
    once and exponentiating per authority costs ``N_AA`` exponentiations and one
    pairing; recomputing it per authority would cost ``N_AA`` pairings for the
    same result, and would make setup cost scale on the wrong term.

    ``faithful`` is True only when a real Type-III backend produced these
    values. It gates reportability rather than correctness.
    """

    curve: str
    backend: str
    g1: bytes
    g2: bytes
    e_g1_g2: bytes
    faithful: bool

    def __post_init__(self) -> None:
        for name in ("g1", "g2", "e_g1_g2"):
            if not getattr(self, name):
                raise ValueError(f"group element {name} must not be empty")


GroupProvider = Callable[[Mapping[str, Any]], GroupDescription]


def resolve_group(pairing_params: Mapping[str, Any]) -> GroupDescription:
    """Resolve ``G_1, G_2, G_T, e, g_1, g_2`` from the configured backend.

    Raises until a Type-III charm backend exists in ``Common/crypto/pairing.py``.
    It deliberately does not fall back to the installed SS512 backend: that is a
    Type-I symmetric curve, which contradicts the published
    ``e : G_1 x G_2 -> G_T``, changes group-element sizes and pairing cost, and
    at ~80-bit security sits far below the ML-KEM-768 and AES-256 the rest of
    the scheme uses.
    """
    curve = str(pairing_params.get("curve", "?"))
    backend = str(pairing_params.get("backend", "?"))
    if not pairing_params.get("backend_implemented", False):
        raise PairingBackendMissingError(
            f"no faithful Type-III pairing backend for the proposed scheme.\n"
            f"crypto.yaml requests backend={backend!r} curve={curve!r} with "
            f"backend_implemented: false.\n"
            f"Common/crypto/pairing.py currently provides CharmSS512Backend "
            f"(Type-I — wrong group for this scheme) and PetrelicBN254Backend "
            f"(Type-III, does not build).\n"
            f"To resolve: add a Type-III charm backend to "
            f"Common/crypto/pairing.py, verify it on the experiment host (charm "
            f"is built there; it is not available on macOS), confirm the host's "
            f"charm ships {curve} parameters — falling back to "
            f"{pairing_params.get('curve_fallback', 'MNT224')!r} only if it does "
            f"not, and recording which was used — then set "
            f"backend_implemented: true."
        )
    raise PairingBackendMissingError(
        f"crypto.yaml declares backend={backend!r} implemented, but "
        f"initializer.resolve_group has no construction for it. Wire it to the "
        f"Common/crypto/pairing.py backend before use."
    )


@dataclass(frozen=True)
class GlobalContext:
    """Output of Phase I Step 1: the primitive set P and the resolved group."""

    suite: PrimitiveSuite
    group: GroupDescription
    kem: kem_mod.MLKEM768
    config: scheme_config.Configuration

    @property
    def reportable(self) -> bool:
        """Whether a run from this context may produce reportable numbers."""
        return self.group.faithful

    def assert_reportable(self) -> None:
        """Refuse a reportable run whose group came from no real backend."""
        if not self.group.faithful:
            raise UnfaithfulGroupError(
                f"this context's group (curve={self.group.curve!r}, "
                f"backend={self.group.backend!r}) was not produced by a faithful "
                f"Type-III pairing backend, so it must not produce reportable "
                f"numbers. See crypto.yaml ma_lb_pq_vdse.pairing."
            )

    def primitive_set(self) -> Tuple[str, ...]:
        """P as published in Phase I Step 1, in the manuscript's order."""
        return (
            "H",
            self.suite.hash_algorithm,
            self.suite.aead_algorithm,
            self.suite.kdf_algorithm,
            self.suite.kem_algorithm,
        )


def _self_test_primitives(kem: kem_mod.MLKEM768) -> None:
    """Prove P works before anything is built on it.

    Phase I is untimed, so this costs nothing that gets reported, and it turns a
    broken or mis-detected backend into an error at initialization rather than a
    failure deep inside Phase III key delivery.
    """
    probe = b"MA-LB-PQ-VDSE/phase-I/self-test"

    if len(hashes.sha256(probe)) != 32:
        raise InitializationError("SHA-256 did not return a 256-bit digest")

    key = symmetric.generate_key()
    ciphertext = symmetric.encrypt(key, probe, associated_data=b"phase-I")
    if symmetric.decrypt(key, ciphertext, associated_data=b"phase-I") != probe:
        raise InitializationError("AES-256-GCM round-trip failed")

    derived = hashes.hkdf_sha256(probe, length=32, info=b"phase-I")
    if derived != hashes.hkdf_sha256(probe, length=32, info=b"phase-I"):
        raise InitializationError("HKDF-SHA256 is not deterministic")
    if len(derived) != 32:
        raise InitializationError("HKDF-SHA256 returned the wrong length")

    if not kem.self_test():
        raise InitializationError(
            f"ML-KEM-768 self-test failed on backend {kem.backend!r}: the two "
            f"parties did not derive the same shared secret"
        )


def initialize(
    config: Optional[scheme_config.Configuration] = None,
    *,
    group_provider: GroupProvider = resolve_group,
    kem_backend: Optional[str] = None,
    self_test: bool = True,
) -> GlobalContext:
    """Phase I Step 1: initialize P and select the bilinear group.

    ``group_provider`` is a seam, not a fallback: the only implementation in
    this package raises (see :func:`resolve_group`). A provider that returns a
    group with ``faithful=False`` produces a context that
    :meth:`GlobalContext.assert_reportable` rejects.
    """
    config = config or scheme_config.load()
    pairing_params = scheme_config._require(
        config.crypto, "pairing", source="crypto.yaml"
    )

    kem = kem_mod.MLKEM768(kem_backend)
    group = group_provider(pairing_params)

    # Cross-check the resolved group against the configuration, so a provider
    # cannot quietly deliver a different curve than the one whose hash lands in
    # run_meta.json.
    configured_curve = str(pairing_params.get("curve"))
    configured_fallback = str(pairing_params.get("curve_fallback", ""))
    if group.faithful and group.curve not in (configured_curve, configured_fallback):
        raise UnfaithfulGroupError(
            f"resolved curve {group.curve!r} is neither the configured "
            f"{configured_curve!r} nor its fallback {configured_fallback!r}"
        )

    suite = PrimitiveSuite(
        hash_algorithm=str(crypto_get("global", "hash", "algorithm")),
        aead_algorithm=str(crypto_get("global", "aead", "algorithm")),
        kdf_algorithm=str(crypto_get("global", "kdf", "algorithm")),
        kem_algorithm=str(crypto_get("kem", "algorithm")),
        kem_backend=kem.backend,
        # PrimitiveSuite refuses a non-Type-III pairing, so a Type-I curve
        # cannot reach a context even by way of an injected provider.
        pairing_type=str(pairing_params.get("type")),
        pairing_curve=group.curve,
        pairing_backend=group.backend,
    )

    if self_test:
        _self_test_primitives(kem)

    return GlobalContext(suite=suite, group=group, kem=kem, config=config)


def build_public_parameters(
    context: GlobalContext,
    authority_public_keys: Sequence[Tuple[str, AuthorityPublicKey]] = (),
) -> PublicParameters:
    """Assemble PP without publishing it (Phase I Step 3, first half).

    The groups and the map enter PP through the suite's curve and backend rather
    than as objects: two runs agree on PP exactly when they resolved the same
    curve, which is what the digest needs to capture.
    """
    expected = context.config.authorities.count
    if authority_public_keys and len(authority_public_keys) != expected:
        raise InitializationError(
            f"PP carries {len(authority_public_keys)} authority public keys but "
            f"global.yaml sets N_AA={expected}; every participating authority "
            f"must appear in PP (Phase I Step 3)"
        )
    return PublicParameters.build(
        suite=context.suite,
        g1=context.group.g1,
        g2=context.group.g2,
        authority_public_keys=authority_public_keys,
    )


def publish_public_parameters(
    ledger: Ledger,
    context: GlobalContext,
    authority_public_keys: Sequence[Tuple[str, AuthorityPublicKey]] = (),
) -> PublicParameters:
    """Phase I Step 3: assemble PP and anchor it on the consortium blockchain.

    Phase I Step 3 also says each authority publishes its public key and
    identifier. Both are inside PP — ``{PK_i}`` keyed by ``ID_i`` — so anchoring
    PP publishes them as one record. The per-authority record that additionally
    carries the administrative domain is ``Reg_i = (ID_i, Dom_i, PK_i)``, which
    is Phase II Step 1 and belongs to ``authority.py``.
    """
    pp = build_public_parameters(context, authority_public_keys)
    ledger.publish_public_parameters(pp)
    return pp


def measure_kem_setup_cost(repetitions: int = 30) -> dict:
    """ML-KEM-768 session-establishment cost, reported SEPARATELY.

    README §5 (Exp. 1 rule): encapsulation happens once at session
    establishment and is excluded from the per-query trapdoor curve, reported in
    the text as a one-time setup cost. Kept here, in the phase that owns session
    establishment, so it cannot drift into the Exp. 1 measurement path.

    The returned ``backend`` key must be checked before the number is quoted: a
    timing from the pure-Python ``kyber-py`` backend is not reportable.
    """
    return kem_mod.measure_setup_cost(repetitions)


__all__ = [
    "InitializationError",
    "PairingBackendMissingError",
    "UnfaithfulGroupError",
    "GroupDescription",
    "GroupProvider",
    "GlobalContext",
    "resolve_group",
    "initialize",
    "build_public_parameters",
    "publish_public_parameters",
    "measure_kem_setup_cost",
]
