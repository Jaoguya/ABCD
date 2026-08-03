"""Bilinear pairing backends.

Ref[41] publishes a TYPE-I (symmetric) pairing — Ref[41].txt:510-513:

    "two multiplicative cyclic groups I1 and I2 of prime order w, with i and h
     as generators of I1. A bilinear map is defined as e : I1 x I1 -> I2"

Both arguments come from the same group, and security rests on DBDH
(Ref[41].txt:280-300). Per README §14 the baseline is implemented AS
PUBLISHED: symmetric pairing, DBDH. Do not "upgrade" it.

A NOTE ON REF[41]'s POST-QUANTUM CLAIM
--------------------------------------
Ref[41].txt:299 states DBDH "forms the foundation of the post-quantum security
claims in this work", while Ref[41].txt:919-927 of the same paper states that
pairings are not post-quantum. That contradiction is the published paper's.
It is reproduced here rather than corrected, and should be reported as an
observation about the baseline — not silently fixed.

BACKENDS
--------
``charm_ss512``   Type-I, symmetric, faithful to Ref[41]. Linux only.
``petrelic_bn254`` Type-III, asymmetric. DEVELOPMENT ONLY — different group
                  sizes and pairing cost, so it must never produce reportable
                  Ref[41] numbers. Guarded by
                  ``allow_dev_fallback_in_reportable_runs`` in crypto.yaml.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class PairingUnavailableError(RuntimeError):
    """Raised when no usable pairing backend is installed."""


class UnfaithfulBackendError(RuntimeError):
    """Raised when a reportable run would use a non-published pairing type."""


class PairingBackend(ABC):
    """Minimal interface the ABE constructions need."""

    name: str
    pairing_type: str  # "type-1" or "type-3"

    @abstractmethod
    def random_g1(self) -> Any: ...

    @abstractmethod
    def random_g2(self) -> Any: ...

    @abstractmethod
    def random_zr(self) -> Any: ...

    @abstractmethod
    def pair(self, a: Any, b: Any) -> Any: ...

    @abstractmethod
    def hash_to_g1(self, data: bytes) -> Any: ...

    @abstractmethod
    def hash_to_zr(self, data: bytes) -> Any: ...

    @abstractmethod
    def element_size_bytes(self, element: Any) -> int:
        """Serialised size — trapdoor/ciphertext size metrics depend on this."""

    @property
    def is_symmetric(self) -> bool:
        return self.pairing_type == "type-1"


class CharmSS512Backend(PairingBackend):
    """Type-I symmetric pairing on the SS512 supersingular curve (charm-crypto).

    This is the faithful backend for Ref[41]: G1 and G2 are the same group,
    so ``e(g, h)`` accepts two G1 elements exactly as the paper writes it.
    """

    name = "charm_ss512"
    pairing_type = "type-1"

    def __init__(self, curve: str = "SS512") -> None:
        try:
            from charm.toolbox.pairinggroup import PairingGroup
        except ImportError as exc:  # pragma: no cover - platform dependent
            raise PairingUnavailableError(
                "charm-crypto is not installed. It is Linux-only; on Windows "
                "use WSL2 or run on the Ubuntu experiment host. "
                "Install: pip install charm-crypto"
            ) from exc
        self._group = PairingGroup(curve)
        self.curve = curve

    @property
    def group(self):
        """The underlying charm PairingGroup, for scheme-specific operations."""
        return self._group

    def random_g1(self):
        from charm.toolbox.pairinggroup import G1

        return self._group.random(G1)

    def random_g2(self):
        # Symmetric pairing: G2 IS G1. Returning a G1 element is correct here,
        # not a shortcut.
        return self.random_g1()

    def random_zr(self):
        from charm.toolbox.pairinggroup import ZR

        return self._group.random(ZR)

    def pair(self, a, b):
        from charm.toolbox.pairinggroup import pair

        return pair(a, b)

    def hash_to_g1(self, data: bytes):
        from charm.toolbox.pairinggroup import G1

        return self._group.hash(data, G1)

    def hash_to_zr(self, data: bytes):
        from charm.toolbox.pairinggroup import ZR

        return self._group.hash(data, ZR)

    def element_size_bytes(self, element) -> int:
        return len(self._group.serialize(element))


class PetrelicBN254Backend(PairingBackend):
    """Type-III asymmetric pairing on BN254 (petrelic). DEVELOPMENT ONLY.

    BN254 has different group-element sizes and a different pairing cost from
    SS512, so Ref[41] numbers produced here do not reflect its paper.
    """

    name = "petrelic_bn254"
    pairing_type = "type-3"

    def __init__(self) -> None:
        try:
            from petrelic.multiplicative.pairing import G1, G2, GT  # noqa: F401
        except ImportError as exc:  # pragma: no cover - platform dependent
            raise PairingUnavailableError(
                "petrelic is not installed. Install: pip install petrelic"
            ) from exc
        from petrelic.multiplicative.pairing import G1, G2, GT

        self._G1, self._G2, self._GT = G1, G2, GT

    def random_g1(self):
        return self._G1.generator() ** self._G1.order().random()

    def random_g2(self):
        return self._G2.generator() ** self._G2.order().random()

    def random_zr(self):
        return self._G1.order().random()

    def pair(self, a, b):
        return a.pair(b)

    def hash_to_g1(self, data: bytes):
        return self._G1.hash_to_point(data)

    def hash_to_zr(self, data: bytes):
        from .hashes import sha256

        digest = int.from_bytes(sha256(data, domain=b"pairing/zr"), "big")
        return digest % int(self._G1.order())

    def element_size_bytes(self, element) -> int:
        return len(element.to_binary())


_BACKENDS = {
    CharmSS512Backend.name: CharmSS512Backend,
    PetrelicBN254Backend.name: PetrelicBN254Backend,
}


def get_backend(
    scheme: str = "thingom_pq_abse",
    *,
    reportable: bool = True,
    override: Optional[str] = None,
) -> PairingBackend:
    """Build the configured pairing backend for ``scheme``.

    ``reportable=True`` (the default) refuses to fall back to a pairing type
    the scheme's paper did not publish. Development runs pass
    ``reportable=False`` to opt into the fallback knowingly.
    """
    from .config import get

    cfg = get(scheme, "pairing")
    requested = override or cfg["backend"]
    allow_fallback = bool(cfg.get("allow_dev_fallback_in_reportable_runs", False))
    published_type = cfg["type"]

    try:
        backend = _build(requested, cfg)
    except PairingUnavailableError:
        fallback = cfg.get("dev_fallback_backend")
        if not fallback:
            raise
        if reportable and not allow_fallback:
            raise UnfaithfulBackendError(
                f"pairing backend {requested!r} is unavailable and the "
                f"fallback {fallback!r} is a different pairing type than the "
                f"one Ref[41] publishes ({published_type}). Refusing to "
                f"produce reportable numbers with it. Run on the Linux "
                f"experiment host, or pass reportable=False for development."
            )
        backend = _build(fallback, cfg)

    if reportable and backend.pairing_type != published_type:
        raise UnfaithfulBackendError(
            f"backend {backend.name!r} is {backend.pairing_type}, but "
            f"{scheme} publishes {published_type}"
        )
    return backend


def _build(name: str, cfg: dict) -> PairingBackend:
    if name not in _BACKENDS:
        raise ValueError(f"unknown pairing backend {name!r}; have {sorted(_BACKENDS)}")
    if name == CharmSS512Backend.name:
        return CharmSS512Backend(cfg.get("curve", "SS512"))
    return _BACKENDS[name]()


def available_backends() -> dict[str, bool]:
    """Which backends import on this machine — recorded in ``run_meta.json``."""
    status: dict[str, bool] = {}
    for name, cls in _BACKENDS.items():
        try:
            cls()  # type: ignore[call-arg]
            status[name] = True
        except Exception:
            status[name] = False
    return status
