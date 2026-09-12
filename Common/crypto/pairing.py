"""Bilinear pairing backends.

Ref[41] publishes a TYPE-I (symmetric) pairing — Ref[41].txt:510-513:

    "two multiplicative cyclic groups I1 and I2 of prime order w, with i and h
     as generators of I1. A bilinear map is defined as e : I1 x I1 -> I2"

Both arguments come from the same group, and security rests on DBDH
(Ref[41].txt:280-300). Per skill.md the baseline is implemented AS
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
    def order(self) -> int:
        """Group order ``w`` as a Python int.

        LSSS share generation and reconstruction (Ref[41] §II-A) are linear
        algebra over the field ``F_w``. Doing that arithmetic on plain ints
        mod ``order()`` keeps it identical across backends; only the final
        exponentiation touches backend element types.
        """

    @abstractmethod
    def zr_from_int(self, value: int) -> Any:
        """Coerce an int in ``[0, order)`` to a backend exponent element."""

    @abstractmethod
    def serialize(self, element: Any) -> bytes:
        """Canonical byte encoding of a group element."""

    def element_size_bytes(self, element: Any) -> int:
        """Serialised size — trapdoor/ciphertext size metrics depend on this."""
        return len(self.serialize(element))

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

    def order(self) -> int:
        return int(self._group.order())

    def zr_from_int(self, value: int):
        from charm.toolbox.pairinggroup import ZR

        return self._group.init(ZR, value % self.order())

    def serialize(self, element) -> bytes:
        return self._group.serialize(element)


class CharmType3Backend(PairingBackend):
    """Type-III asymmetric pairing on a charm curve (BN254 by default).

    The faithful backend for ``ma_lb_pq_vdse``, whose published map is
    ``e : G_1 x G_2 -> G_T`` with ``G_1 != G_2`` (crypto.yaml
    ``ma_lb_pq_vdse.pairing.type: type-3``). Until this existed the proposed
    scheme ran on an injected hash-based stand-in and every run was stamped
    ``backend_implemented: false`` -> not reportable, so the paper's own
    contribution could not produce a quotable number at all.

    Uses charm rather than adding a dependency: charm is already built and
    verified on the experiment host for Ref[41]'s Type-I curve, and it ships
    Type-III curves in the same install. ``petrelic`` was the earlier intended
    route and does not build.

    G1 and G2 are genuinely distinct groups — verified on the host at BN254:
    a G1 element serialises to 46 B and a G2 element to 90 B, and bilinearity
    ``e(g1^a, g2^c) == e(g1, g2)^(ac)`` holds. That distinction is the point:
    it is what makes measured element sizes and pairing costs correspond to
    the published construction rather than to a symmetric stand-in.

    Note charm does NOT reject ``pair(g2, g1)`` on this curve — it accepts the
    reversed argument order rather than raising. That is library permissiveness,
    not evidence the groups are the same (the differing sizes above settle
    that), but it means calling code cannot rely on the library to catch an
    argument-order mistake; the construction must get the order right itself.
    """

    name = "charm_type3"
    pairing_type = "type-3"

    def __init__(self, curve: str = "BN254") -> None:
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
        from charm.toolbox.pairinggroup import G2

        # NOT G1: asymmetric pairing, so G2 is a different group. Returning a
        # G1 element here (as the Type-I backend legitimately does) would
        # silently make the scheme symmetric.
        return self._group.random(G2)

    def random_zr(self):
        from charm.toolbox.pairinggroup import ZR

        return self._group.random(ZR)

    def pair(self, a, b):
        from charm.toolbox.pairinggroup import pair

        return pair(a, b)

    def hash_to_g1(self, data: bytes):
        from charm.toolbox.pairinggroup import G1

        return self._group.hash(data, G1)

    def hash_to_g2(self, data: bytes):
        from charm.toolbox.pairinggroup import G2

        return self._group.hash(data, G2)

    def hash_to_zr(self, data: bytes):
        from charm.toolbox.pairinggroup import ZR

        return self._group.hash(data, ZR)

    def order(self) -> int:
        return int(self._group.order())

    def zr_from_int(self, value: int):
        from charm.toolbox.pairinggroup import ZR

        return self._group.init(ZR, value % self.order())

    def serialize(self, element) -> bytes:
        return self._group.serialize(element)


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
        return self.zr_from_int(digest)

    def order(self) -> int:
        return int(self._G1.order())

    def zr_from_int(self, value: int):
        from petrelic.bn import Bn

        return Bn.from_decimal(str(value % self.order()))

    def serialize(self, element) -> bytes:
        to_binary = getattr(element, "to_binary", None)
        if to_binary is not None:
            return to_binary()
        # Bn (exponent) elements expose binary() rather than to_binary().
        return element.binary()


_BACKENDS = {
    CharmSS512Backend.name: CharmSS512Backend,
    CharmType3Backend.name: CharmType3Backend,
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
    if name == CharmType3Backend.name:
        # curve_fallback is deliberately NOT applied automatically: crypto.yaml
        # requires it be confirmed on the host and recorded before a reportable
        # run, "not selected silently".
        return CharmType3Backend(cfg.get("curve", "BN254"))
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
