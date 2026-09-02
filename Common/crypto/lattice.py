"""Lattice primitives: Z_q arithmetic, discrete Gaussians, and the GPV-style
trapdoor toolkit (TrapGen / SamplePre / SampleLeft / SampleR).

Required by Ref[52] (Zhuang et al.), which defines exactly these four
algorithms at Ref[52].txt:93-145 and publishes its parameters in Table III
(Ref[52].txt:722-735):

    n = 284,  m = 13,812,  q = 2^24,  sigma > 0

WHY THE MICCIANCIO-PEIKERT (MP12) INSTANTIATION
-----------------------------------------------
Ref[52] states the TrapGen interface but not its internals. The published m
settles it. With k = log2(q) = 24 the gadget block is n*k = 6,816, leaving
m - n*k = 13,812 - 6,816 = 6,996 for the uniform block — which is just above
the n*log(q) = 6,816 lower bound that MP12 requires. Those numbers are the
MP12 decomposition exactly; a classic Ajtai/GPV TrapGen would not produce
m = 13,812 for n = 284. So MP12 is not a substitution for the published
algorithm, it is the algorithm the published parameters describe.

MEASUREMENT CAVEAT — READ BEFORE REPORTING ANY NUMBER FROM THIS MODULE
----------------------------------------------------------------------
``SamplePre`` supports three perturbation modes (see ``PerturbationMode``).
The cryptographically exact MP12 sampler needs a covariance Cholesky over an
m x m = 13,812^2 matrix (~1.5 GB in float64, O(m^3) work) per parameter set,
which is not tractable in Python at these parameters. The default,
``SPHERICAL``, produces correct and short preimages and pays the dominant
cost (the R @ z product, ~47.7M multiply-adds), but it is a LOWER BOUND on
the exact sampler's latency.

Any Exp. 1/2/5/6 figure for Ref[52] must state which mode produced it. This
needs sign-off before reportable runs.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

import numpy as np

# Tail cut for the discrete Gaussian. Mass beyond 6s is < 2^-60, far below
# any statistical distance that matters here.
_TAIL_FACTOR = 6


class PerturbationMode(str, Enum):
    """How ``SamplePre`` perturbs, i.e. what it is honest about measuring."""

    NONE = "none"            # e = [R;I]z only. Shortest and fastest; the
                             # output distribution leaks R. Debug only.
    SPHERICAL = "spherical"  # p ~ D_{Z^m, s}. Default. Correct and short;
                             # approximates MP12's covariance correction.
    EXACT = "exact"          # Full MP12. NOT IMPLEMENTED at these parameters.


@dataclass(frozen=True)
class LatticeParams:
    """Lattice parameter set. Defaults are Ref[52] Table III."""

    n: int = 284
    m: int = 13812
    log_q: int = 24
    sigma: float = 4.0

    @property
    def q(self) -> int:
        return 1 << self.log_q

    @property
    def k(self) -> int:
        """Gadget width: bits per Z_q entry."""
        return self.log_q

    @property
    def gadget_cols(self) -> int:
        """n * k — width of the gadget block."""
        return self.n * self.k

    @property
    def uniform_cols(self) -> int:
        """m - n*k — width of the uniform block."""
        return self.m - self.gadget_cols

    def validate(self) -> None:
        if self.uniform_cols <= 0:
            raise ValueError(
                f"m={self.m} is too small for n={self.n}, log_q={self.log_q}: "
                f"the gadget block alone needs {self.gadget_cols} columns"
            )
        if self.uniform_cols < self.n * self.log_q:
            raise ValueError(
                f"uniform block {self.uniform_cols} < n*log(q)="
                f"{self.n * self.log_q}; A would not be statistically uniform"
            )
        # Guard the int64 accumulator in A @ e (see module tests).
        worst = self.m * (self.q - 1) ** 2
        if worst >= 2**63:
            raise ValueError(
                f"parameters risk int64 overflow in matmul (worst case {worst})"
            )

    @classmethod
    def from_config(cls, scheme: str) -> "LatticeParams":
        """Build from ``Experiment Configuration/crypto.yaml``.

        ``scheme`` has no default on purpose. It used to default to
        ``"zhuang_lattice_mabse"``, but that scheme was dropped 2026-08-27
        and its crypto.yaml block no longer has a
        ``lattice`` sub-block — a silent default here would have read from
        wherever the dropped scheme's config used to point, or raised a
        confusing error far from the actual cause. No caller currently
        invokes this method (checked at the time of the fix); when
        `perera_lv_pqabse` is implemented, pass its scheme name explicitly.
        """
        from .config import get

        block = get(scheme, "lattice")
        return cls(
            n=int(block["n"]),
            m=int(block["m"]),
            log_q=int(block["log_q"]),
            sigma=float(block["gaussian_sigma"]),
        )


REF52_PARAMS = LatticeParams()


# ---------------------------------------------------------------------------
# Modular arithmetic
# ---------------------------------------------------------------------------
def mod_q(x: np.ndarray, q: int) -> np.ndarray:
    """Reduce into ``[0, q)``. numpy's ``%`` is already non-negative."""
    return np.mod(x, q)


def centered(x: np.ndarray, q: int) -> np.ndarray:
    """Reduce into ``(-q/2, q/2]`` — the representation norms are taken in."""
    r = np.mod(x, q)
    return np.where(r > q // 2, r - q, r)


def norm(x: np.ndarray, q: Optional[int] = None) -> float:
    """Euclidean norm, in centered representation when ``q`` is given."""
    v = centered(x, q) if q is not None else x
    return float(np.linalg.norm(v.astype(np.float64)))


# ---------------------------------------------------------------------------
# Discrete Gaussian
# ---------------------------------------------------------------------------
def sample_discrete_gaussian(
    size: int | Tuple[int, ...],
    s: float,
    *,
    center: float = 0.0,
    rng: Optional[np.random.Generator] = None,
) -> np.ndarray:
    """Sample from D_{Z, s} with density proportional to exp(-pi(x-c)^2/s^2).

    Uses the ``rho_s(x) = exp(-pi x^2 / s^2)`` convention standard in the
    TrapGen/SamplePre literature, NOT the statistics convention
    ``exp(-x^2/2sigma^2)``. The two differ by ``s = sigma * sqrt(2*pi)``;
    mixing them silently changes every norm bound in the scheme.

    Vectorised rejection sampling: draw uniformly from the tail-cut interval
    and accept with probability rho_s. Batched so the loop runs a couple of
    times rather than once per sample.
    """
    if s <= 0:
        raise ValueError(f"s must be positive, got {s}")
    rng = rng or np.random.default_rng()
    shape = (size,) if isinstance(size, int) else size
    total = int(np.prod(shape))
    if total == 0:
        return np.zeros(shape, dtype=np.int64)

    bound = int(math.ceil(_TAIL_FACTOR * s))
    lo, hi = int(math.floor(center)) - bound, int(math.ceil(center)) + bound

    out = np.empty(total, dtype=np.int64)
    filled = 0
    while filled < total:
        # Over-draw: acceptance rate is ~ s/(2*bound) ~ 1/12, so ask for more.
        draw = max(1024, int((total - filled) * 14))
        cand = rng.integers(lo, hi + 1, size=draw)
        prob = np.exp(-math.pi * np.square(cand - center) / (s * s))
        accepted = cand[rng.random(draw) < prob]
        take = min(len(accepted), total - filled)
        out[filled : filled + take] = accepted[:take]
        filled += take
    return out.reshape(shape)


def sample_uniform_zq(
    shape: Tuple[int, ...], q: int, *, rng: Optional[np.random.Generator] = None
) -> np.ndarray:
    rng = rng or np.random.default_rng()
    return rng.integers(0, q, size=shape, dtype=np.int64)


# ---------------------------------------------------------------------------
# Gadget matrix
# ---------------------------------------------------------------------------
def gadget_vector(k: int) -> np.ndarray:
    """g = (1, 2, 4, ..., 2^(k-1))."""
    return (1 << np.arange(k, dtype=np.int64)).astype(np.int64)


def gadget_matrix(n: int, k: int) -> np.ndarray:
    """G = I_n (x) g^T, of shape ``(n, n*k)``.

    Built with a Kronecker product rather than a Python loop — at n=284,
    k=24 this is a 284 x 6816 matrix and the loop version is measurably slow
    inside a setup path that runs per repetition.
    """
    return np.kron(np.eye(n, dtype=np.int64), gadget_vector(k).reshape(1, k))


def gadget_decompose(v: np.ndarray, k: int) -> np.ndarray:
    """Binary-decompose ``v in Z_q^n`` into ``z in {0,1}^(n*k)`` with ``Gz = v``.

    This is why the gadget exists: inverting G is a bit-shift instead of a
    lattice problem.
    """
    v = np.asarray(v, dtype=np.int64).reshape(-1)
    bits = ((v[:, None] >> np.arange(k, dtype=np.int64)[None, :]) & 1)
    return bits.reshape(-1).astype(np.int64)


# ---------------------------------------------------------------------------
# Trapdoor generation
# ---------------------------------------------------------------------------
@dataclass
class Trapdoor:
    """An MP12 trapdoor: the short ``R`` with ``A @ [R; I] = G (mod q)``."""

    R: np.ndarray            # (uniform_cols, gadget_cols), small entries
    params: LatticeParams

    @property
    def size_bytes(self) -> int:
        """Serialised trapdoor size — an Exp. 1 secondary metric."""
        return int(self.R.size * self.R.dtype.itemsize)


def trapgen(
    params: LatticeParams = REF52_PARAMS,
    *,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[np.ndarray, Trapdoor]:
    """``TrapGen(n, m, q, sigma)`` — Ref[52].txt:104-117.

    Returns ``(A, T_A)`` with ``A`` statistically close to uniform over
    ``Z_q^(n x m)`` and ``T_A`` a short trapdoor for ``Lambda_q^perp(A)``.

    Construction: ``A = [A_bar | G - A_bar @ R]``, so that
    ``A @ [R; I] = A_bar@R + G - A_bar@R = G``.
    """
    params.validate()
    rng = rng or np.random.default_rng()
    q, k = params.q, params.k

    a_bar = sample_uniform_zq((params.n, params.uniform_cols), q, rng=rng)
    R = sample_discrete_gaussian(
        (params.uniform_cols, params.gadget_cols), params.sigma, rng=rng
    )
    G = gadget_matrix(params.n, k)
    a_right = mod_q(G - a_bar @ R, q)
    A = np.concatenate([a_bar, a_right], axis=1)
    return A, Trapdoor(R=R, params=params)


def sample_r(
    rows: int, cols: int, *, rng: Optional[np.random.Generator] = None
) -> np.ndarray:
    """``SampleR`` — Ref[52].txt:140-145.

    A uniform matrix in ``{-1, +1}^(rows x cols)``, the standard low-norm
    re-randomiser used to build the right-hand block in ABE constructions.
    """
    rng = rng or np.random.default_rng()
    return (rng.integers(0, 2, size=(rows, cols), dtype=np.int64) * 2 - 1)


# ---------------------------------------------------------------------------
# Preimage sampling
# ---------------------------------------------------------------------------
def sample_pre(
    A: np.ndarray,
    trapdoor: Trapdoor,
    u: np.ndarray,
    *,
    s: Optional[float] = None,
    mode: PerturbationMode = PerturbationMode.SPHERICAL,
    rng: Optional[np.random.Generator] = None,
) -> np.ndarray:
    """``SamplePre(A, T_A, u, sigma)`` — Ref[52].txt:118-126.

    Returns a short ``e`` with ``A @ e = u (mod q)``.

    Steps: perturb, reduce the target through the gadget, lift with the
    trapdoor::

        p  <- perturbation             (mode-dependent)
        v  = u - A @ p     (mod q)
        z  = G^{-1}(v)                 bit decomposition, exact
        e  = p + [R; I] @ z

    Correctness: ``A@e = A@p + A@[R;I]@z = A@p + G@z = A@p + v = u``.
    """
    params = trapdoor.params
    q = params.q
    s = s if s is not None else params.sigma
    rng = rng or np.random.default_rng()

    u = np.asarray(u, dtype=np.int64).reshape(-1)
    if u.shape[0] != params.n:
        raise ValueError(f"u must have length n={params.n}, got {u.shape[0]}")
    if A.shape != (params.n, params.m):
        raise ValueError(f"A must be {(params.n, params.m)}, got {A.shape}")

    if mode is PerturbationMode.EXACT:
        raise NotImplementedError(
            "Exact MP12 perturbation needs a Cholesky factor of an "
            f"{params.m}x{params.m} covariance matrix (~"
            f"{params.m ** 2 * 8 / 1e9:.1f} GB, O(m^3) work) and is not "
            "tractable in Python at Ref[52]'s published parameters. Use "
            "SPHERICAL and state the mode alongside any reported number."
        )

    if mode is PerturbationMode.NONE:
        p = np.zeros(params.m, dtype=np.int64)
    else:
        p = sample_discrete_gaussian(params.m, s, rng=rng)

    v = mod_q(u - A @ p, q)
    z = gadget_decompose(v, params.k)

    # e = p + [R; I] @ z, blockwise so the identity block is never materialised.
    e = p.copy()
    e[: params.uniform_cols] += trapdoor.R @ z
    e[params.uniform_cols :] += z
    return e


def sample_left(
    A: np.ndarray,
    B: np.ndarray,
    trapdoor: Trapdoor,
    u: np.ndarray,
    *,
    s: Optional[float] = None,
    mode: PerturbationMode = PerturbationMode.SPHERICAL,
    rng: Optional[np.random.Generator] = None,
) -> np.ndarray:
    """``SampleLeft(A, B, T_A, u, sigma)`` — Ref[52].txt:127-139.

    Returns a short ``e`` with ``[A | B] @ e = u (mod q)``, using only a
    trapdoor for ``A``. This is the algorithm that lets an attribute-based
    scheme delegate: ``B`` carries the attribute/identity block and needs no
    trapdoor of its own.

    Method: sample the ``B``-half ``e_2`` freely, then solve the residual
    ``u - B @ e_2`` through ``A``'s trapdoor.
    """
    params = trapdoor.params
    q = params.q
    s = s if s is not None else params.sigma
    rng = rng or np.random.default_rng()

    u = np.asarray(u, dtype=np.int64).reshape(-1)
    if A.shape[0] != B.shape[0]:
        raise ValueError(
            f"A and B must have the same row count, got {A.shape[0]} and {B.shape[0]}"
        )
    if u.shape[0] != A.shape[0]:
        raise ValueError(f"u must have length {A.shape[0]}, got {u.shape[0]}")

    e2 = sample_discrete_gaussian(B.shape[1], s, rng=rng)
    residual = mod_q(u - B @ e2, q)
    e1 = sample_pre(A, trapdoor, residual, s=s, mode=mode, rng=rng)
    return np.concatenate([e1, e2])


# ---------------------------------------------------------------------------
# Verification helper
# ---------------------------------------------------------------------------
def verify_preimage(
    A: np.ndarray, e: np.ndarray, u: np.ndarray, q: int, *, bound: Optional[float] = None
) -> bool:
    """Check ``A @ e = u (mod q)`` and, optionally, that ``e`` is short.

    Correctness self-check for the toolkit. A SamplePre that returns a vector
    satisfying the equation but not the norm bound is broken in a way that
    still "works", so the bound is checked too.
    """
    if not np.array_equal(mod_q(A @ e, q), mod_q(u, q)):
        return False
    return bound is None or norm(e, q) <= bound
