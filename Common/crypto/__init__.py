"""Cryptographic primitives shared by every scheme in the benchmark.

One implementation of each primitive, used by all five schemes, so that a
latency difference between two schemes is attributable to their constructions
and not to two different AES wrappers (README §1, environment parity).

    from Common.crypto import hashes, symmetric, merkle
    ct = symmetric.encrypt(key, b"record")
    root = merkle.commitment([b"a", b"b", b"c"])

WHAT BELONGS HERE
-----------------
Primitives a paper CITES: SHA-256, HMAC, AES-GCM, Merkle trees, Bloom
filters, discrete Gaussians, pairings, ML-KEM.

WHAT DOES NOT
-------------
Anything a paper CONTRIBUTES: Guo's forward index, Zhuang's attribute key
derivation, Thingom's LSSS policy encoding, our PDSI/AASS/IAS. Those live in
``Schemes/<name>/src/`` and stay independent per README §14.

WHICH SCHEME USES WHAT
----------------------
    hashes, rng, symmetric   all five schemes
    prf                      Ref[35] (PRF + t-Pun-PRF), ours
    merkle                   ours (Phases IV/VII/VIII), Ref[35] verification
    bloom                    Ref[52] BF(32,3), ours
    lattice                  Ref[52]
    pairing                  Ref[41] (Type-I), ours (MA-CP-ABE)
    kem                      ours only (ML-KEM-768)
"""

from . import (  # noqa: F401
    bloom,
    config,
    hashes,
    kem,
    lattice,
    merkle,
    pairing,
    prf,
    rng,
    symmetric,
)

__all__ = [
    "bloom",
    "config",
    "hashes",
    "kem",
    "lattice",
    "merkle",
    "pairing",
    "prf",
    "rng",
    "symmetric",
    "environment_report",
]


def environment_report() -> dict:
    """Snapshot of the crypto environment, for ``run_meta.json`` (README §7).

    Records library versions, the live pairing and ML-KEM backends, and the
    config-file hashes. A reviewer tracing a number back gets the exact
    primitive environment that produced it — including, critically, whether a
    development-only backend was active.
    """
    import platform
    import sys

    def _version(module_name: str) -> str:
        try:
            import importlib

            module = importlib.import_module(module_name)
            return str(getattr(module, "__version__", "unknown"))
        except Exception:
            return "not installed"

    return {
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "libraries": {
            name: _version(name)
            for name in ("cryptography", "numpy", "scipy", "mmh3", "yaml")
        },
        "pairing_backends_available": pairing.available_backends(),
        "kem_backends_available": kem.available_backends(),
        "config_hashes": config.config_hashes(),
    }
