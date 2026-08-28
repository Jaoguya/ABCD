"""Ref[54] parameters, loaded from ``Experiment Configuration/crypto.yaml``.

Nothing here is hardcoded. Every value the paper publishes is read from the
config, and every value it does NOT publish is a recorded benchmark decision in
the same place — see the ``perera_lv_pqabse`` block, which carries the reason
and the date for each one.
"""

from __future__ import annotations

from dataclasses import dataclass

from Common.crypto.config import get as cfg_get
from Common.crypto.lattice import LatticeParams


@dataclass(frozen=True)
class SchemeParams:
    """All Ref[54] parameters."""

    # --- published ---
    security_parameter_lambda: int   # 192, NIST Category 3
    kem: str                         # kyber768 -> ML-KEM-768
    signature: str                   # dilithium3 -> ML-DSA-65
    hash_name: str                   # sha3-256
    symmetric: str                   # aes-256-gcm

    # --- benchmark decisions (crypto.yaml records why) ---
    attribute_universe: int
    ngram_size: int
    fuzzy_threshold: float
    cross_domain_mode: str
    abe_on_measured_path: bool

    lattice: LatticeParams

    @classmethod
    def from_config(cls) -> "SchemeParams":
        block = cfg_get("perera_lv_pqabse")
        lat = block["lattice"]
        fuzzy = block["fuzzy"]
        return cls(
            security_parameter_lambda=int(block["security_parameter_lambda"]),
            kem=str(block["kem"]),
            signature=str(block["signature"]),
            hash_name=str(block["hash"]),
            symmetric=str(block["symmetric"]),
            attribute_universe=int(block["attributes"]["universe_size"]),
            ngram_size=int(fuzzy["ngram_size"]),
            fuzzy_threshold=float(fuzzy["match_threshold"]),
            cross_domain_mode=str(block["cross_domain"]["mode"]),
            abe_on_measured_path=bool(block["abe_on_measured_path"]),
            lattice=LatticeParams(
                n=int(lat["n"]),
                m=int(lat["m"]),
                log_q=int(lat["log_q"]),
                sigma=float(lat["gaussian_sigma"]),
            ),
        )

    def __post_init__(self) -> None:
        # Fail here rather than deep inside a matmul: the int64 overflow guard
        # is the one that silently corrupts results instead of raising.
        self.lattice.validate()
        if self.security_parameter_lambda != 192:
            raise ValueError(
                f"Ref[54] publishes lambda = 192 (NIST Category 3), got "
                f"{self.security_parameter_lambda}"
            )
