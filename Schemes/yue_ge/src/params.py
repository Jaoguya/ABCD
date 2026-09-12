"""Scheme parameters for Scheme 30 (Ge et al., Peony / Peony++).

Every value here is loaded from ``Experiment Configuration/crypto.yaml`` under
the ``yue_ge`` block. Nothing is hardcoded: skill.md requires that every
reported number carry a config hash, which only works if the config is the
single source of truth.

Published vs. benchmark provenance for each field is recorded in crypto.yaml
itself and, at more length, in ``References/Ref[55]/Ref[55].md`` §4 and §5.

The one derived quantity
------------------------
The Bloom filter array size ``b`` is NOT a stored constant. The paper gives it
as a formula (§VII-B):

    b = -d * ln(p) / (ln 2)^2

where ``d`` is the number of deletions between two searches and ``p`` the
false-positive rate. So ``b`` grows with deletion volume and is computed per
(keyword, level) filter rather than fixed at setup. ``bloom_array_bits()``
below is that formula and nothing else — the reproduction check in
``test_scheme.py`` verifies it against the paper's own Table V storage figures.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from Common.crypto.config import get as cfg_get


@dataclass(frozen=True)
class SchemeParams:
    """All Scheme 30 parameters, loaded from crypto.yaml."""

    # --- published ---
    access_levels: int              # |L| = 3, level 3 highest
    bloom_fp_rate: float            # p = 1e-4
    bloom_num_hashes: int           # h = 5 (published; 13 is the alternate)
    bloom_num_hashes_alt: int       # h = 13
    deletions_between_searches: int # d = 1000 (paper's own Table VII point)
    file_identifier_bytes: int      # <= 32 B
    digest_hash: str                # keccak256, for on-chain prooflist entries

    # --- benchmark decisions (paper does not fix these) ---
    security_parameter_lambda: int  # 128, matched to guo_vdsse
    update_batches_c: int           # c = 4, matched to the repo's default d=4
    punc_output_bits: int           # GGM leaf width (depth is DERIVED from b)
    level_assignment: str           # "pid_hash"

    @classmethod
    def from_config(cls) -> "SchemeParams":
        """Load from ``Experiment Configuration/crypto.yaml``."""
        block = cfg_get("yue_ge")
        bf = block["bloom_filter"]
        pp = block["puncturable_prf"]
        return cls(
            access_levels=int(block["access_levels"]),
            bloom_fp_rate=float(bf["false_positive_rate"]),
            bloom_num_hashes=int(bf["num_hashes"]),
            bloom_num_hashes_alt=int(bf["num_hashes_alt"]),
            deletions_between_searches=int(block["deletions_between_searches"]),
            file_identifier_bytes=int(block["file_identifier_bytes"]),
            digest_hash=str(block["digest_hash"]),
            security_parameter_lambda=int(block["security_parameter_lambda"]),
            update_batches_c=int(block["update_batches_c"]),
            punc_output_bits=int(pp["output_bits"]),
            level_assignment=str(block["level_assignment"]),
        )

    # ------------------------------------------------------------------
    # Derived quantities
    # ------------------------------------------------------------------
    @property
    def lambda_bytes(self) -> int:
        """Key length in bytes for the level keys k_l."""
        return self.security_parameter_lambda // 8

    @property
    def punc_output_bytes(self) -> int:
        return self.punc_output_bits // 8

    def bloom_array_bits(self, deletions: int | None = None) -> int:
        """``b = -d * ln(p) / (ln 2)^2`` — Scheme 30 §VII-B, verbatim.

        Args:
            deletions: ``d``, the number of deletions between two searches.
                Defaults to the configured ``deletions_between_searches``.

        Returns:
            The array size ``b`` in bits, rounded up. A floor of 1 keeps the
            filter well-formed when ``d = 0`` (a keyword with no deletions),
            which the formula alone would send to zero.
        """
        d = self.deletions_between_searches if deletions is None else deletions
        if d <= 0:
            return 1
        b = -d * math.log(self.bloom_fp_rate) / (math.log(2) ** 2)
        return max(1, math.ceil(b))
