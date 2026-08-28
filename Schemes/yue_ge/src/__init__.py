"""Ref[55] — Ge et al., Peony / Peony++ (IEEE IoT-J, vol. 11, no. 24, 2024).

Verifiable multilevel dynamic searchable encryption with forward and Type-II
backward privacy. See ``References/Ref[55]/Ref[55].md`` for the construction
summary, published parameters, and the legitimacy assessment; see
``../SCHEME.md`` for the experiment mapping.

Module layout follows the paper's own sectioning:

    params.py      parameters from crypto.yaml; the derived Bloom size b
    levels.py      §V-A   multilevel access policy a(id) <= a(u)
    digest.py      §VI-A  keccak256 + the XOR multiset accumulator
    msre.py        §IV    multilevel symmetric revocable encryption
    index.py       §V-D   server-side (A_c, T_c) per update batch
    peony.py       §V     forward-private MLDSSE
    peony_plus.py  §VI    + Type-II backward privacy + public verification
"""

from .params import SchemeParams  # noqa: F401

__all__ = ["SchemeParams"]
