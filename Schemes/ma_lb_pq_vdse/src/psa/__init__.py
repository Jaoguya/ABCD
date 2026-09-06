"""The manuscript's policy-state-aware construction — divergences D1-D5.

``MANUSCRIPT_DIVERGENCE.md`` records nine places where the implemented scheme
and `Overleaf/MA-LB-PQ-VDSE.tex` disagree. D1-D5 are the cryptographic ones, and
this package implements the manuscript's side of all five so that both
constructions can be **measured against each other** rather than argued about:

======  ==========================================================  ============
D       The manuscript's form, implemented here                     Module
======  ==========================================================  ============
D1      ``T = H(w ‖ PID ‖ PV ‖ Dom)`` (eq:policy-bound-token,       ``tokens``
        eq:query-token), index and query token identical
D2      ``V_P = {(ID_k, v_k) : AA_k ∈ AA(PID)}``                    ``state``
        (eq:policy-version-state) and ``PV = H(Encode(V_P))``
        (eq:policy-version-digest), replacing the scalar ``VID``
D3      ``AuthState = H(Encode({(ID_k, C_k^auth)}))``               ``state``,
        (eq:policy-auth-state) and ``Commit = H(CID ‖ Root ‖        ``commit``
        PID ‖ PV ‖ AuthState)`` (eq:record-commitment)
D4      ``I = (T, CID, PID, PV)`` (eq:index-entry)                  ``records``
D5      ``VAP = (UID, D_U, V_U, C_U, AuthRoot_U)``                  ``records``
======  ==========================================================  ============

**Nothing here replaces the existing scheme.** ``src/index/tokens.py`` and the
Option D construction it implements are untouched and remain the default, so
every banked ``results.csv`` stays reproducible. This package is reached only
through the ``psa`` construction variant (``--construction psa``), which writes
to its own ``exp*__psa/`` directories.

WHY BOTH EXIST
--------------
Option D was chosen on 2026-08-10 because the *previous* manuscript wrote the
index token with ``PID‖VID‖Dom`` and the query token with ``VID_U`` alone, which
cannot both hold; it resolved the contradiction by reducing both to ``H(w)``.
The current manuscript resolves the same contradiction the other way and proves
the two tokens equal as a theorem. Neither is obviously wrong. What was missing
was a measurement of what the manuscript's choice costs, and that is what this
package exists to supply — see ``MANUSCRIPT_DIVERGENCE.md`` D1.

WHAT IT COSTS, AS A PREDICTION TO BE TESTED
-------------------------------------------
Binding the token to the policy state means an authority version bump
re-tokenizes every entry governed by that authority, where under Option D it
touches no token at all. ``PHASE_IV_PLAN.md`` §1.3 put that at ~9.0M entries per
bump. Exp. 5 and Exp. 6 under ``--construction psa`` are what turn that estimate
into a number.
"""

from . import commit, governance, records, state, tokens, verify  # noqa: F401

__all__ = ["commit", "governance", "records", "state", "tokens", "verify"]
