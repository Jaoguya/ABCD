"""Phase III — User Registration and Version-Bound Authorization Profile.

Both roles enrol here: the manuscript registers "each Data Owner (DO) and Data
User (DU)" through one path, differing in the attributes granted rather than in
the mechanism. The Data Owner's ``AuthRoot_DO``, which Phase IV Step 5 binds into
``Commit_i``, is produced by this phase.

* ``registration.py`` — Step 1, ``Req_U = (UID, Dom, Role, Cred)`` and each
  authority's independent local validation.
* ``delivery.py`` — Step 3, ML-KEM-768 + HKDF + AES-256-GCM hybrid key delivery.
* ``profile.py`` — Step 4, ``AuthRoot_U`` and ``VAP_U``.

Step 2 (``KeyGen(MSK_i, S_{U,i})``) is absent: the manuscript gives it as an
interface without defining ``SK_{U,i}``'s structure, and it additionally needs the
Type-III pairing backend. See ``../PHASE_III_PLAN.md``.
"""
