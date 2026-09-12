"""Phase VIII — Verifiable Retrieval.

* ``proof.py`` — Steps 1-2: the ``Pi_i`` bundle, the Merkle membership check, and
  ``Commit_i*`` recomputation.
* ``ledger.py`` — Step 3: agreement with the anchored ``BC_i``, plus hash-chain
  integrity.

These three steps are exactly what Exp. 4 measures (global.yaml: "client-side
verification only: Merkle proof, ``Commit_i*`` recomputation, chain consistency.
IPFS fetch and decryption excluded"). Steps 4-6 — ciphertext retrieval,
multi-authority decryption, audit logging — are outside that boundary and are not
implemented here.

Two blockers in Step 2 as published are recorded in ``proof.py``'s module
docstring: it recomputes ``Commit_i*`` with ``AuthRoot_U``
where Phase IV Step 5 bound ``AuthRoot_DO``, and it requires ``VID_i = VID_U``
across two different version namespaces. Both would make Exp. 4 report zero
acceptances if implemented literally.
"""
