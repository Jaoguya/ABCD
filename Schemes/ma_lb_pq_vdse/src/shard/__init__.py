"""Index shard distribution across the Fog Search Nodes.

``propagation.py`` implements Phase V Step 4 (``Sync_i`` to the authorized FSNs)
and Step 5 (the index catalog the AIM maintains).

Phase V Steps 1-3 — IPFS outsourcing of ``CT_i``, metadata registration, and the
``BC_i`` blockchain commitment — are not implemented. ``CID_i`` is therefore a
labelled placeholder, and Step 4's "after successful blockchain confirmation"
ordering is a documented precondition rather than an enforced one.
"""
