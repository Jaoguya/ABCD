"""Phase VII — Dynamic Index Evolution and Incremental Authorization Sync.

``ias.py`` implements Steps 2-7: localized index evolution, authorization-state
evolution (``VID_k' = VID_k + 1``, ``RevRoot_k'``, ``C_k^auth'``), the incremental
Merkle update, the ``IAS_i`` message, selective propagation to the affected Fog
Search Nodes, and the ``BC_i'`` anchor.

This is the phase Exp. 5 and Exp. 6 measure, so what it avoids matters as much as
what it does: no global index rebuild, and under Option D no
re-tokenization at all — a policy or version change rewrites entry payload and
two bitmap bits, never a token or a posting list.
"""
