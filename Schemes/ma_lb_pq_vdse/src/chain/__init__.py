"""Consortium blockchain and IPFS adapters (Phase V, and anchoring throughout).

``ledger.py`` holds the ledger interface and the in-process append-only chain
used by Phases I-III. Hyperledger Fabric v2.5 implements the same interface and
is required before Exp. 4, the first experiment that measures a
blockchain-consistency check.
"""
