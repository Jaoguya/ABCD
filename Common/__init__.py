"""Shared, scheme-independent building blocks for the MA-LB-PQ-VDSE benchmark.

This package holds code that must be IDENTICAL across every scheme so that
measured differences come from the constructions under test and not from the
primitive layer beneath them (skill.md, "Environment parity is part of the
result").

Scope rule — read this before adding anything here:

    Common/ holds PRIMITIVES. It must never hold a scheme's CONSTRUCTION.

A primitive is something a published paper cites rather than defines: SHA-256,
HMAC, AES-GCM, a Merkle tree, a Bloom filter, discrete Gaussian sampling, a
bilinear pairing. A construction is what a paper actually contributes: Guo's
forward index, Perera's hybrid index, our PDSI/AASS/DIAS.
Constructions live in ``Schemes/<name>/src/`` and stay independent per
skill.md ("Do NOT copy implementation logic between scheme folders").
"""

__all__ = ["crypto"]
