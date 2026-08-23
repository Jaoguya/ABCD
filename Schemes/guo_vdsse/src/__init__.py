"""Guo VDSSE (Ref[35]) — Forward Private Verifiable DSSE with Conjunctive Query.

Guo et al., "Forward Private Verifiable Dynamic Searchable Symmetric
Encryption With Efficient Conjunctive Query", IEEE TDSC, Vol. 21, No. 2,
March/April 2024.

This package implements the published construction faithfully:
  - Dual index (inverted + forward via t-Pun-PRF)
  - XOR-accumulated verification tags from symmetric crypto only
  - Forward privacy via version-keyed encryption
  - Non-interactive conjunctive query

Shared primitives (SHA-256, HMAC, AES-GCM, t-Pun-PRF) come from
Common/crypto/; scheme-specific logic stays here. See README §8 for the
separation principle.
"""
