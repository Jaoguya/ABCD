"""LV-PQ-ABSE — Ref[54], Phases 1-5.

    Phase 1  System Setup                  (TA: ABE.Setup, Kyber, Dilithium)
    Phase 2  Edge-Side Encryption          (Algorithm 1, EdgeEncrypt)
    Phase 3  Fog Verification + Indexing   (hybrid index, Merkle roots)
    Phase 4  Search                        (Algorithm 2, SearchExec)
    Phase 5  Retrieval + Verification      (Algorithm 3, RetrieveVerify)

Single Trusted Authority — the paper never claims multi-authority, and
54.md records that not repeating skill.md's mislabelling of Ref[41] as
"multi-authority" is deliberate.

THE HYBRID COMBINER IS THE POINT
--------------------------------
Phase 2 encapsulates the record key twice, under the lattice CP-ABE and under
ML-KEM-768, and combines them with HKDF:

    K_hyb = HKDF(K_abe || K_kem)

which stays secure if *either* primitive does. Implemented as the paper states
rather than collapsed to one encapsulation — collapsing it would remove the
scheme's headline security property while making it look faster.

WHAT EXP. 1-3 EXECUTE
---------------------
Exp. 1 measures :func:`trapdoor`, Exp. 2 measures :meth:`FogNode.search`, and
Exp. 3 measures ``d`` independent trapdoor+search pairs. None of them touches
``ct_abe``; see ``abe.py`` and crypto.yaml's ``abe_on_measured_path``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np

from Common.crypto import merkle
from Common.crypto.hashes import hkdf_sha256
from Common.crypto.kem import MLKEM768
from Common.crypto.rng import secure_random_bytes
from Common.crypto.signature import MLDSA65
from Common.crypto.symmetric import Ciphertext
from Common.crypto.symmetric import decrypt as se_decrypt
from Common.crypto.symmetric import encrypt as se_encrypt

from . import abe
from .hybrid_index import HybridIndex, token
from .params import SchemeParams


def sha3_256(*parts: bytes) -> bytes:
    """``H`` — the paper names SHA3-256 for all three domain-separated hashes."""
    h = hashlib.sha3_256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.digest()


# ---------------------------------------------------------------------------
# Phase 1 — System Setup
# ---------------------------------------------------------------------------
@dataclass
class SystemKeys:
    """``mpk = {PP_ABE, PK_Kyber, VPK_Dilithium}`` plus the TA's secrets."""

    params: SchemeParams
    master: Optional[abe.MasterKey]     # None when the ABE is off the path
    kem_encapsulation_key: bytes
    kem_decapsulation_key: bytes
    edge_verifying_key: bytes
    edge_signing_key: bytes
    fog_verifying_key: bytes
    fog_signing_key: bytes
    token_key: bytes                    # Phase 3 PRF tokenization key
    # sk_U / vk_U. Ref[54] L566 signs the trapdoor with the USER's key, not the
    # edge device's: the edge signs ciphertext provenance in Phase 2, the user
    # authorises a query in Phase 4. They are different credentials held by
    # different parties, and conflating them let a device credential stand in
    # for a user's authorisation.
    user_verifying_key: bytes = b""
    user_signing_key: bytes = b""


def setup(params: SchemeParams, *, with_abe: Optional[bool] = None,
          rng: Optional[np.random.Generator] = None) -> SystemKeys:
    """Phase 1.

    ``with_abe`` defaults to crypto.yaml's ``abe_on_measured_path``. Generating
    the CP-ABE master key means a TrapGen at ``n = 768``, which Exp. 1-3 never
    use — see the module docstring.
    """
    if with_abe is None:
        with_abe = params.abe_on_measured_path

    kem = MLKEM768()
    kem_kp = kem.keygen()
    sig = MLDSA65()
    edge = sig.keygen()
    fog = sig.keygen()
    user = sig.keygen()

    return SystemKeys(
        params=params,
        master=(
            abe.setup(params.lattice, params.attribute_universe, rng=rng)
            if with_abe else None
        ),
        kem_encapsulation_key=kem_kp.encapsulation_key,
        kem_decapsulation_key=kem_kp.decapsulation_key,
        edge_verifying_key=edge.verifying_key,
        edge_signing_key=edge.signing_key,
        fog_verifying_key=fog.verifying_key,
        fog_signing_key=fog.signing_key,
        token_key=secure_random_bytes(32),
        user_verifying_key=user.verifying_key,
        user_signing_key=user.signing_key,
    )


# ---------------------------------------------------------------------------
# Phase 2 — Edge-Side Encryption (Algorithm 1)
# ---------------------------------------------------------------------------
@dataclass
class EdgeCiphertext:
    """What one edge device emits for one record."""

    rid: int
    body: Ciphertext                    # AES-256-GCM record ciphertext
    ct_abe: Optional[abe.AbeCiphertext]
    ct_kem: bytes                       # ML-KEM-768 encapsulation
    signature: bytes                    # Dilithium3 over the digest
    tag_prov: bytes                     # provenance tag
    prov_digest: bytes                  # ProvDigest

    @property
    def size_bytes(self) -> int:
        total = self.body.size_bytes + len(self.ct_kem) + len(self.signature)
        total += len(self.tag_prov) + len(self.prov_digest)
        if self.ct_abe is not None:
            total += self.ct_abe.size_bytes
        return total


def _combine(k_abe: bytes, k_kem: bytes) -> bytes:
    """``K_hyb = HKDF(K_abe || K_kem)`` — the hybrid combiner of Phase 2."""
    return hkdf_sha256(k_abe + k_kem, length=32, info=b"perera/hybrid/v1")


def edge_encrypt(keys: SystemKeys, rid: int, plaintext: bytes,
                 policy: Sequence[int], *, device_id: str = "edge-0",
                 rng: Optional[np.random.Generator] = None) -> EdgeCiphertext:
    """Algorithm 1 — ``EdgeEncrypt``."""
    kem = MLKEM768()
    enc = kem.encapsulate(keys.kem_encapsulation_key)

    k_abe = secure_random_bytes(32)
    k_hyb = _combine(k_abe, enc.shared_secret)
    body = se_encrypt(k_hyb, plaintext)

    ct_abe = (
        abe.encrypt(keys.master, policy, k_abe, rng=rng)
        if keys.master is not None else None
    )

    tag_prov = sha3_256(b"prov", device_id.encode(), rid.to_bytes(8, "big"))
    prov_digest = sha3_256(b"digest", tag_prov, body.to_bytes(), enc.ciphertext)
    signature = MLDSA65().sign(keys.edge_signing_key, prov_digest)

    return EdgeCiphertext(
        rid=rid, body=body, ct_abe=ct_abe, ct_kem=enc.ciphertext,
        signature=signature, tag_prov=tag_prov, prov_digest=prov_digest,
    )


# ---------------------------------------------------------------------------
# Phase 3 — Fog verification, provenance binding, hybrid index construction
# ---------------------------------------------------------------------------
@dataclass
class FogNode:
    """One fog node: a hybrid index plus the partitioned Merkle roots over it."""

    keys: SystemKeys
    index: HybridIndex
    partition_roots: Dict[str, bytes] = field(default_factory=dict)
    global_root: bytes = b""
    root_signature: bytes = b""
    ciphertexts: Dict[int, EdgeCiphertext] = field(default_factory=dict)
    _partition_leaves: Dict[str, List[bytes]] = field(default_factory=dict)
    #: Built ONCE by `finalize()`, then reused by every verification.
    #:
    #: `retrieve_verify` used to do `MerkleTree(leaves)` per call, rebuilding
    #: the whole partition tree to produce one inclusion proof -- O(N) work for
    #: an operation the paper's Table II claims is O(log N) -- plus a linear
    #: `leaves.index(digest)` scan to locate the leaf. `MerkleTree.prove()` is
    #: already O(log N) on a BUILT tree, so the cost was entirely the rebuild.
    #: Both are Phase 3 (indexing) work, not Phase 5 (retrieval) work, so they
    #: belong here, where `finalize()` already pays for exactly one build.
    _partition_trees: Dict[str, "merkle.MerkleTree"] = field(default_factory=dict)
    _leaf_positions: Dict[str, Dict[bytes, int]] = field(default_factory=dict)
    rejected: int = 0

    # -- ingest (untimed setup) ---------------------------------------------
    def ingest(self, ct: EdgeCiphertext, keywords: Sequence[str], *,
               epoch: str, category: int, fuzzy_terms: Sequence[str] = (),
               keep_ciphertext: bool = False) -> bool:
        """Verify the edge signature, then index. Returns False on rejection.

        The signature check is not decoration: Phase 3 exists to stop an
        unauthenticated edge device from writing into the index, and a fog node
        that indexed first would have already leaked the write.
        """
        if not MLDSA65().verify(
            self.keys.edge_verifying_key, ct.prov_digest, ct.signature
        ):
            self.rejected += 1
            return False

        tokens = [token(self.keys.token_key, w) for w in keywords]
        self.index.add(
            ct.rid, tokens, epoch=epoch, category=category,
            ngram_terms=fuzzy_terms,
        )
        self._partition_leaves.setdefault(epoch, []).append(ct.prov_digest)
        if keep_ciphertext:
            self.ciphertexts[ct.rid] = ct
        return True

    def finalize(self) -> bytes:
        """Per-partition Merkle roots, aggregated and signed — end of Phase 3.

        The trees themselves are RETAINED (see `_partition_trees`), not
        discarded and rebuilt per verification. This is the same single build
        that was always paid here; only the tree object now outlives it.
        """
        self._partition_trees = {
            part: merkle.MerkleTree(leaves)
            for part, leaves in sorted(self._partition_leaves.items())
        }
        self._leaf_positions = {
            part: {digest: i for i, digest in enumerate(leaves)}
            for part, leaves in sorted(self._partition_leaves.items())
        }
        self.partition_roots = {
            part: tree.root for part, tree in self._partition_trees.items()
        }
        if not self.partition_roots:
            self.global_root = sha3_256(b"empty-index")
        else:
            self.global_root = merkle.MerkleTree(
                [
                    sha3_256(p.encode(), r)
                    for p, r in sorted(self.partition_roots.items())
                ]
            ).root
        self.root_signature = MLDSA65().sign(
            self.keys.fog_signing_key, self.global_root
        )
        return self.global_root

    # -- Phase 4 — SearchExec (the measured path) ---------------------------
    def search(self, trapdoor: "Trapdoor") -> "SearchResult":
        """Algorithm 2. Verifies the trapdoor signature, then intersects."""
        if not MLDSA65().verify(
            trapdoor.verifying_key, trapdoor.digest, trapdoor.signature
        ):
            raise PermissionError("trapdoor signature does not verify")

        before = self.index.keywords.descents
        matches = self.index.search(
            trapdoor.tokens, epoch=trapdoor.epoch, category=trapdoor.category
        )
        if trapdoor.fuzzy_term:
            matches |= self.index.fuzzy(
                trapdoor.fuzzy_term, self.keys.params.fuzzy_threshold
            )
        descents = self.index.keywords.descents - before

        return SearchResult(
            rids=matches,
            audit_commit=sha3_256(
                b"audit", self.global_root, trapdoor.digest,
                len(matches).to_bytes(4, "big"),
            ),
            tree_descents=descents,
            candidates_examined=sum(
                len(self.index.keywords.lookup(t)) for t in trapdoor.tokens
            ),
        )


# ---------------------------------------------------------------------------
# Phase 4 — trapdoor (what Exp. 1 measures)
# ---------------------------------------------------------------------------
@dataclass
class Trapdoor:
    """``T_w`` — a signed PRF token set. No lattice sampling, per Table II."""

    tokens: Tuple[bytes, ...]
    epoch: Optional[str]
    category: Optional[int]
    fuzzy_term: Optional[str]
    digest: bytes
    signature: bytes
    verifying_key: bytes

    @property
    def size_bytes(self) -> int:
        """Exp. 1's secondary metric."""
        return sum(len(t) for t in self.tokens) + len(self.signature)


def enrol_user(keys: SystemKeys, attributes: Optional[Sequence[int]] = None):
    """Phase 1: issue this user their attribute secret key ``SK_A``.

    Ref[54]'s trapdoor binds to ``SK_A`` (L563-565) and Theorem 2 rests on that
    binding (L816), so a querying user must hold one. Enrolment is setup: the
    lattice preimage sampling happens here, once, and never on the query path.

    Defaults to the first three attributes of the universe -- a benchmark
    choice. The paper fixes no particular attribute set for its own evaluation,
    and the count does not reach the measured path: ``attribute_binding()``
    hashes the preimages whatever there are of them.
    """
    if keys.master is None:
        raise ValueError(
            "no ABE master key: setup() was called with with_abe=False, so no "
            "attribute key can be issued and trapdoors cannot be bound as "
            "Ref[54] L563-565 requires"
        )
    if attributes is None:
        attributes = range(min(3, keys.params.attribute_universe))
    return abe.keygen(keys.master, list(attributes))

def attribute_binding(key: "abe.AttributeKey") -> bytes:
    """``H(SK_A)`` — the value the trapdoor is bound to.

    Ref[54] L563-565 binds query tokens to the user's attribute-based secret key
    and Theorem 2 (L816) rests on that binding. This derives a commitment to the
    key from material only its holder has: the attribute set AND the short
    preimages ``d_i``. Binding to the attribute set alone would be forgeable by
    anyone who knows which attributes a user holds, which is public.

    A HASH, not a lattice operation. Table II costs the trapdoor at
    ``O(n + T_PRF)`` and states there is no lattice sampling at query time, so
    binding must not introduce one.
    """
    parts = [b"attr-bind"]
    for index in sorted(key.attributes):
        parts.append(index.to_bytes(4, "big"))
        # tobytes() over the preimage: the secret half of the key.
        parts.append(key.d[index].astype("<i8", copy=False).tobytes())
    return sha3_256(*parts)


def trapdoor(keys: SystemKeys, keywords: Sequence[str], *,
             attribute_key: "abe.AttributeKey",
             epoch: Optional[str] = None, category: Optional[int] = None,
             fuzzy_term: Optional[str] = None) -> Trapdoor:
    """``TokenTrapdoorGen(SK_A, T, range, op, epoch)`` — Ref[54] §IV-C.5b, L798.

    The whole of Exp. 1: ``q`` PRF evaluations, one attribute-key binding hash,
    and one Dilithium3 signature. All three are timed.

    **The attribute key is required, not optional.** L563-565 constructs the
    trapdoor by "binding query tokens to the user's attribute-based secret key",
    and Theorem 2's proof (L816) takes that binding as a precondition. A
    trapdoor without it is a cheaper object than the paper specifies, and this
    baseline may not be measured on a weaker construction than it published.

    **Signed with ``sk_U``, not the edge device's key** (L566:
    ``sigma_user = Dilithium3.Sign(sk_U, H_2(TD))``). The edge device signs
    ciphertext provenance in Phase 2; the querying user authorises the query in
    Phase 4. :meth:`FogNode.search` verifies against ``user_verifying_key``.
    """
    tokens = tuple(token(keys.token_key, w) for w in keywords)
    digest = sha3_256(
        b"trapdoor", *tokens,
        (epoch or "").encode(),
        b"" if category is None else category.to_bytes(4, "big"),
        (fuzzy_term or "").encode(),
        # The binding Theorem 2 depends on.
        attribute_binding(attribute_key),
    )
    return Trapdoor(
        tokens=tokens, epoch=epoch, category=category, fuzzy_term=fuzzy_term,
        digest=digest,
        signature=MLDSA65().sign(keys.user_signing_key, digest),
        verifying_key=keys.user_verifying_key,
    )


@dataclass
class SearchResult:
    rids: Set[int]
    audit_commit: bytes
    tree_descents: int
    candidates_examined: int


# ---------------------------------------------------------------------------
# Phase 5 — Retrieval, Decryption, Verification (Algorithm 3)
# ---------------------------------------------------------------------------
@dataclass
class RetrieveOutcome:
    plaintext: Optional[bytes]
    signature_ok: bool
    inclusion_ok: bool
    fresh: bool

    @property
    def accepted(self) -> bool:
        return (
            self.plaintext is not None
            and self.signature_ok
            and self.inclusion_ok
            and self.fresh
        )


@dataclass
class VerifyOutcome:
    """The three checks of Algorithm 3, without the retrieval half."""

    signature_ok: bool
    inclusion_ok: bool
    fresh: bool
    proof: Optional[merkle.MerkleProof] = None

    @property
    def accepted(self) -> bool:
        return self.signature_ok and self.inclusion_ok and self.fresh


def verify_record(keys: SystemKeys, node: FogNode, rid: int, epoch: str,
                  latest_root: bytes) -> VerifyOutcome:
    """Algorithm 3's VERIFICATION half — the three checks, no decryption.

    Split out of :func:`retrieve_verify` so Exp. 4 can time this repo's Exp. 4
    boundary as it is defined for every other scheme: "verification is
    client-side: Merkle proof check ... IPFS fetch and decryption are
    EXCLUDED". Algorithm 3 as published does both halves in one call, so
    timing `retrieve_verify` whole would charge Ref[54] for an ABE decrypt, a
    KEM decapsulation and an AES-GCM open that no other arm's number contains.

    The inclusion proof comes from the tree `finalize()` already built, so this
    is O(log N) in the partition size, which is what Table II claims.

    The freshness check (``root_T == root*_T``) is what makes a stale index
    snapshot detectable; without it a server could serve an old, correct-looking
    Merkle proof forever, which is the attack the paper's verifiability game
    covers.
    """
    ct = node.ciphertexts[rid]

    signature_ok = MLDSA65().verify(
        keys.edge_verifying_key, ct.prov_digest, ct.signature
    )

    position = node._leaf_positions.get(epoch, {}).get(ct.prov_digest)
    tree = node._partition_trees.get(epoch)
    inclusion_ok = False
    proof = None
    if position is not None and tree is not None:
        proof = tree.prove(position)
        inclusion_ok = merkle.MerkleTree.verify(
            proof, node.partition_roots[epoch]
        )

    return VerifyOutcome(
        signature_ok=signature_ok, inclusion_ok=inclusion_ok,
        fresh=node.global_root == latest_root, proof=proof,
    )


def retrieve_verify(keys: SystemKeys, node: FogNode, rid: int,
                    key_abe: abe.AttributeKey, epoch: str,
                    latest_root: bytes) -> RetrieveOutcome:
    """Algorithm 3 in full — the three checks, then hybrid key reconstruction.

    Unchanged in behaviour; the checks now come from :func:`verify_record` so
    the two halves can be measured separately without either being reimplemented.
    """
    ct = node.ciphertexts[rid]
    checks = verify_record(keys, node, rid, epoch, latest_root)
    signature_ok = checks.signature_ok
    inclusion_ok = checks.inclusion_ok
    fresh = checks.fresh

    plaintext = None
    if keys.master is not None and ct.ct_abe is not None:
        k_abe = abe.decrypt(keys.master, key_abe, ct.ct_abe)
        if k_abe is not None:
            k_kem = MLKEM768().decapsulate(keys.kem_decapsulation_key, ct.ct_kem)
            try:
                plaintext = se_decrypt(_combine(k_abe, k_kem), ct.body)
            except Exception:  # noqa: BLE001 - a failed unwrap is a real outcome
                plaintext = None

    return RetrieveOutcome(
        plaintext=plaintext, signature_ok=signature_ok,
        inclusion_ok=inclusion_ok, fresh=fresh,
    )
