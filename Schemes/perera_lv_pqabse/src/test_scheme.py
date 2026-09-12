"""Correctness tests for Ref[54] LV-PQ-ABSE.

Covers the full Phase 1 -> Phase 5 path INCLUDING the lattice CP-ABE, which the
Exp. 1-3 runners deliberately skip (crypto.yaml ``abe_on_measured_path``). The
construction is therefore verified end to end even though the experiments do not
execute that half — which is the condition under which skipping it is honest.

The CP-ABE tests use a reduced lattice dimension. At the configured n = 768 a
single Setup+Encrypt is ~1 s and TrapGen dominates, which would make the suite
unusable; the dimension does not change whether the algebra is correct, and
``test_configured_parameters_are_valid`` pins the real parameter set separately.
"""

from __future__ import annotations

import numpy as np
from dataclasses import replace

import pytest

from Common.crypto.lattice import LatticeParams

from . import abe, scheme
from .hybrid_index import BPlusTree, HybridIndex, ngrams, token
from .params import SchemeParams

SMALL = LatticeParams(n=64, m=64 * 2 * 22, log_q=22, sigma=4.0)


@pytest.fixture(scope="module")
def params() -> SchemeParams:
    return SchemeParams.from_config()


@pytest.fixture(scope="module")
def keys(params: SchemeParams) -> scheme.SystemKeys:
    """Setup with the ABE ON, at the SMALL lattice.

    It was ``with_abe=False`` until 2026-09-12. Trapdoors must now bind to the
    user's attribute key (Ref[54] L563-565), so a key has to exist -- and the
    campaign's n=768 TrapGen takes minutes, which no test suite can pay. SMALL
    gives a real attribute key in milliseconds; nothing here measures the
    lattice, only that the binding is present and enforced.
    """
    small = replace(params, lattice=SMALL, attribute_universe=4,
                    abe_on_measured_path=True)
    return scheme.setup(small, with_abe=True)


# ---------------------------------------------------------------------------
# parameters
# ---------------------------------------------------------------------------

_USER_KEYS = {}


def user_key(keys):
    """One enrolled user per SystemKeys, cached.

    ``enrol_user`` samples lattice preimages, so calling it per assertion would
    make the suite unusable. A user's attribute key does not change between
    queries, so caching it is also what the scheme does.
    """
    k = id(keys)
    if k not in _USER_KEYS:
        _USER_KEYS[k] = scheme.enrol_user(keys)
    return _USER_KEYS[k]

def test_configured_parameters_are_valid(params: SchemeParams):
    """The real (n, q, sigma) must satisfy the toolkit's own guards.

    Especially the int64 overflow guard: exceeding it corrupts results silently
    rather than raising, which is why it is asserted rather than assumed.
    """
    params.lattice.validate()
    assert params.lattice.n == 768
    assert params.lattice.q == 1 << 22
    worst = params.lattice.m * (params.lattice.q - 1) ** 2
    assert worst < 2**63, "int64 matmul would overflow at these parameters"


def test_lambda_is_the_published_192(params: SchemeParams):
    assert params.security_parameter_lambda == 192


# ---------------------------------------------------------------------------
# lattice CP-ABE
# ---------------------------------------------------------------------------
def test_abe_decrypts_when_the_policy_is_satisfied():
    rng = np.random.default_rng(11)
    mk = abe.setup(SMALL, 4, rng=rng)
    key = abe.keygen(mk, [0, 1, 2], rng=rng)
    msg = bytes(range(32))
    ct = abe.encrypt(mk, [0, 1], msg, rng=rng)
    assert abe.decrypt(mk, key, ct) == msg


def test_abe_refuses_when_an_attribute_is_missing():
    """A conjunctive policy must not be satisfiable by a subset of it."""
    rng = np.random.default_rng(12)
    mk = abe.setup(SMALL, 4, rng=rng)
    partial = abe.keygen(mk, [0], rng=rng)
    ct = abe.encrypt(mk, [0, 1], bytes(32), rng=rng)
    assert abe.decrypt(mk, partial, ct) is None


def test_abe_ciphertexts_differ_under_the_same_message():
    """Fresh randomness per encryption; two ct_abe must not be identical."""
    rng = np.random.default_rng(13)
    mk = abe.setup(SMALL, 3, rng=rng)
    msg = b"\x01" * 32
    a = abe.encrypt(mk, [0], msg, rng=rng)
    b = abe.encrypt(mk, [0], msg, rng=rng)
    assert not np.array_equal(a.c0, b.c0)


# ---------------------------------------------------------------------------
# hybrid index
# ---------------------------------------------------------------------------
def test_bplustree_is_a_tree_not_a_flat_map():
    """The paper specifies a B+-tree and costs search at O(log n).

    A dict would be faster and would understate the baseline's search cost, so
    the structure's height is asserted directly.
    """
    tree = BPlusTree(order=8)
    keys_ = [token(b"k" * 32, f"w{i}") for i in range(2000)]
    for i, tk in enumerate(keys_):
        tree.insert(tk, i)
    assert tree.height >= 3
    assert all(tree.lookup(tk) == [i] for i, tk in enumerate(keys_))
    assert tree.lookup(token(b"k" * 32, "absent")) == []


def test_index_search_is_conjunctive():
    idx = HybridIndex()
    k = b"t" * 32
    idx.add(1, [token(k, "a"), token(k, "b")], epoch="e", category=0)
    idx.add(2, [token(k, "a")], epoch="e", category=0)
    assert idx.search([token(k, "a")]) == {1, 2}
    assert idx.search([token(k, "a"), token(k, "b")]) == {1}


def test_index_filters_by_epoch_and_category():
    idx = HybridIndex()
    k = b"t" * 32
    idx.add(1, [token(k, "a")], epoch="2020", category=7)
    idx.add(2, [token(k, "a")], epoch="2021", category=7)
    idx.add(3, [token(k, "a")], epoch="2020", category=9)
    assert idx.search([token(k, "a")], epoch="2020") == {1, 3}
    assert idx.search([token(k, "a")], category=7) == {1, 2}
    assert idx.search([token(k, "a")], epoch="2020", category=7) == {1}


def test_fuzzy_matches_by_ngram_overlap():
    idx = HybridIndex(ngram_size=3)
    idx.add(1, [], epoch="e", category=0, ngram_terms=["hypertension"])
    idx.add(2, [], epoch="e", category=0, ngram_terms=["diabetes"])
    assert idx.fuzzy("hypertensio", 0.6) == {1}
    assert idx.fuzzy("hypertensio", 0.6) != {1, 2}


def test_ngrams_handle_terms_shorter_than_the_window():
    assert ngrams("ab", 3) == ["ab"]
    assert ngrams("", 3) == []


def test_tokens_are_keyed():
    """An unkeyed token would let anyone holding the index derive trapdoors."""
    assert token(b"k1" * 16, "w") != token(b"k2" * 16, "w")


# ---------------------------------------------------------------------------
# end-to-end, Phases 2-4
# ---------------------------------------------------------------------------
def _ingest(keys_: scheme.SystemKeys, n: int = 40) -> scheme.FogNode:
    node = scheme.FogNode(keys=keys_, index=HybridIndex())
    for rid in range(n):
        ct = scheme.edge_encrypt(keys_, rid, f"record-{rid}".encode(), [0, 1])
        node.ingest(
            ct, [f"kw{rid % 5}", f"kw{rid % 3}"], epoch="2026",
            category=rid % 2, fuzzy_terms=[f"term{rid % 4}"],
            keep_ciphertext=True,
        )
    node.finalize()
    return node


def test_search_returns_exactly_the_matching_records(keys: scheme.SystemKeys):
    node = _ingest(keys)
    td = scheme.trapdoor(keys, ["kw0"], attribute_key=user_key(keys))
    got = node.search(td).rids
    assert got == {rid for rid in range(40) if rid % 5 == 0 or rid % 3 == 0}


def test_search_rejects_an_unsigned_trapdoor(keys: scheme.SystemKeys):
    """Phase 4 verifies the trapdoor; an unauthorised query must not run."""
    node = _ingest(keys, n=5)
    td = scheme.trapdoor(keys, ["kw0"], attribute_key=user_key(keys))
    forged = scheme.Trapdoor(
        tokens=td.tokens, epoch=None, category=None, fuzzy_term=None,
        digest=td.digest, signature=b"\x00" * len(td.signature),
        verifying_key=td.verifying_key,
    )
    with pytest.raises(PermissionError):
        node.search(forged)


def test_fog_rejects_a_record_with_a_bad_edge_signature(keys: scheme.SystemKeys):
    node = scheme.FogNode(keys=keys, index=HybridIndex())
    ct = scheme.edge_encrypt(keys, 0, b"payload", [0])
    tampered = scheme.EdgeCiphertext(
        rid=ct.rid, body=ct.body, ct_abe=ct.ct_abe, ct_kem=ct.ct_kem,
        signature=b"\x00" * len(ct.signature), tag_prov=ct.tag_prov,
        prov_digest=ct.prov_digest,
    )
    assert node.ingest(tampered, ["kw"], epoch="e", category=0) is False
    assert node.rejected == 1
    assert node.index.record_count == 0


def test_trapdoor_carries_one_token_per_keyword(keys: scheme.SystemKeys):
    td = scheme.trapdoor(keys, ["a", "b", "c"], attribute_key=user_key(keys))
    assert len(td.tokens) == 3
    assert td.size_bytes == 3 * 32 + len(td.signature)


def test_trapdoor_is_deterministic_in_its_tokens(keys: scheme.SystemKeys):
    """The token is a PRF, so the same keyword must map to the same token.

    Otherwise a trapdoor could never match an index entry written earlier.
    """
    assert scheme.trapdoor(keys, ["x"], attribute_key=user_key(keys)).tokens == scheme.trapdoor(keys, ["x"], attribute_key=user_key(keys)).tokens


# ---------------------------------------------------------------------------
# end-to-end, Phase 5 — with the CP-ABE actually in the path
# ---------------------------------------------------------------------------
def test_full_retrieve_verify_accepts_a_fresh_authorised_record(
    params: SchemeParams,
):
    """Phases 1-5 with ct_abe present, at the reduced lattice dimension."""
    rng = np.random.default_rng(21)
    small = SchemeParams(
        security_parameter_lambda=params.security_parameter_lambda,
        kem=params.kem, signature=params.signature, hash_name=params.hash_name,
        symmetric=params.symmetric, attribute_universe=4,
        ngram_size=params.ngram_size, fuzzy_threshold=params.fuzzy_threshold,
        cross_domain_mode=params.cross_domain_mode, abe_on_measured_path=True,
        lattice=SMALL,
    )
    keys_ = scheme.setup(small, with_abe=True, rng=rng)
    node = scheme.FogNode(keys=keys_, index=HybridIndex())
    ct = scheme.edge_encrypt(keys_, 0, b"clinical-record", [0, 1], rng=rng)
    assert node.ingest(ct, ["fever"], epoch="2026", category=0,
                       keep_ciphertext=True)
    root = node.finalize()

    authorised = abe.keygen(keys_.master, [0, 1, 2], rng=rng)
    out = scheme.retrieve_verify(keys_, node, 0, authorised, "2026", root)
    assert out.plaintext == b"clinical-record"
    assert out.signature_ok and out.inclusion_ok and out.fresh
    assert out.accepted

    # A stale root must be detected: same record, previous global root.
    stale = scheme.retrieve_verify(keys_, node, 0, authorised, "2026", b"\x00" * 32)
    assert not stale.fresh and not stale.accepted

    # An unauthorised key recovers nothing.
    unauthorised = abe.keygen(keys_.master, [2], rng=rng)
    denied = scheme.retrieve_verify(keys_, node, 0, unauthorised, "2026", root)
    assert denied.plaintext is None and not denied.accepted


def test_hybrid_combiner_uses_both_encapsulations():
    """K_hyb must change if either half changes, or it is not a combiner."""
    base = scheme._combine(b"a" * 32, b"b" * 32)
    assert base != scheme._combine(b"c" * 32, b"b" * 32)
    assert base != scheme._combine(b"a" * 32, b"c" * 32)
    assert len(base) == 32


# ---------------------------------------------------------------------------
# Ref[54] L563-565 / L798 / L816 — the trapdoor binds to SK_A
# ---------------------------------------------------------------------------
def test_trapdoor_requires_an_attribute_key(keys: scheme.SystemKeys):
    """It is a required argument, not an optional one.

    L563-565 constructs the trapdoor by "binding query tokens to the user's
    attribute-based secret key", and Theorem 2's proof (L816) takes that binding
    as a precondition. A trapdoor without it is a cheaper object than the paper
    specifies, and this baseline may not be measured on a weaker construction
    than it published.
    """
    with pytest.raises(TypeError):
        scheme.trapdoor(keys, ["kw0"])


def test_different_attribute_keys_give_different_trapdoors(keys):
    """The binding is real: same keywords, different SK_A, different trapdoor.

    If this fails the binding is decorative -- the digest would not actually
    depend on the key it claims to be bound to.
    """
    a = scheme.enrol_user(keys, attributes=[0, 1])
    b = scheme.enrol_user(keys, attributes=[0, 1])
    td_a = scheme.trapdoor(keys, ["kw0"], attribute_key=a)
    td_b = scheme.trapdoor(keys, ["kw0"], attribute_key=b)
    assert td_a.tokens == td_b.tokens, "the PRF tokens are key-independent"
    assert td_a.digest != td_b.digest, (
        "two users with the same attributes but different secret preimages "
        "produced the same trapdoor -- the SK_A binding is not in the digest"
    )


def test_trapdoor_binds_to_the_secret_not_just_the_attribute_set(keys):
    """Binding to the attribute SET alone would be forgeable.

    Which attributes a user holds is public; the preimages are not. Two users
    holding an identical attribute set must still produce distinct trapdoors.
    """
    a = scheme.enrol_user(keys, attributes=[0, 1])
    b = scheme.enrol_user(keys, attributes=[0, 1])
    assert a.attributes == b.attributes
    assert scheme.attribute_binding(a) != scheme.attribute_binding(b)


def test_trapdoor_is_signed_by_the_user_not_the_edge_device(keys):
    """L566: sigma_user = Dilithium3.Sign(sk_U, H_2(TD)).

    The edge device signs ciphertext provenance in Phase 2; the querying user
    authorises the query in Phase 4. Signing with the edge key let a device
    credential stand in for a user's authorisation.
    """
    td = scheme.trapdoor(keys, ["kw0"], attribute_key=user_key(keys))
    assert td.verifying_key == keys.user_verifying_key
    assert td.verifying_key != keys.edge_verifying_key


def test_the_binding_is_not_recomputed_on_the_query_path(keys):
    """Ref[54] Table II costs the trapdoor at O(n + T_PRF).

    The binding hashes the attribute preimages, which are O(m) each -- 792 KB at
    the configured m = 33,792. Doing that per query cost 4.15 ms against a
    1.4 ms trapdoor and grew with the lattice dimension, which would have
    reported this baseline as several times slower than the construction it
    published. It is derived once at enrolment instead.

    Guards the cache, not the speed: a timing assertion would be flaky, so this
    asserts the memo is populated by enrolment and returns the same object.
    """
    k = scheme.enrol_user(keys, attributes=[0, 1])
    assert id(k) in scheme._BINDINGS, (
        "enrol_user must derive the binding; leaving it to the first trapdoor "
        "puts an O(m|S|) hash on the query path"
    )
    first = scheme.attribute_binding(k)
    assert scheme.attribute_binding(k) is first, "binding must be memoised"
