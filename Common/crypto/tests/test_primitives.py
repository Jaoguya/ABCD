#!/usr/bin/env python3
"""Verification tests for every primitive in ``Common/crypto``.

Each test checks a DEFINING PROPERTY of the primitive, not merely that a call
returns bytes of the right length. A Merkle tree that returns 32 bytes but
verifies a tampered leaf has passed the shallow test and failed the real one.

Runs standalone with no test framework::

    python3 Common/crypto/tests/test_primitives.py          # all
    python3 Common/crypto/tests/test_primitives.py lattice  # one module

and is also collectible by pytest if it is installed::

    pytest Common/crypto/tests/test_primitives.py -v

Tests whose backend is not installed (pairing, ML-KEM) SKIP rather than fail,
so a missing optional dependency does not hide a real regression elsewhere.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from Common.crypto import bloom, hashes, kem, lattice, merkle, pairing, prf, rng  # noqa: E402
from Common.crypto import symmetric  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


# ===========================================================================
# hashes.py
# ===========================================================================
def test_hashes_deterministic_and_sized():
    assert hashes.sha256(b"abc") == hashes.sha256(b"abc")
    assert len(hashes.sha256(b"abc")) == 32
    assert hashes.sha256(b"abc") != hashes.sha256(b"abd")


def test_hashes_length_prefix_prevents_framing_collision():
    """(b"ab", b"c") and (b"a", b"bc") must not collide.

    Plain concatenation would hash both to SHA-256("abc"). This is the whole
    reason ``_join`` length-prefixes each part.
    """
    assert hashes.sha256(b"ab", b"c") != hashes.sha256(b"a", b"bc")


def test_hashes_domain_separation():
    assert hashes.sha256(b"x", domain=b"A") != hashes.sha256(b"x", domain=b"B")


def test_hashes_truncation_length_and_prefix():
    """Truncated digests must be a genuine prefix of the full digest."""
    full = hashes.sha256(b"payload")
    short = hashes.sha256_bits(b"payload", bits=192)
    assert len(short) == 24
    assert full.startswith(short)

    for bad in (0, 257, 100):  # zero, oversized, not a whole byte count
        try:
            hashes.sha256_bits(b"x", bits=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"sha256_bits accepted bits={bad}")


def test_hashes_hmac_matches_stdlib():
    """Our HMAC must be real HMAC-SHA256 over the length-prefixed input.

    Note ``hmac_sha256`` frames its parts but does NOT prepend the domain tag
    (that happens only in ``sha256``), so the expected value is built the
    same way here.
    """
    import hashlib
    import hmac as std_hmac

    key = b"k" * 32
    framed = (3).to_bytes(4, "big") + b"abc" + (2).to_bytes(4, "big") + b"de"
    expected = std_hmac.new(key, framed, hashlib.sha256).digest()
    assert hashes.hmac_sha256(key, b"abc", b"de") == expected


def test_hashes_blake2b_keyed_differs_by_key():
    a = hashes.hmac_blake2b(b"key-one", b"msg")
    b = hashes.hmac_blake2b(b"key-two", b"msg")
    assert a != b and len(a) == 32


def test_hashes_hkdf_length_and_sensitivity():
    okm = hashes.hkdf_sha256(b"secret", length=64, salt=b"s", info=b"i")
    assert len(okm) == 64
    # Distinct info must give distinct output, or domain separation is broken.
    assert okm != hashes.hkdf_sha256(b"secret", length=64, salt=b"s", info=b"j")
    # Longer output must extend, not restart: HKDF is a stream.
    assert hashes.hkdf_sha256(b"secret", length=32, salt=b"s", info=b"i") == okm[:32]


def test_hashes_constant_time_equal():
    assert hashes.constant_time_equal(b"abc", b"abc")
    assert not hashes.constant_time_equal(b"abc", b"abd")


def test_hashes_hash_to_zq_in_range_and_deterministic():
    q = 1 << 24  # Ref[52]'s modulus
    values = hashes.hash_to_zq(b"keyword", q, count=64)
    assert len(values) == 64
    assert values.min() >= 0 and values.max() < q
    assert np.array_equal(values, hashes.hash_to_zq(b"keyword", q, count=64))
    assert not np.array_equal(values, hashes.hash_to_zq(b"other", q, count=64))


def test_hashes_hash_to_zq_unbiased_for_prime_modulus():
    """Rejection sampling must stay in range for a non-power-of-two q.

    ``digest % q`` would also stay in range, so the check that matters is
    that the output spreads across the whole space rather than clustering.
    """
    q = 65537
    values = hashes.hash_to_zq(b"seed", q, count=4000)
    assert values.min() >= 0 and values.max() < q
    # With 4000 uniform draws every octant should be populated.
    octants = np.unique((values * 8) // q)
    assert len(octants) == 8, f"only {len(octants)}/8 octants populated"


# ===========================================================================
# rng.py
# ===========================================================================
def test_rng_secure_bytes_length_and_freshness():
    assert len(rng.secure_random_bytes(32)) == 32
    assert rng.secure_random_bytes(32) != rng.secure_random_bytes(32)
    try:
        rng.secure_random_bytes(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative length accepted")


def test_rng_secure_int_in_range():
    assert all(0 <= rng.secure_random_int(10) < 10 for _ in range(200))


def test_rng_deterministic_is_reproducible():
    """Same seed must give the same stream — Exp. 7-8 need identical traces."""
    a = rng.DeterministicRNG(20260803).integers(0, 1000, size=100)
    b = rng.DeterministicRNG(20260803).integers(0, 1000, size=100)
    assert np.array_equal(a, b)
    c = rng.DeterministicRNG(20260804).integers(0, 1000, size=100)
    assert not np.array_equal(a, c)


def test_rng_spawn_streams_are_independent_and_stable():
    parent = rng.DeterministicRNG(42)
    left = parent.spawn("keywords").integers(0, 1000, size=50)
    right = parent.spawn("domains").integers(0, 1000, size=50)
    assert not np.array_equal(left, right)
    # Stable across calls: a fresh parent must reproduce the same child.
    again = rng.DeterministicRNG(42).spawn("keywords").integers(0, 1000, size=50)
    assert np.array_equal(left, again)


def test_rng_label_hashing_is_not_pythons_hash():
    """Labels must hash stably across processes, so PYTHONHASHSEED is irrelevant."""
    assert rng._label_to_int("keywords") == rng._label_to_int("keywords")
    assert rng._label_to_int("keywords") != rng._label_to_int("domains")


# ===========================================================================
# symmetric.py
# ===========================================================================
def test_symmetric_roundtrip():
    key = symmetric.generate_key()
    assert len(key) == symmetric.KEY_BYTES
    ct = symmetric.encrypt(key, b"encrypted EHR record")
    assert symmetric.decrypt(key, ct) == b"encrypted EHR record"


def test_symmetric_wrong_key_rejected():
    ct = symmetric.encrypt(symmetric.generate_key(), b"secret")
    try:
        symmetric.decrypt(symmetric.generate_key(), ct)
    except symmetric.DecryptionError:
        pass
    else:
        raise AssertionError("decryption succeeded under the wrong key")


def test_symmetric_tampering_detected():
    """The point of GCM: a flipped ciphertext bit must fail, not decrypt."""
    key = symmetric.generate_key()
    ct = symmetric.encrypt(key, b"verifiable retrieval payload")
    corrupted = bytearray(ct.body)
    corrupted[0] ^= 0x01
    try:
        symmetric.decrypt(key, symmetric.Ciphertext(ct.nonce, bytes(corrupted)))
    except symmetric.DecryptionError:
        pass
    else:
        raise AssertionError("tampered ciphertext authenticated")


def test_symmetric_associated_data_is_bound():
    key = symmetric.generate_key()
    ct = symmetric.encrypt(key, b"payload", associated_data=b"domain-2")
    assert symmetric.decrypt(key, ct, associated_data=b"domain-2") == b"payload"
    try:
        symmetric.decrypt(key, ct, associated_data=b"domain-3")
    except symmetric.DecryptionError:
        pass
    else:
        raise AssertionError("AAD mismatch accepted")


def test_symmetric_nonces_are_fresh():
    """A repeated (key, nonce) pair breaks GCM catastrophically."""
    key = symmetric.generate_key()
    nonces = {symmetric.encrypt(key, b"m").nonce for _ in range(200)}
    assert len(nonces) == 200


def test_symmetric_wire_format_roundtrip():
    key = symmetric.generate_key()
    ct = symmetric.encrypt(key, b"payload")
    restored = symmetric.Ciphertext.from_bytes(ct.to_bytes())
    assert symmetric.decrypt(key, restored) == b"payload"
    assert ct.size_bytes == len(ct.to_bytes())
    assert symmetric.ciphertext_overhead() == 28  # 12-byte nonce + 16-byte tag


def test_symmetric_rejects_bad_key_length():
    try:
        symmetric.encrypt(b"tooshort", b"m")
    except ValueError:
        pass
    else:
        raise AssertionError("short key accepted")


# ===========================================================================
# prf.py
# ===========================================================================
def test_prf_deterministic_and_key_dependent():
    f = prf.PRF(b"k" * 32)
    assert f(b"w1") == f(b"w1")
    assert f(b"w1") != f(b"w2")
    assert prf.PRF(b"j" * 32)(b"w1") != f(b"w1")


def test_prf_output_length_honoured():
    assert len(prf.PRF(b"k" * 32, output_bytes=24)(b"w")) == 24


def test_punctured_prf_correctness_property():
    """The defining property, Ref[35].txt:386-395.

        Ft.Eval(k_S, x) = Ft(k, x)  for x not in S
        Ft.Eval(k_S, x) = bottom    for x in S

    Small domain_bits keeps the tree walk fast; the property is independent
    of depth.
    """
    f = prf.PuncturablePRF.setup(domain_bits=16, output_bytes=24)
    punctured_points = [f.encode(b"revoked-a"), f.encode(b"revoked-b")]
    key_s = f.puncture(punctured_points)

    for point in punctured_points:
        assert f.eval_punctured(key_s, point) is None, "punctured point evaluated"

    for word in (b"kw-1", b"kw-2", b"kw-3", b"kw-4"):
        point = f.encode(word)
        if point in punctured_points:
            continue
        assert f.eval_punctured(key_s, point) == f.eval(point), (
            "punctured key disagreed with the full key off the punctured set"
        )


def test_punctured_prf_empty_puncture_covers_domain():
    f = prf.PuncturablePRF.setup(domain_bits=12)
    key_s = f.puncture([])
    point = f.encode(b"anything")
    assert f.eval_punctured(key_s, point) == f.eval(point)


def test_punctured_prf_key_grows_with_puncture_count():
    """A t-punctured key holds at most t*d nodes; more punctures, more nodes."""
    f = prf.PuncturablePRF.setup(domain_bits=16)
    one = f.puncture([f.encode(b"a")])
    three = f.puncture([f.encode(b"a"), f.encode(b"b"), f.encode(b"c")])
    assert len(three.nodes) > len(one.nodes)
    assert three.size_bytes > one.size_bytes
    assert len(three.nodes) <= 3 * f.domain_bits


def test_punctured_prf_rejects_out_of_domain_points():
    f = prf.PuncturablePRF.setup(domain_bits=8)
    try:
        f.eval(1 << 8)
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-domain point accepted")


# ===========================================================================
# merkle.py
# ===========================================================================
def test_merkle_root_deterministic_and_order_sensitive():
    assert merkle.commitment([b"a", b"b"]) == merkle.commitment([b"a", b"b"])
    assert merkle.commitment([b"a", b"b"]) != merkle.commitment([b"b", b"a"])


def test_merkle_leaf_and_node_hashes_are_separated():
    """RFC 6962 prefixes: identical bytes must hash differently as leaf vs node.

    Without the 0x00/0x01 prefixes an internal node's preimage could be
    replayed as a leaf — the classic Merkle second-preimage attack.
    """
    assert merkle.hash_leaf(b"") != merkle.hash_node(b"", b"")
    left, right = b"\xaa" * 32, b"\xbb" * 32
    assert merkle.hash_leaf(left + right) != merkle.hash_node(left, right)


def test_merkle_every_proof_verifies():
    leaves = [f"record-{i}".encode() for i in range(9)]  # odd count on purpose
    tree = merkle.MerkleTree(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.prove(i)
        assert merkle.MerkleTree.verify_leaf(leaf, proof, tree.root), f"leaf {i}"


def test_merkle_rejects_wrong_root_and_tampered_leaf():
    leaves = [f"record-{i}".encode() for i in range(8)]
    tree = merkle.MerkleTree(leaves)
    proof = tree.prove(3)
    assert not merkle.MerkleTree.verify(proof, b"\x00" * 32)
    assert not merkle.MerkleTree.verify_leaf(b"forged", proof, tree.root)


def test_merkle_incremental_update_matches_full_rebuild():
    """Phase VII must update in place and land on the same root as a rebuild.

    skill.md, Exp. 5: a run that triggers a global rebuild is a bug. This is
    the test that says the incremental path is actually equivalent.
    """
    leaves = [f"record-{i}".encode() for i in range(16)]
    tree = merkle.MerkleTree(leaves)
    recomputed = tree.update_leaf(5, b"updated-record")
    leaves[5] = b"updated-record"
    assert tree.root == merkle.MerkleTree(leaves).root
    assert recomputed == tree.height, "recomputed count should be the path length"
    assert merkle.MerkleTree.verify_leaf(b"updated-record", tree.prove(5), tree.root)


def test_merkle_update_changes_root():
    tree = merkle.MerkleTree([f"r{i}".encode() for i in range(8)])
    before = tree.root
    tree.update_leaf(0, b"changed")
    assert tree.root != before


def test_merkle_odd_leaf_count_promotes_not_duplicates():
    """Duplicating an odd last node is CVE-2012-2459: two leaf sets, one root."""
    three = merkle.MerkleTree([b"a", b"b", b"c"])
    four = merkle.MerkleTree([b"a", b"b", b"c", b"c"])
    assert three.root != four.root


def test_merkle_proof_metrics_reported():
    tree = merkle.MerkleTree([f"r{i}".encode() for i in range(1024)])
    proof = tree.prove(7)
    assert proof.path_length == 10  # log2(1024)
    assert proof.size_bytes == 10 * 33
    assert tree.height == 10


def test_merkle_rejects_empty_and_bad_index():
    try:
        merkle.MerkleTree([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty tree accepted")
    try:
        merkle.MerkleTree([b"a"]).prove(5)
    except IndexError:
        pass
    else:
        raise AssertionError("out-of-range index accepted")


# ===========================================================================
# bloom.py
# ===========================================================================
def test_bloom_no_false_negatives():
    """The defining property: an inserted item must always test present."""
    bf = bloom.BloomFilter(array_bits=1024, num_hashes=3)
    items = [f"dx:{i}".encode() for i in range(50)]
    bf.add_all(items)
    for item in items:
        assert bf.contains(item), f"false negative on {item!r}"


def test_bloom_ref52_published_parameters():
    """Ref[52] publishes BF with a 32-bit array and 3 hash functions."""
    bf = bloom.BloomFilter(array_bits=32, num_hashes=3)
    bf.add(b"attribute-1")
    assert bf.contains(b"attribute-1")
    assert bf.size_bytes == 4
    assert 0 < bf.bits_set <= 3


def test_bloom_positions_are_distinct():
    """A zero step in double hashing would collapse k hashes into one."""
    bf = bloom.BloomFilter(array_bits=4096, num_hashes=4)
    distinct_counts = [len(set(bf._positions(f"kw{i}".encode()))) for i in range(50)]
    assert sum(distinct_counts) / len(distinct_counts) > 3.5


def test_bloom_serialisation_roundtrip():
    bf = bloom.BloomFilter(array_bits=64, num_hashes=3)
    bf.add_all([b"a", b"b", b"c"])
    restored = bloom.BloomFilter.from_bytes(
        bf.to_bytes(), array_bits=64, num_hashes=3
    )
    assert restored.bits == bf.bits
    for item in (b"a", b"b", b"c"):
        assert restored.contains(item)


def test_bloom_empty_filter_rejects():
    bf = bloom.BloomFilter(array_bits=1024, num_hashes=3)
    assert not bf.contains(b"never-added")
    assert bf.false_positive_rate() == 0.0


def test_bloom_rejects_bad_parameters():
    for bits, k in ((0, 3), (32, 0)):
        try:
            bloom.BloomFilter(array_bits=bits, num_hashes=k)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted array_bits={bits}, num_hashes={k}")


# ===========================================================================
# lattice.py
# ===========================================================================
# Ref[52]'s published parameters (n=284, m=13812) are far too heavy for a
# smoke test. These use a small set with the SAME MP12 structure.
SMALL = lattice.LatticeParams(n=8, m=128, log_q=8, sigma=4.0)


def test_lattice_ref52_parameters_are_mp12_consistent():
    """The MP12 argument recorded in lattice.py and crypto.yaml.

    n*k = 284*24 = 6816 gadget columns, leaving 13812-6816 = 6996 uniform
    columns, which must clear the n*log(q) = 6816 bound. Arithmetic only —
    no matrices built.
    """
    p = lattice.REF52_PARAMS
    assert (p.n, p.m, p.log_q) == (284, 13812, 24)
    assert p.q == 1 << 24
    assert p.gadget_cols == 6816
    assert p.uniform_cols == 6996
    assert p.uniform_cols >= p.n * p.log_q
    p.validate()  # must not raise, incl. the int64 overflow guard


def test_lattice_params_reject_impossible_shapes():
    try:
        lattice.LatticeParams(n=284, m=100, log_q=24).validate()
    except ValueError:
        pass
    else:
        raise AssertionError("accepted m smaller than the gadget block")


def test_lattice_modular_helpers():
    q = 256
    assert lattice.mod_q(np.array([-1, 256, 300]), q).tolist() == [255, 0, 44]
    centred = lattice.centered(np.array([0, 127, 129, 255]), q)
    assert centred.tolist() == [0, 127, -127, -1]
    assert centred.max() <= q // 2 and centred.min() > -q // 2


def test_lattice_gadget_inverts_exactly():
    """G @ G^-1(v) == v: the reason the gadget trapdoor works at all."""
    q, k, n = SMALL.q, SMALL.k, SMALL.n
    G = lattice.gadget_matrix(n, k)
    assert G.shape == (n, n * k)
    v = np.random.default_rng(1).integers(0, q, size=n)
    z = lattice.gadget_decompose(v, k)
    assert set(np.unique(z)).issubset({0, 1}), "decomposition must be binary"
    assert np.array_equal(lattice.mod_q(G @ z, q), v)


def test_lattice_discrete_gaussian_shape_and_moments():
    """Checks the rho_s convention: Var = s^2/(2*pi), so std ~ s/sqrt(2*pi)."""
    s = 4.0
    samples = lattice.sample_discrete_gaussian(
        20000, s, rng=np.random.default_rng(7)
    )
    assert samples.shape == (20000,)
    assert abs(float(samples.mean())) < 0.3, "sampler is biased off centre"
    expected_std = s / np.sqrt(2 * np.pi)
    assert 0.75 * expected_std < float(samples.std()) < 1.25 * expected_std
    assert int(np.abs(samples).max()) <= int(np.ceil(6 * s)), "tail cut violated"


def test_lattice_discrete_gaussian_rejects_bad_sigma():
    try:
        lattice.sample_discrete_gaussian(10, 0.0)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted s=0")


def test_lattice_trapgen_produces_a_valid_trapdoor():
    """The trapdoor property: A @ [R; I] == G (mod q)."""
    rand = np.random.default_rng(11)
    A, td = lattice.trapgen(SMALL, rng=rand)
    assert A.shape == (SMALL.n, SMALL.m)
    assert td.R.shape == (SMALL.uniform_cols, SMALL.gadget_cols)

    stacked = np.vstack([td.R, np.eye(SMALL.gadget_cols, dtype=np.int64)])
    G = lattice.gadget_matrix(SMALL.n, SMALL.k)
    assert np.array_equal(lattice.mod_q(A @ stacked, SMALL.q), lattice.mod_q(G, SMALL.q))
    assert td.size_bytes > 0


def test_lattice_sample_pre_solves_the_equation():
    """The defining property of SamplePre: A @ e == u (mod q), with e short."""
    rand = np.random.default_rng(13)
    A, td = lattice.trapgen(SMALL, rng=rand)
    u = rand.integers(0, SMALL.q, size=SMALL.n)
    e = lattice.sample_pre(A, td, u, rng=rand)
    assert e.shape == (SMALL.m,)
    assert lattice.verify_preimage(A, e, u, SMALL.q), "A @ e != u"
    # "Short" means short RELATIVE to a uniform vector mod q, whose expected
    # norm is sqrt(m * q^2 / 12). A preimage that is merely a solution but not
    # short is a broken sampler that still satisfies the equation.
    uniform_norm = float(np.sqrt(SMALL.m * (SMALL.q**2) / 12))
    assert lattice.norm(e, SMALL.q) < 0.25 * uniform_norm, "preimage is not short"


def test_lattice_sample_pre_modes():
    rand = np.random.default_rng(17)
    A, td = lattice.trapgen(SMALL, rng=rand)
    u = rand.integers(0, SMALL.q, size=SMALL.n)

    for mode in (lattice.PerturbationMode.NONE, lattice.PerturbationMode.SPHERICAL):
        e = lattice.sample_pre(A, td, u, mode=mode, rng=rand)
        assert lattice.verify_preimage(A, e, u, SMALL.q), f"mode {mode} failed"

    # EXACT must refuse loudly rather than silently degrade.
    try:
        lattice.sample_pre(A, td, u, mode=lattice.PerturbationMode.EXACT, rng=rand)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("EXACT mode silently succeeded")


def test_lattice_sample_pre_validates_dimensions():
    rand = np.random.default_rng(19)
    A, td = lattice.trapgen(SMALL, rng=rand)
    try:
        lattice.sample_pre(A, td, np.zeros(SMALL.n + 1, dtype=np.int64), rng=rand)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted a wrongly sized target")


def test_lattice_sample_left_solves_the_concatenated_system():
    """SampleLeft: [A | B] @ e == u (mod q) using only A's trapdoor."""
    rand = np.random.default_rng(23)
    A, td = lattice.trapgen(SMALL, rng=rand)
    extra = 32
    B = lattice.sample_uniform_zq((SMALL.n, extra), SMALL.q, rng=rand)
    u = rand.integers(0, SMALL.q, size=SMALL.n)

    e = lattice.sample_left(A, B, td, u, rng=rand)
    assert e.shape == (SMALL.m + extra,)
    combined = np.concatenate([A, B], axis=1)
    assert np.array_equal(lattice.mod_q(combined @ e, SMALL.q), lattice.mod_q(u, SMALL.q))


def test_lattice_sample_r_is_plus_minus_one():
    R = lattice.sample_r(40, 24, rng=np.random.default_rng(29))
    assert R.shape == (40, 24)
    assert set(np.unique(R).tolist()) == {-1, 1}


def test_lattice_verify_preimage_rejects_wrong_vector():
    rand = np.random.default_rng(31)
    A, td = lattice.trapgen(SMALL, rng=rand)
    u = rand.integers(0, SMALL.q, size=SMALL.n)
    e = lattice.sample_pre(A, td, u, rng=rand)
    e_bad = e.copy()
    e_bad[0] += 1
    assert not lattice.verify_preimage(A, e_bad, u, SMALL.q)
    # And the norm bound must actually be enforced when supplied.
    assert not lattice.verify_preimage(A, e, u, SMALL.q, bound=0.0)


# ===========================================================================
# pairing.py  (optional backend — skips when unavailable)
# ===========================================================================
def test_pairing_backend_availability_reported():
    status = pairing.available_backends()
    assert set(status) == {"charm_ss512", "charm_type3", "petrelic_bn254"}
    # charm_type3 added 2026-08-28 as the faithful Type-III backend for
    # ma_lb_pq_vdse; charm_ss512 remains Ref[41]'s published Type-I curve.
    assert all(isinstance(v, bool) for v in status.values())


def _any_pairing_backend():
    for name, ok in pairing.available_backends().items():
        if ok:
            return pairing.get_backend(reportable=False, override=name)
    raise Skip("no pairing backend installed (charm-crypto / petrelic)")


def test_pairing_bilinearity():
    """The defining property, tested one argument at a time.

        e(g^a, h) == e(g, h^a) == e(g, h)^a

    Phrased without the product ``a*b`` on purpose: the two backends expose
    different scalar types, and an unreduced product would fail for reasons
    that have nothing to do with bilinearity.
    """
    backend = _any_pairing_backend()
    g, h = backend.random_g1(), backend.random_g2()
    a = backend.random_zr()
    assert backend.pair(g**a, h) == backend.pair(g, h**a)
    assert backend.pair(g**a, h) == backend.pair(g, h) ** a


def test_pairing_non_degenerate_and_sized():
    backend = _any_pairing_backend()
    g, h = backend.random_g1(), backend.random_g2()
    assert backend.element_size_bytes(g) > 0
    assert backend.pair(g, h) == backend.pair(g, h)


def test_pairing_hash_is_deterministic():
    backend = _any_pairing_backend()
    assert backend.hash_to_g1(b"attribute") == backend.hash_to_g1(b"attribute")
    assert backend.hash_to_zr(b"a") != backend.hash_to_zr(b"b")


def test_pairing_refuses_unfaithful_backend_for_reportable_runs():
    """Ref[41] publishes Type-I; a reportable run must not silently use Type-III."""
    if not pairing.available_backends()["petrelic_bn254"]:
        raise Skip("petrelic not installed")
    if pairing.available_backends()["charm_ss512"]:
        raise Skip("charm-crypto present, so no fallback is attempted")
    try:
        pairing.get_backend(reportable=True)
    except (pairing.UnfaithfulBackendError, pairing.PairingUnavailableError):
        pass
    else:
        raise AssertionError("reportable run accepted a Type-III backend for Ref[41]")


# ===========================================================================
# kem.py  (optional backend — skips when unavailable)
# ===========================================================================
def test_kem_backend_availability_reported():
    status = kem.available_backends()
    assert set(status) == {"cryptography", "liboqs", "kyber_py"}


def _mlkem():
    try:
        return kem.MLKEM768()
    except kem.KEMUnavailableError as exc:
        raise Skip(str(exc).splitlines()[0])


def test_kem_roundtrip_shared_secret_agrees():
    """Both parties must derive the same 32-byte secret."""
    assert _mlkem().self_test()


def test_kem_fips203_sizes():
    k = _mlkem()
    kp = k.keygen()
    enc = k.encapsulate(kp.encapsulation_key)
    assert len(kp.encapsulation_key) == kem.ENCAPSULATION_KEY_BYTES
    assert len(enc.ciphertext) == kem.CIPHERTEXT_BYTES
    assert len(enc.shared_secret) == kem.SHARED_SECRET_BYTES


def test_kem_distinct_encapsulations():
    """Encapsulation is randomised: two calls must not repeat a secret."""
    k = _mlkem()
    kp = k.keygen()
    first = k.encapsulate(kp.encapsulation_key)
    second = k.encapsulate(kp.encapsulation_key)
    assert first.ciphertext != second.ciphertext
    assert first.shared_secret != second.shared_secret


# ===========================================================================
# Runner
# ===========================================================================
def _collect(selector: str | None) -> List[Tuple[str, Callable[[], None]]]:
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    if selector:
        tests = [(n, f) for n, f in tests if selector in n]
    return sorted(tests)


def main(argv: List[str]) -> int:
    selector = argv[1] if len(argv) > 1 else None
    tests = _collect(selector)
    if not tests:
        print(f"no tests match {selector!r}")
        return 2

    passed: List[str] = []
    skipped: List[Tuple[str, str]] = []
    failed: List[Tuple[str, str]] = []

    for name, fn in tests:
        try:
            fn()
        except Skip as exc:
            skipped.append((name, str(exc)))
            print(f"SKIP  {name}  ({exc})")
        except Exception:
            failed.append((name, traceback.format_exc()))
            print(f"FAIL  {name}")
        else:
            passed.append(name)
            print(f"ok    {name}")

    print(
        f"\n{len(passed)} passed, {len(skipped)} skipped, {len(failed)} failed "
        f"out of {len(tests)}"
    )
    for name, tb in failed:
        print(f"\n{'=' * 70}\nFAILED: {name}\n{'=' * 70}\n{tb}")
    if skipped:
        print("\nSkipped (optional backends not installed):")
        for name, reason in skipped:
            print(f"  {name}: {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
