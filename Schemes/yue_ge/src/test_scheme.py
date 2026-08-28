"""Correctness tests for Ref[55] (Peony / Peony++).

These are written to FAIL when the construction is bypassed, not merely when it
crashes. The Zhuang baseline shipped a Search that compared plaintext Bloom
vectors and passed its own tests because nothing asserted that the cryptographic
path produced the answer, and nothing ever ran an unauthorized user. Every
security property claimed below therefore has a negative test:

  - a lower-level user must NOT see higher-level files (MLA, §V-A)
  - a deleted file must NOT come back (Type-II backward privacy, §VI)
  - a stale token must NOT open a later batch (forward privacy, §V-C)
  - Verify must REJECT a tampered result set (public verification, §VI-A)

Run:  python -m pytest Schemes/yue_ge/src/test_scheme.py -q
      python -m Schemes.yue_ge.src.test_scheme
"""

from __future__ import annotations

import sys
from typing import List, Tuple

from . import msre, peony, peony_plus
from .digest import ZERO_DIGEST, keccak256, xor_digest
from .index import EncryptedIndex
from .levels import (
    assign_level,
    levels_to_update_on_delete,
    user_can_access,
    visible_levels,
)
from .params import SchemeParams


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
def _params() -> SchemeParams:
    return SchemeParams.from_config()


def _corpus(n_files: int = 12) -> List[Tuple[int, int]]:
    """``(file_id, level)`` spread deterministically across the 3 levels."""
    return [(fid, (fid % 3) + 1) for fid in range(n_files)]


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def test_keccak256_is_not_sha3():
    """keccak256 must match Ethereum's vector, not NIST SHA3-256."""
    import hashlib

    empty = keccak256()
    # keccak256(b"") with our length-prefixing is not the bare vector, so test
    # the underlying primitive directly.
    from Crypto.Hash import keccak as _k

    bare = _k.new(digest_bits=256)
    bare.update(b"")
    assert bare.hexdigest() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ), "keccak256 vector mismatch"
    assert bare.digest() != hashlib.sha3_256(b"").digest(), (
        "keccak256 must differ from SHA3-256 — wrong padding would silently "
        "change every published digest"
    )
    assert len(empty) == 32


def test_xor_accumulator_is_order_independent_and_self_cancelling():
    """The two properties Verify's constant size depends on (§VI-A)."""
    a, b, c = keccak256(b"a"), keccak256(b"b"), keccak256(b"c")
    fwd = xor_digest(xor_digest(a, b), c)
    rev = xor_digest(xor_digest(c, b), a)
    assert fwd == rev, "XOR accumulator must be order-independent"
    assert xor_digest(fwd, c) == xor_digest(a, b), "XOR must self-cancel"
    assert xor_digest(a, a) == ZERO_DIGEST


def test_bloom_array_size_matches_published_formula():
    """``b = -d ln p / (ln 2)^2`` reproduces the paper's Table V storage.

    Table V gives BF storage for a *single* level at d=1000, h=5 as 3.540 KiB
    (level 3 — one array). b = -1000*ln(1e-4)/(ln2)^2 = 19171 bits = 2.34 KiB
    of raw array. The published figure is larger because it counts the stored
    filter with its metadata, so we assert the order of magnitude and the
    d-linearity the formula requires, not an exact byte match to a figure whose
    accounting the paper does not break down.
    """
    p = _params()
    b_1000 = p.bloom_array_bits(1000)
    b_10000 = p.bloom_array_bits(10000)
    assert 19_000 <= b_1000 <= 19_400, f"b(1000) = {b_1000}"
    # Linear in d — the property Table V exhibits across its four columns.
    assert abs(b_10000 / b_1000 - 10) < 0.01, "b must be linear in d"


# ---------------------------------------------------------------------------
# multilevel access policy — §V-A
# ---------------------------------------------------------------------------
def test_mla_policy():
    assert user_can_access(3, 1) and user_can_access(3, 3)
    assert not user_can_access(1, 2), "level-1 user must not reach level 2"
    assert visible_levels(2) == [1, 2]


def test_deletion_propagates_upward():
    """§VII-B: deleting a level-1 file touches all three arrays."""
    assert levels_to_update_on_delete(1, 3) == [1, 2, 3]
    assert levels_to_update_on_delete(3, 3) == [3]


def test_level_assignment_is_deterministic_and_balanced():
    levels = [assign_level(f"patient_{i}", 3) for i in range(3000)]
    assert levels == [assign_level(f"patient_{i}", 3) for i in range(3000)]
    for lvl in (1, 2, 3):
        share = levels.count(lvl) / len(levels)
        assert 0.28 < share < 0.39, f"level {lvl} share {share:.3f} unbalanced"


# ---------------------------------------------------------------------------
# MSRE — §IV
# ---------------------------------------------------------------------------
def test_msre_roundtrip_and_revocation():
    p = _params()
    lsk = msre.bgen(array_bits=4096, num_hashes=p.bloom_num_hashes,
                    access_levels=3, output_bytes=32, key_bytes=16)

    kept_tag, revoked_tag = b"tag-kept", b"tag-revoked"
    ct_kept = msre.enc(lsk, b"file-A", kept_tag)
    ct_revoked = msre.enc(lsk, b"file-B", revoked_tag)

    keys = msre.klrev(lsk, [(revoked_tag, 3)], levels=[3])
    skr = keys[3]

    assert msre.dec(lsk.prf, skr, ct_kept) == b"file-A", (
        "a non-revoked ciphertext must still decrypt"
    )
    assert msre.dec(lsk.prf, skr, ct_revoked) is None, (
        "a revoked ciphertext must be UNDECRYPTABLE — this is Type-II "
        "backward privacy; if it returns plaintext the primitive is broken"
    )


def test_msre_revocation_respects_levels():
    """A level-2 deletion must not be revoked in the level-1 filter."""
    p = _params()
    lsk = msre.bgen(array_bits=4096, num_hashes=p.bloom_num_hashes,
                    access_levels=3, output_bytes=32, key_bytes=16)
    tag = b"tag-level2"
    ct = msre.enc(lsk, b"file-C", tag)
    keys = msre.klrev(lsk, [(tag, 2)], levels=[1, 2, 3])

    assert msre.dec(lsk.prf, keys[2], ct) is None, "revoked at level 2"
    assert msre.dec(lsk.prf, keys[3], ct) is None, "and upward at level 3"
    assert msre.dec(lsk.prf, keys[1], ct) == b"file-C", (
        "level 1 never saw this file, so its filter must be untouched"
    )


# ---------------------------------------------------------------------------
# Peony — §V
# ---------------------------------------------------------------------------
def test_peony_prf_owner_and_server_agree():
    """``F{i}_{k_l}(w||st)`` must equal ``F.Eval(F.Cons(k_l,w), st, i)``."""
    p = _params()
    key = peony.keygen(p)
    st = key.state(1)
    for i in (1, 2, 3):
        owner = peony._f_level(key.level_keys[2], "asthma", st, i)
        server = peony.f_eval(peony.f_cons(key.level_keys[2], "asthma"), st, i)
        assert owner == server, f"F{i} owner/server mismatch"


def test_peony_search_returns_only_permitted_levels():
    p = _params()
    key = peony.keygen(p)
    index = EncryptedIndex()
    entries = _corpus(12)
    peony.update(p, key, index, 1, {"asthma": entries})

    for user_level in (1, 2, 3):
        tok = peony.token_gen(key, "asthma", user_level, batch_count=1)
        out = peony.search(tok, index)
        expected = {fid for fid, lvl in entries if lvl <= user_level}
        assert out.result_ids == expected, (
            f"level-{user_level} user got {sorted(out.result_ids)}, "
            f"expected {sorted(expected)}"
        )
        assert out.nodes_traversed > 0, "search must actually walk the list"


def test_peony_forward_privacy():
    """A token issued at batch 1 must not reach batch 2 (§V-C)."""
    p = _params()
    key = peony.keygen(p)
    index = EncryptedIndex()
    peony.update(p, key, index, 1, {"asthma": [(1, 3)]})

    stale = peony.token_gen(key, "asthma", 3, batch_count=1)
    peony.update(p, key, index, 2, {"asthma": [(2, 3)]})

    out = peony.search(stale, index)
    assert out.result_ids == {1}, (
        f"stale token reached batch 2: got {sorted(out.result_ids)} — "
        "forward privacy is broken"
    )
    fresh = peony.token_gen(key, "asthma", 3, batch_count=2)
    assert peony.search(fresh, index).result_ids == {1, 2}


def test_sparse_level_batch_is_a_documented_limitation():
    """A batch missing a level serves that level NOTHING — as published.

    This pins a limitation of Ref[55] itself, not of this implementation. Update
    line 5 masks each node with its own level key while Search line 5 derives
    only ``F3_{k_a(u)}``, so the entry node must sit at exactly the user's level;
    a batch with no file at level 2 therefore stores bottom for level 2, and a
    level-2 user cannot reach even the level-1 files in it.

    The paper never states the "every level populated per batch" assumption. At
    its own scale (2.2M files, 3 levels) it holds and the case never surfaces.

    Asserted as-is rather than repaired: AGENT_RULES forbids strengthening a
    baseline past its published construction. The condition is counted so runs
    surface it — see the ``sparse_levels`` assertion below.
    """
    p = _params()
    key = peony.keygen(p)
    index = EncryptedIndex()
    # Levels 3 and 1 only — nothing at level 2.
    batch = peony.update(p, key, index, 1, {"asthma": [(10, 3), (11, 1)]})

    assert batch.sparse_levels == 1, (
        f"expected exactly one bottom entry (level 2), got "
        f"{batch.sparse_levels} — the limitation must be COUNTED, not hidden"
    )

    got_l2 = peony.search(
        peony.token_gen(key, "asthma", 2, batch_count=1), index
    ).result_ids
    assert got_l2 == set(), (
        f"level-2 user got {sorted(got_l2)}; the published construction gives "
        f"them nothing from a batch with no level-2 file. A non-empty result "
        f"here means the baseline was silently strengthened."
    )

    # Levels that ARE present behave normally.
    assert peony.search(
        peony.token_gen(key, "asthma", 3, batch_count=1), index
    ).result_ids == {10, 11}
    assert peony.search(
        peony.token_gen(key, "asthma", 1, batch_count=1), index
    ).result_ids == {11}


def test_fully_populated_batches_have_no_sparse_levels():
    """The regime the benchmark actually runs in: every level present."""
    p = _params()
    key = peony.keygen(p)
    index = EncryptedIndex()
    batch = peony.update(p, key, index, 1, {"asthma": _corpus(12)})
    assert batch.sparse_levels == 0, (
        "a batch covering all levels must produce no bottom entries"
    )


def test_peony_wrong_keyword_returns_nothing():
    p = _params()
    key = peony.keygen(p)
    index = EncryptedIndex()
    peony.update(p, key, index, 1, {"asthma": _corpus(6)})
    tok = peony.token_gen(key, "diabetes", 3, batch_count=1)
    assert peony.search(tok, index).result_ids == set()


# ---------------------------------------------------------------------------
# Peony++ — §VI
# ---------------------------------------------------------------------------
def _plus_fixture(n_files: int = 9):
    p = _params()
    state, index, pl = peony_plus.setup(p)
    entries = _corpus(n_files)
    peony_plus.add(state, index, pl, 1, {"asthma": entries})
    return p, state, index, pl, entries


def test_peony_plus_search_roundtrip_and_levels():
    _, state, index, pl, entries = _plus_fixture()
    for user_level in (1, 2, 3):
        tok = peony_plus.token_gen(state, "asthma", user_level, 1)
        out = peony_plus.search(state, tok, index, "asthma")
        expected = {fid for fid, lvl in entries if lvl <= user_level}
        assert out.result_ids == expected, (
            f"level-{user_level}: got {sorted(out.result_ids)}, "
            f"expected {sorted(expected)}"
        )


def test_peony_plus_deletion_is_backward_private():
    _, state, index, pl, entries = _plus_fixture()
    victim = next(fid for fid, lvl in entries if lvl == 3)

    before = peony_plus.search(
        state, peony_plus.token_gen(state, "asthma", 3, 1), index, "asthma"
    ).result_ids
    assert victim in before

    peony_plus.delete(state, "asthma", [(victim, 3)])

    after = peony_plus.search(
        state, peony_plus.token_gen(state, "asthma", 3, 1), index, "asthma"
    ).result_ids
    assert victim not in after, (
        f"deleted file {victim} still returned — Type-II backward privacy "
        "is broken; the server must be UNABLE to decrypt it"
    )
    assert after == before - {victim}, "deletion must not disturb other files"


def test_peony_plus_verify_accepts_honest_result():
    _, state, index, pl, entries = _plus_fixture()
    tok = peony_plus.token_gen(state, "asthma", 3, 1)
    out = peony_plus.search(state, tok, index, "asthma")
    res = peony_plus.verify(state, pl, "asthma", 3, out.result_ids)
    assert res.accepted, (
        "Verify rejected an honest result set — the digest algebra is wrong"
    )
    assert res.entries_combined == 1


def test_peony_plus_verify_rejects_tampering():
    """The negative test that matters: a malicious server must be caught."""
    _, state, index, pl, entries = _plus_fixture()
    tok = peony_plus.token_gen(state, "asthma", 3, 1)
    honest = peony_plus.search(state, tok, index, "asthma").result_ids

    dropped = set(honest) - {min(honest)}
    assert not peony_plus.verify(
        state, pl, "asthma", 3, dropped
    ).accepted, "Verify accepted a result set with a file OMITTED"

    injected = set(honest) | {9999}
    assert not peony_plus.verify(
        state, pl, "asthma", 3, injected
    ).accepted, "Verify accepted a result set with a file INJECTED"


def test_peony_plus_verify_after_deletion():
    """Verify must still accept once deletions are folded in."""
    _, state, index, pl, entries = _plus_fixture()
    victim = next(fid for fid, lvl in entries if lvl == 3)
    peony_plus.delete(state, "asthma", [(victim, 3)])

    tok = peony_plus.token_gen(state, "asthma", 3, 1)
    out = peony_plus.search(state, tok, index, "asthma")
    res = peony_plus.verify(state, pl, "asthma", 3, out.result_ids)
    assert res.accepted, (
        "Verify rejected an honest post-deletion result set — proof_del is "
        "not cancelling correctly"
    )


def test_peony_plus_multi_batch():
    p = _params()
    state, index, pl = peony_plus.setup(p)
    peony_plus.add(state, index, pl, 1, {"asthma": [(1, 3), (2, 1)]})
    peony_plus.add(state, index, pl, 2, {"asthma": [(3, 2), (4, 3)]})

    tok = peony_plus.token_gen(state, "asthma", 3, 2)
    out = peony_plus.search(state, tok, index, "asthma")
    assert out.result_ids == {1, 2, 3, 4}
    assert out.batches_scanned == 2
    assert peony_plus.verify(state, pl, "asthma", 3, out.result_ids).accepted

    low = peony_plus.token_gen(state, "asthma", 1, 2)
    low_out = peony_plus.search(state, low, index, "asthma")
    assert low_out.result_ids == {2}, "level-1 user must see only level-1 files"
    assert peony_plus.verify(state, pl, "asthma", 1, low_out.result_ids).accepted


# ---------------------------------------------------------------------------
# manual entry point
# ---------------------------------------------------------------------------
def _main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}\n        {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}\n        {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
