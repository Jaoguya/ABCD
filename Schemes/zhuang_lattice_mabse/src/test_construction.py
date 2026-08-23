"""Quick correctness test for the Ref[52] construction.

Runs a minimal roundtrip: Setup → AASetup → Enroll → Encrypt → TokenGen → Search → Decrypt.
Uses reduced parameters to keep runtime manageable on a laptop.
"""
import sys
import time
import numpy as np

# Use small parameters for testing (full parameters take ~minutes per TrapGen)
# We'll monkey-patch to use n=8, m=48, q=2^10 for quick testing
from Common.crypto.lattice import LatticeParams

SMALL_PARAMS = LatticeParams(n=4, m=120, log_q=12, sigma=1.5)

from Schemes.zhuang_lattice_mabse.src.params import SchemeParams
from Schemes.zhuang_lattice_mabse.src.access_tree import make_and_policy, check_satisfaction
from Schemes.zhuang_lattice_mabse.src.construction.p1_setup import setup, GlobalParams
from Schemes.zhuang_lattice_mabse.src.construction.p2_aa_setup import aa_setup
from Schemes.zhuang_lattice_mabse.src.construction.p3_enroll import enroll
from Schemes.zhuang_lattice_mabse.src.construction.p4_revoke import revoke
from Schemes.zhuang_lattice_mabse.src.construction.p5_extend import extend
from Schemes.zhuang_lattice_mabse.src.construction.p6_encrypt import encrypt
from Schemes.zhuang_lattice_mabse.src.construction.p7_token_gen import token_gen
from Schemes.zhuang_lattice_mabse.src.construction.p8_search import search
from Schemes.zhuang_lattice_mabse.src.construction.p9_decrypt import decrypt


def test_roundtrip():
    """Full construction roundtrip with small parameters."""
    print("=== Ref[52] Construction Correctness Test ===")
    print()

    rng = np.random.default_rng(12345)

    # Build small params
    params = SchemeParams(
        lattice=SMALL_PARAMS,
        bloom_array_bits=32,
        bloom_num_hashes=3,
        num_attributes=3,   # small for testing
        num_users=2,
        keywords_per_ct=3,
    )

    # Phase 1: Setup
    print("Phase 1: Setup...", end=" ")
    t0 = time.perf_counter()
    gp = setup(params, rng=rng)
    print(f"OK ({time.perf_counter()-t0:.3f}s)")

    # Phase 2: AASetup (one authority, 3 attributes)
    print("Phase 2: AASetup...", end=" ")
    t0 = time.perf_counter()
    attr_ids = [0, 1, 2]
    auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)
    print(f"OK ({time.perf_counter()-t0:.3f}s)")

    # Phase 3: Enroll two users
    print("Phase 3: Enroll...", end=" ")
    t0 = time.perf_counter()
    # User 0 has all attributes
    user0_pub, user0_prv = enroll(gp, auth_pk, auth_mk, "user_0", [0, 1, 2], rng=rng)
    # User 1 has only attribute 0
    user1_pub, user1_prv = enroll(gp, auth_pk, auth_mk, "user_1", [0], rng=rng)
    print(f"OK ({time.perf_counter()-t0:.3f}s)")
    print(f"  User 0 held: {user0_pub.held_attributes}")
    print(f"  User 1 held: {user1_pub.held_attributes}")

    # Access policy: AND(0, 1, 2) — requires all 3 attributes
    access_tree = make_and_policy(attr_ids)
    print(f"  Policy: AND({attr_ids})")
    print(f"  User 0 satisfies: {check_satisfaction(access_tree, {a for _, a in user0_pub.held_attributes})}")
    print(f"  User 1 satisfies: {check_satisfaction(access_tree, {a for _, a in user1_pub.held_attributes})}")

    # Phase 6: Encrypt bit=1 with keywords
    print("Phase 6: Encrypt...", end=" ")
    keywords = [b"diagnosis_A", b"medication_B", b"lab_C"]
    t0 = time.perf_counter()
    ct, idx = encrypt(gp, 1, 0, keywords, access_tree, [user0_pub, user1_pub], rng=rng)
    print(f"OK ({time.perf_counter()-t0:.3f}s)")
    print(f"  C = {ct.C}")
    print(f"  Ciphertext components: {len(ct.C_components)}")
    print(f"  Index vectors: {len(idx.index_vectors)}")
    print(f"  Bloom vector: {idx.bloom_vector}")

    # Phase 7: TokenGen — user 0 searches for matching keywords
    print("Phase 7: TokenGen (user 0, matching keywords)...", end=" ")
    t0 = time.perf_counter()
    tok0 = token_gen(gp, 0, keywords, user0_pub, user0_prv, rng=rng)
    print(f"OK ({time.perf_counter()-t0:.3f}s)")
    print(f"  Token vectors: {len(tok0.token_vectors)}")
    print(f"  Token size: {tok0.size_bytes} bytes")

    # Phase 8: Search — should match
    print("Phase 8: Search (matching)...", end=" ")
    t0 = time.perf_counter()
    result = search(gp, tok0, idx, access_tree, "user_0")
    print(f"{'MATCH' if result.matched else 'NO MATCH'} ({time.perf_counter()-t0:.3f}s)")

    # Phase 7: TokenGen — user 0 searches for NON-matching keywords
    print("Phase 7: TokenGen (user 0, different keywords)...", end=" ")
    diff_keywords = [b"other_keyword"]
    tok0_diff = token_gen(gp, 0, diff_keywords, user0_pub, user0_prv, rng=rng)
    print("OK")

    # Phase 8: Search — should NOT match (different keywords)
    print("Phase 8: Search (non-matching)...", end=" ")
    result_diff = search(gp, tok0_diff, idx, access_tree, "user_0")
    print(f"{'MATCH' if result_diff.matched else 'NO MATCH'}")

    # Phase 9: Decrypt — user 0 (has all attributes)
    print("Phase 9: Decrypt (user 0)...", end=" ")
    t0 = time.perf_counter()
    recovered = decrypt(gp, ct, access_tree, user0_pub, user0_prv, rng=rng)
    print(f"bit={recovered} ({time.perf_counter()-t0:.3f}s)")

    # Phase 4: Revoke attribute 2 from user 0
    print("Phase 4: Revoke attribute 2 from user 0...", end=" ")
    revoke(gp, user0_pub, user0_prv, 0, 2, rng=rng)
    print(f"OK  held={user0_pub.held_attributes}")

    # Phase 5: Extend attribute 2 back to user 0
    print("Phase 5: Extend attribute 2 back to user 0...", end=" ")
    extend(gp, auth_pk, auth_mk, user0_pub, user0_prv, 2, rng=rng)
    print(f"OK  held={user0_pub.held_attributes}")

    # Summary
    print()
    print("=== Results ===")
    print(f"  Encrypt bit=1, Decrypt recovered: {recovered}")
    print(f"  Matching search:     {'PASS' if result.matched else 'FAIL'}")
    print(f"  Non-matching search: {'PASS' if not result_diff.matched else 'FAIL'}")
    print(f"  Decrypt correctness: {'PASS' if recovered == 1 else 'FAIL'}")

    all_pass = (recovered == 1) and result.matched and not result_diff.matched
    print(f"\n  Overall: {'ALL PASS' if all_pass else 'SOME FAILED'}")
    return all_pass


if __name__ == "__main__":
    ok = test_roundtrip()
    sys.exit(0 if ok else 1)
