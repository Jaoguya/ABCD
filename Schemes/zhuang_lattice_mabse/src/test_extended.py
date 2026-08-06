"""Extended validation: bit=0, bit=1, OR gates, subset search, revoke, multiple roundtrips."""
import numpy as np
from Common.crypto.lattice import LatticeParams

LP = LatticeParams(n=4, m=120, log_q=12, sigma=1.5)

from Schemes.zhuang_lattice_mabse.src.params import SchemeParams
from Schemes.zhuang_lattice_mabse.src.access_tree import make_and_policy, make_or_policy
from Schemes.zhuang_lattice_mabse.src.construction import (
    setup, aa_setup, enroll, revoke, extend, encrypt, token_gen, search, decrypt
)

print("=== EXTENDED VALIDATION ===")
print()

params = SchemeParams(lattice=LP, bloom_array_bits=32, bloom_num_hashes=3,
                       num_attributes=3, num_users=2, keywords_per_ct=3)
rng = np.random.default_rng(9999)
gp = setup(params, rng=rng)
attr_ids = [0, 1, 2]
auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)
user_pub, user_prv = enroll(gp, auth_pk, auth_mk, "u0", [0,1,2], rng=rng)
kw = [b"k1", b"k2", b"k3"]
results = []

# Test 1: Encrypt bit=0
print("Test 1: Encrypt bit=0, AND policy")
tree = make_and_policy(attr_ids)
ct0, idx0 = encrypt(gp, 0, 0, kw, tree, [user_pub], rng=rng)
d0 = decrypt(gp, ct0, tree, user_pub, user_prv, rng=rng)
ok = d0 == 0
results.append(ok)
print(f"  Decrypt: {d0} ... {'PASS' if ok else 'FAIL'}")

# Test 2: Encrypt bit=1
print("Test 2: Encrypt bit=1, AND policy")
tree = make_and_policy(attr_ids)
ct1, idx1 = encrypt(gp, 1, 0, kw, tree, [user_pub], rng=rng)
d1 = decrypt(gp, ct1, tree, user_pub, user_prv, rng=rng)
ok = d1 == 1
results.append(ok)
print(f"  Decrypt: {d1} ... {'PASS' if ok else 'FAIL'}")

# Test 3: 20 roundtrips
print("Test 3: 20 roundtrips (10x bit=0 + 10x bit=1)")
correct = 0
for bit in range(2):
    for _ in range(10):
        t = make_and_policy(attr_ids)
        # Clear preimage cache so each roundtrip is independent
        user_prv.preimages.clear()
        ct, ix = encrypt(gp, bit, 0, kw, t, [user_pub], rng=rng)
        d = decrypt(gp, ct, t, user_pub, user_prv, rng=rng)
        if d == bit:
            correct += 1
ok = correct == 20
results.append(ok)
print(f"  {correct}/20 correct ... {'PASS' if ok else 'FAIL'}")

# Test 4: OR policy
print("Test 4: OR policy (user has all attrs)")
or_tree = make_or_policy(attr_ids)
user_prv.preimages.clear()
ct_or, _ = encrypt(gp, 1, 0, kw, or_tree, [user_pub], rng=rng)
d_or = decrypt(gp, ct_or, or_tree, user_pub, user_prv, rng=rng)
ok = d_or == 1
results.append(ok)
print(f"  Decrypt: {d_or} ... {'PASS' if ok else 'FAIL'}")

# Test 5: Subset keyword search (search 2 of 3 keywords)
print("Test 5: Subset keyword search")
tree = make_and_policy(attr_ids)
ct_s, idx_s = encrypt(gp, 1, 0, kw, tree, [user_pub], rng=rng)
tok_sub = token_gen(gp, 0, [b"k1", b"k2"], user_pub, user_prv, rng=rng)
res_sub = search(gp, tok_sub, idx_s, tree, "u0")
ok = res_sub.matched
results.append(ok)
print(f"  Subset match: {res_sub.matched} ... {'PASS' if ok else 'FAIL'}")

# Test 6: Disjoint keyword search
print("Test 6: Disjoint keyword search")
tok_dis = token_gen(gp, 0, [b"x1", b"x2"], user_pub, user_prv, rng=rng)
res_dis = search(gp, tok_dis, idx_s, tree, "u0")
ok = not res_dis.matched
results.append(ok)
print(f"  Disjoint match: {res_dis.matched} ... {'PASS' if ok else 'FAIL'}")

# Test 7: Revoke removes attribute
print("Test 7: Revoke attribute 2")
revoke(gp, user_pub, user_prv, 0, 2, rng=rng)
ok = (0, 2) not in user_pub.held_attributes and (0, 2) not in user_prv.trapdoors
results.append(ok)
print(f"  Held after revoke: {user_pub.held_attributes} ... {'PASS' if ok else 'FAIL'}")

# Test 8: Extend restores attribute
print("Test 8: Extend restores attribute 2")
extend(gp, auth_pk, auth_mk, user_pub, user_prv, 2, rng=rng)
ok = (0, 2) in user_pub.held_attributes and (0, 2) in user_prv.trapdoors
results.append(ok)
print(f"  Held after extend: {user_pub.held_attributes} ... {'PASS' if ok else 'FAIL'}")

# Summary
passed = sum(results)
total = len(results)
print()
print(f"=== {passed}/{total} tests passed ===")
if passed < total:
    exit(1)
