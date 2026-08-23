# Ref[52] Implementation Report — Zhuang Lattice MA-BSE

> **Paper:** Zhuang et al., "Multi-Authority Attribute-Based Multi-Keyword Searchable Encryption with Dynamic Membership from Lattices", IEEE DSC 2025
>
> **Date:** 2026-08-06
>
> **Status:** Construction complete, correctness verified, experiment harnesses ready

---

## 1. What Was Built

A full implementation of the Ref[52] cryptographic construction and five experiment harnesses, totalling **25 Python source files**.

### Files Created

| # | File | Purpose | Size |
|---|------|---------|------|
| 1 | `src/__init__.py` | Package marker | 197 B |
| 2 | `src/params.py` | Parameter loading from `crypto.yaml` + hash functions H0, Hi | 4.5 KB |
| 3 | `src/access_tree.py` | AND/OR gate access tree evaluator (Section II.B) | 4.6 KB |
| 4 | `src/harness.py` | Experiment measurement utilities (CSV, JSON, 95% CI) | 8.0 KB |
| 5 | `src/main.py` | CLI entry point | 2.9 KB |
| 6 | `src/test_construction.py` | Correctness roundtrip test | 5.5 KB |
| 7 | `src/construction/__init__.py` | Re-exports all 9 phases | 1.4 KB |
| 8 | `src/construction/p1_setup.py` | Phase 1 — System Setup (Section III.A) | 2.0 KB |
| 9 | `src/construction/p2_aa_setup.py` | Phase 2 — Authority Setup (Section III.B) | 2.0 KB |
| 10 | `src/construction/p3_enroll.py` | Phase 3 — User Enrollment (Section III.C) | 4.3 KB |
| 11 | `src/construction/p4_revoke.py` | Phase 4 — Attribute Revocation (Section III.D) | 1.6 KB |
| 12 | `src/construction/p5_extend.py` | Phase 5 — Attribute Extension (Section III.E) | 1.8 KB |
| 13 | `src/construction/p6_encrypt.py` | Phase 6 — Encryption (Section III.F) | 6.3 KB |
| 14 | `src/construction/p7_token_gen.py` | Phase 7 — Token Generation (Section III.G) | 3.4 KB |
| 15 | `src/construction/p8_search.py` | Phase 8 — Search (Section III.H) | 4.2 KB |
| 16 | `src/construction/p9_decrypt.py` | Phase 9 — Decryption (Section III.I) | 3.9 KB |
| 17 | `exp1_trapdoor_generation/__init__.py` | Package marker | — |
| 18 | `exp1_trapdoor_generation/runner.py` | Exp 1 runner | 3.2 KB |
| 19 | `exp2_search_latency/__init__.py` | Package marker | — |
| 20 | `exp2_search_latency/runner.py` | Exp 2 runner | 3.6 KB |
| 21 | `exp3_crossdomain_scalability/__init__.py` | Package marker | — |
| 22 | `exp3_crossdomain_scalability/runner.py` | Exp 3 runner | 3.5 KB |
| 23 | `exp5_keyword_update/__init__.py` | Package marker | — |
| 24 | `exp5_keyword_update/runner.py` | Exp 5 runner | 4.0 KB |
| 25 | `exp6_authorization_sync/__init__.py` | Package marker | — |
| 26 | `exp6_authorization_sync/runner.py` | Exp 6 runner | 3.6 KB |

### Folder Structure

```
Schemes/zhuang_lattice_mabse/
│
├── SCHEME.md                              ← Pre-existing experiment guide
├── IMPLEMENTATION_REPORT.md               ← This file
│
├── src/
│   ├── __init__.py
│   ├── params.py                          ← All parameters from crypto.yaml
│   ├── access_tree.py                     ← AND/OR gate policy trees
│   ├── harness.py                         ← Measurement loop + output writers
│   ├── main.py                            ← CLI entry point
│   ├── test_construction.py               ← Correctness test
│   │
│   └── construction/                      ← THE 9 ALGORITHMS FROM Section III
│       ├── __init__.py
│       ├── p1_setup.py                    ← Section III.A  Setup
│       ├── p2_aa_setup.py                 ← Section III.B  AASetup
│       ├── p3_enroll.py                   ← Section III.C  Enroll
│       ├── p4_revoke.py                   ← Section III.D  Revoke
│       ├── p5_extend.py                   ← Section III.E  Extend
│       ├── p6_encrypt.py                  ← Section III.F  Encrypt
│       ├── p7_token_gen.py                ← Section III.G  TokenGen
│       ├── p8_search.py                   ← Section III.H  Search
│       └── p9_decrypt.py                  ← Section III.I  Decrypt
│
├── exp1_trapdoor_generation/              ← Experiment 1
│   ├── __init__.py
│   └── runner.py
│
├── exp2_search_latency/                   ← Experiment 2
│   ├── __init__.py
│   └── runner.py
│
├── exp3_crossdomain_scalability/          ← Experiment 3
│   ├── __init__.py
│   └── runner.py
│
├── exp5_keyword_update/                   ← Experiment 5
│   ├── __init__.py
│   └── runner.py
│
└── exp6_authorization_sync/               ← Experiment 6
    ├── __init__.py
    └── runner.py
```

---

## 2. The 9 Construction Phases

Each phase maps directly to one algorithm in Section III of the paper:

### Phase 1 — Setup (`p1_setup.py`)

**Paper reference:** Section III.A, lines 222-247

**What it does:** Generates global public parameters `GP = {q, n, m, sigma, H0, {Hi}, D, U, L, chi, u}`

**Key operations:**
- Reads parameters from `crypto.yaml` (not hardcoded)
- Generates random target vector `u in Z_q^n`
- Initializes authority and attribute ID sets

**Data structures:**
```python
@dataclass
class GlobalParams:
    params: SchemeParams        # from crypto.yaml
    u_vector: np.ndarray        # u in Z_q^n
    authority_ids: List[int]    # D
    attribute_ids: List[int]    # U
    user_ids: List[str]         # L
```

---

### Phase 2 — AASetup (`p2_aa_setup.py`)

**Paper reference:** Section III.B, lines 248-265

**What it does:** Each attribute authority generates its public/master key pair

**Key operations:**
- For each attribute a_i in U_d: runs `TrapGen(n, m, q, sigma)` producing `(A_{d,i}, T_{A_{d,i}})`
- Public key `PK_d = {A_{d,i}}` is published
- Master key `MK_d = {T_{A_{d,i}}}` is kept secret

**Uses from Common/crypto:** `lattice.trapgen()`

---

### Phase 3 — Enroll (`p3_enroll.py`)

**Paper reference:** Section III.C, lines 266-329

**What it does:** Registers a user under an authority, generating delegated keys

**Key operations:**
- For attributes user **has**: generates `(B, T_B)` key pair
- For attributes user **lacks**: generates random `B` (no trapdoor, user cannot use it)
- Returns partial private key `SK^ID_d = {T_B}`

**Important implementation note:** The paper uses `BasisDel(A, R, T_A, sigma)` to derive `B = A R^{-1}` and its trapdoor. We use independent `TrapGen` instead. See Section 5 Design Decisions below for full explanation.

---

### Phase 4 — Revoke (`p4_revoke.py`)

**Paper reference:** Section III.D, lines 330-352

**What it does:** Revokes an attribute from a user

**Key operations:**
- Replace `B^ID_{d,t}` with a fresh random matrix
- Delete user's trapdoor and cached preimage for that attribute
- New ciphertexts using the updated public key will be undecryptable by the revoked user

---

### Phase 5 — Extend (`p5_extend.py`)

**Paper reference:** Section III.E, lines 353-409

**What it does:** Grants a new attribute to an existing user

**Key operations:**
- Same as Enroll for a single attribute
- Generates new `(B, T_B)` pair
- Updates public info and private key

---

### Phase 6 — Encrypt (`p6_encrypt.py`)

**Paper reference:** Section III.F, lines 412-504

**What it does:** Encrypts one bit `b` with a keyword search index under access policy `tau`

**Key equations implemented:**

| Eq. | Formula | Description |
|-----|---------|-------------|
| (1) | `C = u^T s1 * r + b * floor(q/2) + x` | Message ciphertext (scalar) |
| (2) | `C^ID_{d,i} = (B^ID_{d,i})^T * s1 * r_i + x_{1,i}` | Per-user per-attribute partial CT (m-vector) |
| (3) | `I_{1,theta} = u^T * s2 * r + w_theta * floor(q/2) + x_l` | Bloom bit encoding (scalar per bit) |
| (4) | `I^ID_{d,i} = [B\|K]^T * s2 * r_i + x_{2,i}` | Per-user per-attribute index (2m-vector) |

**Bloom filter:** Built using `Common/crypto/bloom.py` with `BF(32, 3)` (32-bit array, 3 hashes)

**Access tree shares:** AND gate uses additive shares summing to `r`; OR gate gives each child `r`

---

### Phase 7 — TokenGen (`p7_token_gen.py`)

**Paper reference:** Section III.G, lines 508-581

**What it does:** User generates a search token independently (offline KGC)

**Key operations:**
1. `K' = H0(k'_0)` — hash keyword category to `n x m` matrix
2. Build Bloom filter `w'` from search keywords
3. For each held attribute: `SampleLeft(B, K', T_B, u, sigma)` producing `k^ID_{d,i} in Z_q^{2m}`

**This is the timed operation for Experiment 1.**

**Uses from Common/crypto:** `lattice.sample_left()`

---

### Phase 8 — Search (`p8_search.py`)

**Paper reference:** Section III.H, lines 582-643

**What it does:** Cloud server checks if search keywords are a subset of ciphertext keywords

**Key operations:**
- **AND gates:** `S = sum(k^T * I)` computed once (l dot products of 2m-vectors), then `w'_theta = I_{1,theta} - S` for each Bloom bit
- **OR gates:** use any one attribute's token
- Threshold: `|w'_theta - floor(q/2)| < floor(q/4)` gives 1, else 0
- Bloom containment: `(w_search & w_ciphertext) == w_search`

**Cost:** `l * Tmul8 = 0.18 ms` per record (Table VI)

---

### Phase 9 — Decrypt (`p9_decrypt.py`)

**Paper reference:** Section III.I, lines 644-710

**What it does:** Recovers the plaintext bit from a ciphertext

**Key operations:**
1. Preimages `e` cached: `SamplePre(B, T_B, u, sigma)` producing `e` where `B*e = u mod q` (computed once, reused)
2. **AND:** `b' = C - sum(e_i^T * C_i)` using l inner products
3. **OR:** `b' = C - (e_i^T * C_i)` using one inner product
4. Threshold: close to `floor(q/2)` gives bit=1, close to 0 gives bit=0

**Cost:** `l * Tmul5 = 0.12 ms` per ciphertext (Table VI)

---

## 3. The 5 Experiments

| Exp | Name | Variable | Range | Primary Metric | Secondary |
|-----|------|----------|-------|---------------|-----------|
| 1 | Trapdoor Generation | keywords `q` | 1 to 20 | TokenGen latency (ms) | token size (bytes) |
| 2 | Search Latency | index size `N` | 10^4 to 10^6 | search latency (ms) | n_eff, prune ratio |
| 3 | Cross-Domain | domains `d` | 2 to 10 | total latency (ms) | trapdoors issued |
| 5 | Keyword Update | pairs `k` | 10^2 to 10^5 | update latency (ms) | entries rewritten |
| 6 | Auth Sync | updates `delta` | 10^2 to 10^5 | sync latency (ms) | message size (KB) |

### Measurement Methodology (README Section 7)

- **30 measured runs** after 5 discarded warm-ups
- **`time.perf_counter_ns()`** for latency
- **95% CI** via Student's t-distribution (scipy)
- **No outlier deletion** — all runs retained
- **Output:** `raw_runs.csv` + `results.csv` + `run_meta.json` per experiment

### Experiment Details

**Exp 1 — TokenGen latency vs keywords:**
The SampleLeft cost (dominant) is independent of keyword count `q` — only the Bloom filter hashing scales with `q`. Curve should be roughly flat, showing this scheme's token generation does not scale with query size.

**Exp 2 — Search latency vs index size:**
Linear scan — each record costs `l * Tmul8`. Times N repetitions of the search check operation.

**Exp 3 — Cross-domain (native mode):**
This scheme has NO native cross-domain support. Runs `d` independent TokenGen + Search operations with client-side aggregation. Latency scales linearly with `d`.

**Exp 5 — Keyword update:**
Incremental re-encryption of changed index entries. Each update rebuilds the Bloom filter and recomputes Eq. (3) and (4) for the modified entry.

**Exp 6 — Authorization sync:**
Alternating Revoke + Extend cycles. Revoke is cheap (random matrix generation). Extend is expensive (TrapGen for new key pair).

---

## 4. Published Parameters (Table III)

All loaded from `Experiment Configuration/crypto.yaml` — **nothing hardcoded**.

| Parameter | Symbol | Value | Source |
|-----------|--------|-------|--------|
| Security parameter | `n` | 284 | published |
| Basis dimension | `m` | 13,812 | published |
| Modulus | `q` | 2^24 = 16,777,216 | published |
| Gaussian width | `sigma` | 4.0 | benchmark (paper says "sigma > 0") |
| Attributes | `l` | 10 | published |
| Users | `u` | 50 | published |
| Keywords per CT | `w` | 5 | published |
| Bloom array bits | | 32 | published |
| Bloom hash functions | | 3 | published |

**Note on parameter naming:** Table III labels "h" for hashes and "k" for bloom array length, which swaps the `l`/`k` roles used in Section II.C's `BF(l, k)` definition. The code follows the **words** (32-bit array, 3 hashes).

---

## 5. Design Decisions

### 5.1 BasisDel replaced with TrapGen (Equivalent)

**Problem:** The paper's Enroll uses `R = SampleR(1^m)` to get `R in {-1,+1}^{m x m}`, then `B = A * R^{-1}` and `T_B = BasisDel(A, R, T_A)`.

At `m = 13,812`:
- `R` is 190M entries (~1.5 GB in int64)
- `det(R) = 0 (mod 2)` for any `m > 1` matrix with +/-1 entries, so **R is never invertible over Z_{2^24}**
- The definition as written is **unrealizable** at these parameters

**Solution:** Use independent `TrapGen` per user-attribute pair. This produces an identically-distributed `(B, T_B)` — both are statistically close to uniform. The measured operations (TokenGen, Search, Decrypt) are indistinguishable.

**This does NOT weaken or strengthen the baseline.** It implements the same cryptographic functionality.

### 5.2 Modular Arithmetic Overflow Fix

**Problem:** `np.dot(e, C_i)` where `e` and `C_i` are `m`-vectors with entries up to `q = 2^24` produces values up to `m * q^2 = 13812 * 2^48 = ~2^62`, which can overflow int64.

**Solution:** Use Python big-int arithmetic:
```python
dot = sum(int(a) * int(b) for a, b in zip(e, C_i)) % q
```
Slower but correct. Applied in `p8_search.py` and `p9_decrypt.py`.

### 5.3 Preimage Caching for Fast Decrypt

**Observation:** The preimage vectors `e` in Decrypt satisfy `B*e = u mod q`. Since `B`, `u` are fixed per user-attribute pair, `e` is computed once at enrollment and cached. Per-ciphertext decrypt cost is just `l` inner products, matching the paper's Table VI formula.

### 5.4 Access Tree Policy for Experiments

**Choice:** AND-only policy (all `l` attributes required) for experiments. This matches the Table VI computation cost formula ("when tau is constructed by only AND gates"). Both AND and OR gates are fully implemented and tested.

### 5.5 H0 Hash Function Implementation

**Paper:** `H0 : {0,1}* -> Z_q^{n x m}` maps a keyword category bit to an `n x m` matrix.

**Implementation:** SHA-256 of the input produces a 256-bit seed, which seeds a numpy PRNG that generates `n*m` uniform values in `[0, q)`. This is a standard random-oracle instantiation. Since `k0 in {0,1}`, only two possible outputs exist — cached after first call.

---

## 6. Correctness Test Results

```
=== Ref[52] Construction Correctness Test ===

Phase 1: Setup...                              OK (0.000s)
Phase 2: AASetup...                            OK (0.004s)
Phase 3: Enroll...                             OK (0.004s)
  User 0 held: {(0, 1), (0, 2), (0, 0)}
  User 1 held: {(0, 0)}
  Policy: AND([0, 1, 2])
  User 0 satisfies: True
  User 1 satisfies: False
Phase 6: Encrypt...                            OK (0.001s)
  C = 1278
  Ciphertext components: 6
  Index vectors: 6
Phase 7: TokenGen (matching keywords)...       OK (0.001s)
  Token vectors: 3, Token size: 6016 bytes
Phase 8: Search (matching)...                  MATCH       [PASS]
Phase 7: TokenGen (different keywords)...      OK
Phase 8: Search (non-matching)...              NO MATCH    [PASS]
Phase 9: Decrypt (user 0)...                   bit=1       [PASS]
Phase 4: Revoke attribute 2...                 OK          [PASS]
Phase 5: Extend attribute 2 back...            OK          [PASS]

Overall: ALL PASS
```

Test uses small parameters (`n=4, m=120, q=2^12, sigma=1.5`) for speed. The published parameters (`n=284, m=13812, q=2^24, sigma=4.0`) are used for actual experiment runs.

---

## 7. Dependencies

Uses only what is already in the repo:

| Module | What it provides |
|--------|-----------------|
| `Common/crypto/lattice.py` | TrapGen, SamplePre, SampleLeft, SampleR, Gaussian sampling |
| `Common/crypto/bloom.py` | BloomFilter BF(32, 3) |
| `Common/crypto/hashes.py` | hash_to_zq (used by H0, Hi) |
| `Common/crypto/config.py` | Parameter loading from crypto.yaml |
| `numpy` | Matrix arithmetic |
| `scipy.stats` | Student's t for 95% CI |

**No modifications to any Common/ file.** The existing primitives were sufficient.

---

## 8. How to Use

### Quick correctness test
```powershell
python -m Schemes.zhuang_lattice_mabse.src.test_construction
```

### Run specific experiments
```powershell
python -m Schemes.zhuang_lattice_mabse.src.main `
    --experiment 1 `
    --runs 3
```

### Run all experiments (full benchmark)
```powershell
python -m Schemes.zhuang_lattice_mabse.src.main `
    --experiment 1,2,3,5,6 `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 30
```

### Output files per experiment

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run |
| `results.csv` | Aggregated means with 95% CI |
| `run_meta.json` | Git commit, dataset SHA-256, Python version, UTC timestamp |

---

## 9. What Was NOT Modified

- `README.md` — source of truth, never edited per AGENT_RULES
- `Common/crypto/lattice.py` — existing primitives sufficient
- `Common/crypto/bloom.py` — used as-is
- `Experiment Configuration/crypto.yaml` — parameters already correct
- `SCHEME.md` — experiment guide unchanged
- Any other scheme folder — isolation maintained per README Section 14

---

## 10. Known Limitations

1. **Memory at full parameters:** Each TrapGen produces a trapdoor R of ~364 MB. Ten trapdoors (one user, all attributes) = ~3.6 GB. Feasible on m6i.xlarge (16 GB) but not on 8 GB laptops.

2. **Python big-int dot products:** The overflow-safe dot product `sum(int(a)*int(b) for ...)` is ~10x slower than `np.dot`. At full parameters this matters for Search (Exp 2 at large N). A Cython or chunked-reduction approach would help.

3. **Encryption scales O(l*u):** With `l=10, u=50`, encryption computes 500 matrix-vector products. Table VI reports ~4741 ms. This is the honest cost of the published construction.

4. **Small-parameter test only:** The correctness test uses reduced parameters. Full-parameter correctness requires a machine with at least 16 GB RAM and ~minutes per TrapGen call.
