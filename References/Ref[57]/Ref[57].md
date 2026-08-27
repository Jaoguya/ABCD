# Blockchain-Enabled Lattice-Based Attribute-Based Searchable Encryption with Instant Revocation

Zhishan Feng, Wenzhong Yang\*, Ying Hu\*, Yabo Yin, Tianqi Ma, Xiaodan Tian, Xiangxin Deng

*Electronics* (MDPI), vol. 15, no. 11, article 2471, 4 June 2026, pp. 1–50.
Received 2 May 2026; revised 23 May 2026; accepted 27 May 2026; published 4 June 2026.
School of Computer Science and Technology (School of Cyberspace Security), Xinjiang University, Urumqi 830046, China.
Open access, CC-BY. Funded by the Autonomous Region Science and Technology Plan Project (Grant No. ZYYD2025JD10).

Digital Object Identifier: **10.3390/electronics15112471**

*Keywords* — searchable encryption; lattice cryptography; ring learning with errors; attribute-based encryption; blockchain; threshold secret sharing

**Extraction note:** hand-transcribed via direct PDF read (no `marker` CLI available on the host, same limitation as `Ref[54].md`). Sampled ~30 of 50 pages (pp. 1–20 in full: intro, preliminaries, problem formalization, all five core algorithms; pp. 30–40: remaining security proofs + first half of evaluation; pp. 47–50: discussion, conclusion, references). Not a page-by-page transcription of every page — the omitted pages (21–29, 41–46) cover additional algorithms (RevokeAccess, UpdatePolicy, QueryAuditLog, smart contract pseudocode) and additional evaluation subsections (threshold parameter verification, blockchain throughput stress test, communication/storage overhead) referenced but not reproduced verbatim here.

---

## Abstract

As cloud computing proliferates, outsourced data faces severe security threats, yet existing searchable encryption (SE) schemes rely on classical hardness assumptions, centralized trust authorities, and static access control, leaving critical gaps in quantum resistance, single-point-of-failure prevention, and dynamic permission management. To address these limitations, we propose BL-ABSE, a blockchain-enhanced, lattice-based attribute-based searchable encryption framework. BL-ABSE employs the Ring Learning With Errors (RLWE) problem as its security foundation and applies the Number Theoretic Transform (NTT) to reduce polynomial multiplication from O(n²) to O(n log n). To eliminate single-point trust risks, the framework further integrates a (t,n) threshold key protocol across an edge-node consortium governed by Practical Byzantine Fault Tolerance (PBFT) consensus. A smart-contract-maintained on-chain revocation list enables permission withdrawal via a single blockchain transaction without re-encryption. Experimental evaluation demonstrates that commitment generation requires approximately 23 ms at n=1024, search latency scales linearly at roughly 29 μs per record, and revocation completes in approximately 2 s regardless of system scale. Formal security proofs under the quantum polynomial-time (QPT) adversary model reduce six security properties — index indistinguishability, query privacy, threshold key security, Byzantine fault tolerance, audit immutability, and revocation immediacy — to the hardness of RLWE and the Short Integer Solution (SIS) problems. To the best of our knowledge, BL-ABSE is the first framework to simultaneously achieve post-quantum security, attribute-based access control, decentralized key management, instant revocation, and immutable auditing within a single unified framework. We further conduct threshold parameter verification, end-to-end revocation latency decomposition, blockchain throughput stress testing, search-pattern leakage quantification, and communication/storage overhead analysis, providing a comprehensive evaluation of both performance and security trade-offs. We explicitly characterize the search-pattern leakage inherent in the deterministic commitment design as a correctness–privacy trade-off and discuss mitigation directions.

---

## 1. Introduction

Motivates via IBM Cost of a Data Breach Report 2024 ($4.88M average, 72% cloud-hosted). Identifies three systemic limitations of existing ABSE: (1) security based on discrete log/DBDH, broken by Shor's algorithm; (2) reliance on a single trusted authority for key generation and search, a single point of failure; (3) revocation via key redistribution or re-encryption, incurring hour-to-day latencies. Surveys prior lattice-based SE attempts (Zhang et al., Liu et al., Shen et al., Yang et al. — each addresses only a subset of the gaps) and blockchain-assisted revocation work (Wang et al.: O(users) key updates; Yu et al.: on-chain revocation but still requires re-encryption; Chen et al.: both major revocation strategies scale with system size).

**Five stated contributions:**
1. **Post-quantum-secure and efficient searchable encryption construction.** RLWE-based keyword commitment + NTT (O(n²)→O(n log n)), ~17× faster than naive at n=1024. Security reduces strictly to RLWE and SIS.
2. **Decentralized threshold key management.** (t,n) threshold protocol distributing the master key across an edge-node federation; key generation requires ≥t nodes + ZK proofs; PBFT tolerates ⌊(n−1)/3⌋ Byzantine nodes.
3. **Smart-contract-based instantaneous permission revocation.** Single blockchain transaction (~2s), no re-encryption/key redistribution, revocation latency reduced from hour-scale to second-scale.
4. **Tamper-proof operational audit log.** All critical operations (upload, key request, search, policy change, revocation) recorded on-chain with hash chaining.
5. **Rigorous formal security analysis.** Six properties proven under the QPT adversary model via sequential game reductions, all grounded in RLWE/SIS hardness.

Compared against 13 representative approaches; claims to be the first framework simultaneously achieving post-quantum security + ABE + decentralized key management + instant revocation + immutable auditing.

---

## 2. Preliminaries

**Table 1 — Notation:** λ=128 (security parameter, this paper), n=1024 (lattice dimension), q=12,289 (prime, q≡1 mod 2n), σ=3.2 (discrete Gaussian std dev), R_q=Z_q[x]/(x^n+1), (t,n) threshold, H/H_seed (keyword-encoding and seed-derivation hashes).

- **§2.2 Lattice foundations.** Standard Lattice, SVP, CVP definitions. LWE and RLWE definitions (Def. 2–3) — RLWE compresses key size O(n²)→O(n), supports O(n log n) multiplication via NTT. Discrete Gaussian distribution (Def. 4), σ=3.2 with n=1024, q=12,289 gives 128-bit PQ security.
- **§2.3 NTT.** Forward/inverse NTT definitions (Eq. 3–4) over R_q with primitive 2n-th root of unity ω. Negative-wrapped convolution via ψ=√ω to avoid a cyclic-vs-negacyclic mismatch. Practical acceleration: precomputed root-of-unity tables, bit-reversal permutation, Montgomery reduction.
- **§2.4 CP-ABE.** Standard four-algorithm definition (Setup/KeyGen/Encrypt/Decrypt); BL-ABSE's ABE component is lattice-based (LWE/RLWE-hard), not pairing-based.
- **§2.5 Blockchain.** Consortium chain, smart contract as a deterministic state-transition function (Eq. 5); three roles: access-policy management, revocation control, audit-log recording.
- **§2.6 Threshold secret sharing.** Shamir's scheme (Def. 8), information-theoretic security regardless of adversary compute power (including quantum).
- **§2.6 RLWE commitment (Construction 1).** `commit = a·s + H(w) mod q`, s deterministically derived via H_seed(w) — **not** from the user's private key. This is the load-bearing design choice: identical keywords always produce identical commitments (needed for non-interactive search matching), at the cost of leaking the search pattern (analyzed quantitatively in §5.9/§6.8).
  - **Theorem 2 (Binding, with full proof).** Reduces finding two keywords with equal commitments to Ring-SIS: if commit(w)=commit(w') for w≠w', then a·(s−s')=H(w')−H(w) mod q gives a short nonzero z=s−s' solving Ring-SIS. Proof given in full (not sketched).
- **§2.7 Security model.** Leakage-function framework L=(L_Setup, L_Encrypt, L_Search). IND-INDEX security (Def. 9) and IND-TRAPDOOR security (Def. 10) as standard indistinguishability games. Post-quantum security (Def. 11): same definitions hold with "QPT adversary" substituted for "PPT adversary."

---

## 3. Problem Formalization

### 3.1 System Model — six entities

1. **Data Owner (DO)** — submits raw data + keywords to the edge consortium, specifies access policy, registers policy on-chain.
2. **Data User (DU)** — obtains an attribute certificate from the AA, obtains a private key via threshold collaboration among edge nodes, generates search tokens, verifies returned proofs.
3. **Edge Node Association (ENA)** — the core improvement over prior single-edge-server designs: n edge nodes under a (t,n) threshold scheme, master key split into n shares, any t honest nodes can complete sensitive operations (key generation), fewer than t learn nothing.
4. **Cloud Storage Node (CSN)** — IPFS-based, content-addressed by CID; honest-but-curious.
5. **Blockchain Network (BCN)** — consortium chain on Hyperledger Fabric; on-chain policy registration/verification/update, revocation-list maintenance and immediate enforcement, tamper-proof audit logs.
6. **Attribute Authority (AA)** — verifies identities, issues attribute certificates. **Remains centralized** — explicitly flagged (Remark 1) as a deliberate, disclosed trust limitation, with three concrete mitigation strategies discussed (multi-AA cross-verification, on-chain issuance-event logging, periodic re-certification) and full decentralization named as future work, not silently assumed away.

**Dual-layer architecture:** encrypted search layer (keyword-search sub-layer via RLWE commitment; access-control sub-layer via lattice CP-ABE) + blockchain enhancement layer (decentralized key management, smart-contract access control, tamper-proof audit). Design principle: blockchain interactions are concentrated in low-frequency operations (init, key gen, policy registration); high-frequency search uses only local computation + cached queries.

**Five-phase workflow:** (1) System Initialization — DKG among edge nodes, deploy KeyManagement/AccessControl/AuditLog contracts, once at deployment. (2) Data Upload — DO→edge nodes: AES-GCM encrypt, derive s via H_seed(w), compute RLWE commitment, ABE-encrypt the data key under policy P, store on IPFS, register policy hash + CID on-chain. (3) Key Request — DU→AA for cert, then ≥t edge nodes verify + each computes a partial key + ZK proof, contract verifies all proofs and Lagrange-interpolates the full private key. (4) Search Query — DU derives s via the same public H_seed(w), builds token T_w=(commit_q, S, ts, σ_user); triple verification (signature+validity, on-chain policy/revocation check, RLWE commitment match). (5) Result Decryption — retrieve matching ciphertexts from IPFS, ABE-decrypt the data key, AES-GCM-decrypt; ⊥ if attributes don't satisfy the policy.

### 3.2 Threat model

Four adversary types: **A_ext** (external eavesdropper, explicitly modeled with quantum capability), **A_csn** (honest-but-curious cloud storage, may record access/search-frequency metadata), **A_du** (malicious data user — forging attribute certs, replaying expired tokens, colluding), **A_byz** (compromised/malicious edge nodes — refusing DKG participation, submitting incorrect partial keys, colluding to reconstruct the master key). **Table 2** enumerates 7 threats (T1 keyword-privacy disclosure … T7 quantum attack) each mapped to source and impact.

**Trust assumptions (Assumptions 2–6):** honest majority (≥2n/3 edge nodes honest, f<n/3, justified by pre-vetted consortium membership under legal/commercial constraint — not just an abstract game-theoretic claim); threshold security (adversary compromises at most t−1 nodes; typical (3,5) config tolerates 2 compromised); secure TLS inter-node channel; trusted AA (with the disclosed limitation above); standard RLWE/SIS hardness plus standard hash/symmetric assumptions.

### 3.3 Design objectives — G1–G8

G1 Post-Quantum Security (RLWE/SIS, n=1024/q=12,289 → 128-bit). G2–G4 data confidentiality, search privacy, fine-grained dynamic access control. G5 Computational Efficiency (O(n log n) commitment/matching, blockchain overhead confined to low-frequency ops). G6 Decentralized Trust ((t,n) threshold + PBFT, tolerates ⌊(n−1)/3⌋ malicious). G7–G8 tamper-proof on-chain audit + immediate blockchain-transaction-based revocation (~2s, no re-encryption/redistribution).

### 3.4 Formal protocol definition — nine algorithms (Definition 12)

`BC-Setup`, `ThresholdKeyGen`, `BC-Encrypt`, `Trapdoor`, `BC-Search`, `Decrypt`, `RevokeAccess`, `UpdatePolicy`, `QueryAuditLog` — signatures given in full in the source. **Correctness (Definition 13)** decomposes into three sub-conditions: commitment-matching correctness (same keyword → same seed → same commitment), ABE decryption correctness (P⊆S), threshold aggregation correctness (|T|≥t, Lagrange interpolation). **Five security definitions** (9–19): IND-INDEX, IND-TRAPDOOR, Threshold Key Security, Byzantine Fault Tolerance (safety+liveness), Audit Log Tamper-Proofness, Revocation Immediacy.

---

## 4. Protocol Design — the five core algorithms in full

**Algorithm 1 — `BC-Setup(1^λ, n, t, U)`.** RLWE parameter selection (n=1024, q=12289, σ=3.2, B=40 — commitment-matching threshold); seed_A←{0,1}^256, a←ExpandSeed(seed_A), â←NTT(a) (precomputed once); initialize Fabric network, configure PBFT (block time 2s); deploy KeyManagement/AccessControl/AuditLog contracts; **Pedersen DKG**: each node i samples a degree-(t−1) polynomial f_i, secret-sends shares f_i(j) to node j, each node sums received shares into sk_j, publishes verification commitment C_j=g^{sk_j} on-chain; distributed ABE setup. Returns (pp, {sk_i}, BC).
- Design notes: q=12,289 is the *smallest* prime satisfying q≡1 mod 2n (NTT requirement) — a genuine, checkable engineering constraint, not an arbitrary choice.
- **Parameter security strength analysis** (unusual level of rigor): computes the actual root Hermite factor δ=(q/σ)^(1/n)≈1.0082, giving BKZ block size β≈456 under classical Core-SVP (cost≈2^(0.292β)≈2^133) and β under quantum sieving (cost≈2^(0.265β)≈2^121) — both exceed the NIST Level-1 thresholds (128-bit classical / 120-bit quantum) the paper claims. This is a real lattice-estimator-style security argument, not just an assertion.
- **Explicit comparison to ML-KEM-768** (NIST FIPS 203): different ring structure (BL-ABSE: n=1024 ideal-lattice RLWE vs. ML-KEM-768: n=256,k=3, Module-LWE), larger modulus (q=12,289 vs 3329) — the paper argues this is required by its NTT constraint (q≡1 mod 2n) and commitment arithmetic, not an oversight. Both derive hardness from the same RLWE→SVP family.

**Algorithm 2 — `ThresholdKeyGen(pp, S, {EN_i}_{i∈T})`.** For each participating node, verify the user's attribute cert, compute a partial ABE key sk_abe,S^(i), generate a ZK proof π_i (proves correct computation without leaking sk_i), submit encrypted partial key + proof on-chain; once all proofs verify, Lagrange-interpolate the full sk_abe,S. User private key sk_S=(S, sk_abe,S) — **no user-specific PRF key** (deliberately — see below).

**Algorithm 3 — `BC-Encrypt(pp, w, P, M)`.** seed_c←H_seed(w); s←GaussianSample(seed_c,σ); NTT-domain commitment: ŝ←NTT(s·ψ), ĉ←â⊙ŝ (pointwise mult), c←INTT(ĉ)·ψ^{-1}, commit←c+H(w) mod q. K_data←random 256 bits; C_abe←ABE.Encrypt(pp_abe,P,K_data); AES-GCM-encrypt M under K_data with a fresh 96-bit nonce; serialize+store on IPFS→CID; dataId←H(CID‖owner‖ts); register (dataId, policyHash, expireTime, CID) on-chain via AccessControl; emit an AuditLog event. Returns (CID, I, txHash).

**Algorithm 4 — `Trapdoor(pp, sk_S, w)`.** Same seed_c/s/commit_q derivation as encryption (Steps 1–3 identical to BC-Encrypt's Steps 1–7) — this identity IS the search-matching mechanism. ts/expiry for anti-replay; σ_user=Sign(DU.privKey, msg) binds the token to the user's identity. **Purely local — no blockchain interaction, no network round-trip** — token generation latency is one NTT multiplication + one signature.
- **Key design point, worth flagging explicitly for the benchmark**: because commitment derivation depends only on the *public* H_seed and the keyword — not on any user-specific secret — any two users searching the same keyword produce byte-identical commitments. This is what makes non-interactive matching possible, and it's also exactly the search-pattern/cross-user-linkage leakage the paper quantifies later (§5.9) rather than hiding.

**Algorithm 5 — `BC-Search(T_w, BC, DB)`.** Reject if expired or signature invalid. **Then linearly scans every (I_i, CID_i) pair in DB**: for each, check policy validity + revocation status (both against on-chain/cached state — `continue` on either failure), then compute diff=(commit_i − commit_q) mod q, centered-reduce each of the n coefficients to [−q/2, q/2], sum of squares → dist, and accept (add CID_i to R) iff dist ≤ B. Emit an audit event with the query id, hashed commitment, and result count — **not the plaintext keyword**. Returns R.
- **This confirms Table 8's `O(|DB|·n)` search complexity is a real, unfiltered linear scan** — structurally the same *shape* of weakness as Thingom's O(N) pairing scan (every record touched, no index/filter), but the *per-record cost* is drastically cheaper: n=1024 centered-modular-subtraction-and-square operations (cheap integer arithmetic) instead of a real bilinear pairing (2u+1 pairings, ~0.7ms each in this repo's own measurements). That's the mechanistic reason its measured search latency (29μs/record) is ~500,000× cheaper per record than Thingom's, despite both being unfiltered linear scans in shape.
- **On-chain query optimization**: local cache + blockchain event subscription — edge nodes cache policies/revocation lists and update on block-confirmation events, turning a 15ms on-chain query into microsecond-level cache access. Cache staleness window ≈ one block-confirmation time (~2s).

**Algorithm 6 — `Decrypt`** (referenced, signature given in Definition 12; detailed steps not sampled in this extraction — see PDF pp. 20–21 for the full listing).

---

## 5. Security Analysis (sampled: Theorems 6–9, pp. 30–34)

- **Theorem 6 (Byzantine Fault Tolerance, safety+liveness)** — proof via honest-majority counting (h≥2f+1>t under n≥3f+1), timeout/retry for stalled key generation, PBFT liveness under eventual synchrony, Fabric's View Change for primary-node failure.
- **Theorem 7 (Post-Quantum Security)** — proof sketch reduces each prior theorem's PPT bound to a QPT bound: RLWE hardness under Regev's worst-case-to-average-case reduction (extended to RLWE by Lyubashevsky et al.), best known quantum SVP-approximation algorithms still need 2^Ω(n) time even with Grover speedup (at n=1024: 2^512, "far beyond feasible computation"); SIS reduces to SVP similarly; Shamir threshold sharing is information-theoretically secure regardless of adversary compute (quantum-immune by construction); AES-256 retains 128-bit security under Grover (paper notes AES-512/ChaCha20 as future-proofing options if stronger margin is wanted). **Explicitly cross-validates against NIST**: notes CRYSTALS-Kyber (Module-LWE) and CRYSTALS-Dilithium (Module-SIS) — the actual NIST PQC standards — share the same RLWE/SIS assumption family as BL-ABSE.
- **Theorem 8 (Audit Tamper-Evidence)** — hash-chain + distributed PBFT consensus (≥2f+1 confirmations needed) + multi-party witnessing; also lists three *practical* (non-cryptographic) detection mechanisms: a blockchain explorer UI, Merkle-proof export for external auditors, periodic public Merkle-root snapshots.
- **Theorem 9 (Revocation Immediacy)** — Δ_confirm≈2s bound decomposed into concrete parts: network delay <100ms + PBFT three-phase message exchange + block write; explicitly notes the revoked user *still holds* a valid key/token at time t' but is rejected because Algorithm 5's on-chain revocation check (Line 13) executes **unconditionally**, not because their credentials became invalid. Direct quantitative comparison table follows (Wang et al. reissue-based: 3,306ms→1,705,047ms, a >515× blowup as N:100→50,000; Yin et al. similar reissue pattern: →1,041,063ms; Shen et al.'s O(log N) KUNodes: →6,631ms, sub-linear but still growing; Yu et al.'s proxy re-encryption: →142,138ms; **BL-ABSE: flat 2019–2065ms across the entire N=100→50,000 range**, empirically confirming the proven O(1) bound).

### §5.9 Search-pattern leakage — quantified, not hand-waved

Explicitly states the deterministic commitment (needed for non-interactive matching) leaks which queries target the same keyword. Three concrete attack vectors with real numbers:
1. **Frequency analysis** (§5.9.1, validated experimentally in §6.8): keyword-recovery rate is only 2.5% at |W|=1000/Zipf α=1.0 even after 10,000 observed queries; rises to 14.9% only for small, highly skewed vocabularies (|W|=100, α=2.0).
2. **Dictionary attack** (§5.9.2): if the adversary's candidate dictionary covers the true keyword space, recovery is 100% — stated as "a fundamental consequence of the deterministic design... shared by all searchable encryption protocols that support non-interactive keyword matching with equality testing," not spun as unique to this scheme.
3. **Cross-user linkage** (§5.9.3): 100% of user pairs sharing ≥1 keyword are linkable with certainty (measured: ~20 shared keywords per pair on average, 100 queries/user, vocabulary 500).
4. **§5.9.4 explicitly frames this as a correctness–privacy trade-off**, operates within a formally declared leakage function (L_Search reveals exactly sp(w), nothing more per the IND-INDEX proof), and names concrete mitigations (ORAM integration, differential privacy) as future work (§7.2) rather than claiming the leakage away.

---

## 6. Experimental Evaluation (sampled: §6.1–6.5, pp. 34–40)

**§6.1 Setup.** Intel Xeon E5-2680 v4 (2.4GHz, 14 cores), 64GB DDR4, Ubuntu 22.04 LTS. Prototype in **Python 3.10 + NumPy 1.24** for polynomial arithmetic, hashlib/SHAKE-256 for hashing. Blockchain experiments use **Hyperledger Fabric 2.5** with PBFT at a 2s block time, deployed across Docker containers. Each experimental group independently repeated **30 times**, mean±std reported. RLWE parameters n=1024, q=12,289, σ=3.2, B=40 held fixed throughout — same implementation-language caveat as `Ref[54]`: **this repo's own Python/AWS measurements would need independent re-implementation**, per README §13, not reuse of these numbers directly, though the language (Python) at least matches this repo's own harness language, unlike Ref[54]'s Rust.

**Table 6 — NTT effectiveness** (n∈{256,512,1024,2048}, 50 reps each): at n=1024 (BL-ABSE's chosen parameter), naive O(n²) commitment generation averages 401.43ms (σ=13.01ms) vs. NTT-optimized 23.13ms (σ=0.68ms) — **17.4× speedup**, growing to 31.3× at n=2048, consistent with the theoretical O(n²)/O(n log n) ratio. NTT-optimized timings also have far lower variance (0.68ms vs 13.01ms std at n=1024) — "important implications for latency predictability."

**Table 7 — 9-dimension feature comparison against 12 named prior works** (Zhang, Yu, Luo, Niu, Yin, Shen, Cao, Huang, Yang, Liu, Zhang(20), Wang, Yan): BL-ABSE is the only row with all nine columns checked (Security Assumption=RLWE/SIS, PQ Secure, Access Control=CP-ABE, Decentralized Key Mgmt, Blockchain, Instant Revocation, Audit Log, NTT Optimization).

**Table 8 — Computational complexity comparison**: BL-ABSE's Encryption=O(n log n), **Search=O(|DB|·n)**, Token Generation=O(n log n), Key Storage=O(n) — vs. pairing-based competitors' O(|U|)P/O(|DB|)P (P = one pairing op) and naive-lattice competitors' O(n²) terms.

**§6.4 Search latency vs. keyword scale — Table 9 (real measured data, 8 points, N=100 to 50,000, reps=30):**

| Keywords | Avg (ms) | Std (ms) | Min (ms) | Max (ms) | Per-record (μs) |
|---|---|---|---|---|---|
| 100 | 2.79 | 0.05 | 2.72 | 3.05 | 27.9 |
| 500 | 14.87 | 0.68 | 13.97 | 17.25 | 29.7 |
| 1,000 | 29.29 | 1.03 | 28.23 | 32.62 | 29.3 |
| 2,000 | 58.01 | 2.21 | 55.83 | 65.57 | 29.0 |
| 5,000 | 146.53 | 5.70 | 139.35 | 163.34 | 29.3 |
| 10,000 | 290.32 | 9.17 | 280.22 | 325.56 | 29.0 |
| 20,000 | 576.35 | 19.78 | 544.40 | 631.12 | 28.8 |
| 50,000 | 1443.79 | 26.00 | 1361.24 | 1495.07 | 28.9 |

Linear fit slope: 28.86 μs/keyword, R² implied "closely" matching the empirical data — per-record cost is stable at 27.9–29.7μs across the entire two-orders-of-magnitude range, confirming the O(|DB|·n) model with no hidden superlinear term.

**§6.5 Revocation comparison — explicitly labeled as simulation, with disclosed sourcing.** *"Simulation Methodology Transparency"* (verbatim section heading): baseline operation costs are literature-derived, not independently re-measured by these authors — bilinear pairing time (4.2ms) "from the benchmarks reported in [28]," lattice polynomial multiplication (401.4ms naive) from their own Table 6, Hyperledger Fabric PBFT confirmation (~2000ms) from Fabric's default config. This is the same kind of explicit "measured here" vs. "modeled from elsewhere" separation this repo's own `run_meta.json`/`reportable` flag enforces — the paper is not passing off literature numbers as its own fresh measurements.

---

## 7. Discussion and Conclusion (sampled: p. 47–48)

**§7.1 Limitations — five, self-identified, not found by outside scrutiny:**
1. Single-keyword exact matching only — no Boolean/conjunctive/range query support (**directly relevant to this repo**: rules out treating BL-ABSE as a multi-keyword scheme without a native-mode workaround, same treatment already applied to Thingom's/Guo's conjunctive queries).
2. Security proofs are in the **random oracle model**; standard-model proofs would be stronger.
3. Revocation-comparison baselines (§6.5) use simulation modeling; absolute timings may differ across hardware platforms (asymptotic complexity claimed hardware-independent).
4. Deterministic commitments leak the search pattern (already covered in depth, §5.9/§6.8).
5. AA remains a centralized single point of trust for identity-to-attribute binding (already covered, Remark 1).

**§7.2 Future directions** (five, concrete): multi-keyword conjunctive query support within the RLWE framework; standard-model security proofs; ORAM/differential-privacy mitigation for search-pattern leakage; fully decentralized attribute management (removing the AA bottleneck); hardware acceleration (FPGA/ARM) for IoT/edge deployment.

**Funding, data availability**: funded by a real regional science-and-technology grant (Xinjiang Autonomous Region). Explicit **Data Availability Statement**: core RLWE primitives implemented as standalone, independently verifiable Python scripts; benchmark scripts for NTT comparison (Table 6), threshold-B verification (§6.6), and leakage quantification (§6.8) "available from the corresponding author upon reasonable request." Standard MDPI conflicts-of-interest and disclaimer boilerplate.

**References**: 32 entries, real and correctly formatted — includes Boneh–Di Crescenzo–Ostrovsky–Persiano (EUROCRYPT 2004, the original PEKS paper), Song–Wagner–Perrig (S&P 2000, the original SSE paper), Shor (1994), Bethencourt–Sahai–Waters (S&P 2007, the original CP-ABE paper), all three NIST PQC FIPS standards (203/204/205), and Nakamoto's Bitcoin whitepaper — all real, correctly attributed foundational citations, no fabricated or mismatched entries spot-checked.

---

## Legitimacy / quality assessment (2026-08-28, same due-diligence standard applied to Ref[41] and Ref[54])

**Result: passes cleanly, and more thoroughly than either prior reference.**

- **DOI resolves** to a real, live, Scopus/Web-of-Science-indexed MDPI journal (`Electronics`, not a predatory or delisted venue) — confirmed via `doi.org` redirect to `mdpi.com/2079-9292/15/11/2471`.
- **Genuinely post-quantum throughout**: every algorithm (Setup, ThresholdKeyGen, BC-Encrypt, Trapdoor, BC-Search, Decrypt) is RLWE/SIS-based. Zero pairings, zero DBDH, anywhere in the actual construction — confirmed by reading all five core algorithms in full, not just the abstract's claim.
- **No duplicated paragraphs, no off-topic filler, no internal self-contradiction** found across ~30 sampled pages spanning the introduction, every core algorithm, the security proofs, half the evaluation, the discussion, and the reference list.
- **Self-discloses five concrete limitations** in a dedicated Discussion section, plus a separate "Simulation Methodology Transparency" callout distinguishing its own fresh measurements from literature-derived baseline numbers, plus an explicit Remark on its one real centralization compromise (the AA) with named mitigation strategies. This is the strongest self-critical posture of the three references processed in this repo so far.
- **Real, checkable engineering justification for parameter choices** (q=12,289 as the *smallest* prime satisfying the NTT constraint; an actual lattice-estimator-style Core-SVP/quantum-sieving security calculation, not just an assertion of "128-bit security").
- **Two things worth flagging for this benchmark, not as legitimacy problems but as scoping decisions**, matching the same rigor already applied to `thingom_pq_abse.attributes.u` and `perera_lv_pqabse`'s undetermined lattice parameters:
  1. **No domain/cross-domain concept exists anywhere in the system model.** Exp. 3 (cross-domain scalability) would need the same native-mode treatment already used for Guo/Thingom (d independent searches, client-side aggregation) — or could legitimately be excluded if that native-mode reading isn't judged faithful to a scheme with no domain notion at all. Needs a decision, not a default.
  2. **No standalone "update an existing index" primitive** — data upload (`BC-Encrypt`) is the only way new records enter the system; there's no distinguished incremental-update algorithm. Exp. 5 (dynamic keyword update) likely does not have a faithful mapping here, similar to why `perera_lv_pqabse` was excluded from Exp. 5.
  - Exp. 1 (trapdoor gen), Exp. 2 (search latency), and Exp. 6 (authorization sync) are strong, well-supported fits — Exp. 6 especially, since instant blockchain revocation is this paper's headline contribution and directly measures what Exp. 6 measures (authorization-update latency vs. scale δ=10²→10⁵), with real data already in hand (Table 9's revocation-comparison figures, Figure 4).
