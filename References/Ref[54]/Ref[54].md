# LV-PQ-ABSE: A Lightweight Verifiable Postquantum Attribute-Based Searchable Encryption Scheme With Hybrid Indexing and Provenance-Aware Verification for IoT-Based EHRs

Maneesha Perera and Somchart Fugkeaw, *Member, IEEE*

*IEEE Internet of Things Journal*, vol. 13, no. 15, 1 August 2026, pp. 34302–34317.
Received 12 January 2026; revised 3 May 2026; accepted 19 May 2026. Date of publication 22 May 2026; date of current version 27 July 2026.
The authors are with the Sirindhorn International Institute of Technology, Thammasat University, Pathum Thani 12120, Thailand (e-mail: maneesha.nick@gmail.com; somchart@siit.tu.ac.th).

Digital Object Identifier: **10.1109/JIOT.2026.3695855**

*Index Terms* — Ciphertext-policy attribute-based encryption (CP-ABE), fog computing, Kyber, lattice-based cryptography, multikeyword search, postquantum cryptography (PQC), searchable encryption (SE), verifiable search.

---

## Abstract

The rapid adoption of Internet of Things (IoT) technologies in healthcare has enabled continuous collection and sharing of electronic health records (EHRs) but has also introduced critical challenges in privacy preservation, fine-grained access control, and long-term security against quantum adversaries. Searchable encryption (SE) combined with attribute-based access control provides a promising foundation for secure EHR querying, yet existing solutions remain either quantum-insecure, computationally expensive, or lack verifiable correctness and provenance guarantees in fog–cloud environments. In this article, we propose **LV-PQ-ABSE**, a lightweight verifiable postquantum attribute-based SE framework for IoT-based EHR systems. LV-PQ-ABSE enables expressive multikeyword, Boolean, range, and fuzzy queries over encrypted data while preserving postquantum confidentiality. To achieve scalability, the framework offloads indexing and search execution to fog nodes, where encrypted hybrid indices are constructed and provenance-aware commitments are generated. Each ciphertext is cryptographically bound to its data source and timestamp, and search results are verified using partitioned Merkle proofs anchored on a blockchain, ensuring integrity, completeness, and freshness with low overhead. Extensive evaluation demonstrates that the proposed framework significantly reduces client-side computation and verification cost compared to existing state-of-the-art schemes, making it practical for large-scale IoT–EHR deployments.

---

## Nomenclature

| Symbol | Meaning |
|---|---|
| λ | Security parameter |
| n, q, σ | Lattice dimension, modulus, and Gaussian noise width |
| 𝒰 | Global attribute universe |
| 𝔸 | Attribute set associated with a user |
| mpk, msk | Master public and secret keys |
| SK_𝔸 | User secret key for attribute set 𝔸 |
| K_m | Master symmetric key |
| K_index, K_query | Derived keys for indexing and trapdoor generation |
| K_mac | Key for message authentication |
| K_s | Symmetric session key for data encryption |
| C_doc | Encrypted data payload (AES-GCM ciphertext) |
| ct_abe | CP-ABE ciphertext component |
| ct_kem | KEM ciphertext (encapsulation output) |
| σ_sig | Digital signature on ciphertext or metadata |
| ObjID | Unique identifier of an encrypted record |
| T_w | Trapdoor corresponding to keyword w |
| token(x) | PRF-generated token for attribute x |
| root_T | Merkle tree root of indexed data |
| π | Merkle proof path |
| t | Epoch index |
| Acc_t | Cryptographic accumulator value at epoch t |
| BC_Params | Blockchain configuration parameters and system settings |
| n | Security parameter or lattice dimension |
| k | Number of attributes or access policy parameters |
| N | Total number of users or ciphertexts in the system |
| T_mul | Time for a single modular multiplication over Z_q |
| T_mult | Time for one polynomial or matrix multiplication |
| T_G | Time for lattice key or trapdoor generation (TrapGen/SamplePre) |
| T_s | Time for digital signature generation (Dilithium) |
| T_v | Time for digital signature verification |
| T_h | Time for a single hash computation |
| T_H | Time for hash-based key derivation (HKDF) |
| T_p | Time for pseudorandom function (PRF) evaluation |
| T_E | Time for symmetric encryption (AES-GCM) |
| T_D | Time for symmetric decryption |
| T_Kyber | Time for Kyber encapsulation/decapsulation |
| T_verify | Time for verification (Merkle proof, signature, parity) |
| log N | Logarithmic factor from Merkle proof verification |
| O(·) | Asymptotic computational complexity |

---

## I. Introduction

Outsourcing sensitive EHR data to semi-trusted fog and cloud infrastructures raises critical concerns regarding data confidentiality, fine-grained authorization, secure search, integrity verification, and regulatory compliance (HIPAA, GDPR). Existing SE + CP-ABE approaches suffer from four fundamental limitations:

1. Heavy reliance on bilinear pairings and exponentiations, prohibitive for resource-constrained IoT devices.
2. Centralized and largely static index architectures that do not scale to dynamic, distributed edge–fog deployments.
3. Absence of cryptographic provenance binding that can irrefutably link ciphertexts to their originating sensors or patients.
4. Limited verifiability guarantees, particularly regarding result completeness and freshness, under decentralized trust assumptions.

These designs are also inherently quantum-insecure. Lattice-based cryptography, grounded in LWE, offers a promising foundation for postquantum security, but existing lattice-based SE schemes support only restricted query models and incur significant computational overhead from costly lattice operations (sampling, trapdoor generation).

**Motivating example query:** `(blood_pressure BETWEEN 120–140) AND (diagnosis CONTAINS "diabtes" OR "diabetic") AND (timestamp < 30 days)` — combines numeric range predicates, fuzzy keyword matching, Boolean logic, and temporal constraints.

### Table I — Functional Feature Comparison

| Scheme | F1 Multi-Keyword | F2 Provenance-Aware | F3 Range | F4 Boolean | F5 Fuzzy | F6 Verifiable |
|---|---|---|---|---|---|---|
| IBEKS [3] | ✓ | ✗ | Partial | Partial | ✗ | ✗ |
| MCP-ABSE-AR [24] | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| ABAEKS [13] | ✗ | ✗ | ✗ | Partial | ✗ | ✗ |
| FS-MUAEKS [7] | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| PunSearch [37] | ✓ | Partial | ✗ | ✗ | ✗ | Partial |
| CP-ABSEL [38] | ✓ | ✗ | ✗ | ✗ | ✗ | Partial |
| PPSEB [41]\* | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ |
| CT-PAEKS [43]\* | Partial | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Ours (LV-PQ-ABSE)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

\* Reference numbers [41]/[43] here are **this paper's own numbering**, unrelated to this repo's `Ref[41]` (Thingom). Do not conflate — see reference list at the end of this file for this paper's own bibliography.

### Contributions

1. **Expressive Postquantum Search.** First lattice-based ABSE framework (to the authors' knowledge) supporting multikeyword, Boolean, fuzzy, and numeric range queries in one unified encrypted search model — via B⁺-trees (range), bitmap indexing (filtering), and n-gram tokenization (fuzzy).
2. **Fog-Assisted Offloading With Cryptographic Provenance.** Offloads expensive lattice operations from IoT devices to fog nodes; uses Kyber KEM for key encapsulation and Dilithium signatures for authentication; each ciphertext is cryptographically bound to its data source and timestamp.
3. **Verifiable and Partition-Optimized Retrieval.** Partitioned Merkle trees for scalable verification, parity-based validation for early tamper detection, threshold-signed root anchoring on blockchain per epoch.

---

## II. Related Work (summary)

Surveys pairing-/number-theory-based SE evolving toward PQC, lattice-based constructions (LWE/Ring-LWE/SIS) being the NIST-favored family. Cites Behnia et al. [2] (LWE/NTRU tradeoffs), Liu et al. [6] (PEKS+KP-ABE), Xu et al. [7] (forward-secure multiuser SE), Yu et al. [8] (revocable PEKS with bounded trapdoor exposure), Jiang and Wang [12] (QPASE, TOPRFs), Luo et al. [13] (ABAEKS, authentication-integrated trapdoors), Sfugkeaw/Tangtanawirut et al. [41] (MK-WISE — self-citation, multikeyword wildcard ABSE with revocation), Varri et al. [38] (CP-ABSEL). Common gap identified: existing lattice/classical designs don't jointly achieve expressive query support, efficiency, **and** verifiability, particularly under partial fog-node trust.

---

## III. Preliminaries

### A. Postquantum Hardness Assumptions

1. **Learning With Errors (LWE).** n,q ∈ ℕ, χ a discrete Gaussian over ℤ with std σ. LWE sample: (a, b = ⟨a,s⟩ + e mod q), a ←$ ℤ_q^n, e ←$ χ. Decisional LWE: no PPT adversary distinguishes LWE_{n,q,χ} samples from uniform U_{n,q} with non-negligible advantage. Reduces to worst-case SVP/SIS on n-dimensional lattices (postquantum hardness).

2. **Ring- and Module-LWE.** Computations over polynomial ring R_q = ℤ_q[x]/(f(x)), f(x)=x^n+1. RLWE sample: (a, b = a·s+e mod q). Module-LWE generalizes to matrices A ∈ R_q^{k×ℓ}. Both reduce to standard LWE.

3. **Trapdoor Sampling and Gaussian Preimages.** A ←$ ℤ_q^{n×m}. Trapdoor T_A for lattice Λ_q^⊥(A) = {x ∈ ℤ^m : Ax = 0 mod q}. `TrapGen(n,m,q)` outputs (A, T_A) statistically close to uniform. `SamplePre(A, T_A, u, σ)` returns short x ← D_{Λ_q(A),σ} s.t. Ax = u mod q, ‖x‖ ≈ σ√m.

4. **Basis Delegation.** Given master trapdoor T_A for A and derived B = rA + E (small noise E), `Deleg(A, T_A, r, E) → T_B` produces a delegated trapdoor for B, statistically close to an independently generated trapdoor. Supports secure delegation of partial keys/search capabilities to fog nodes without exposing the master secret.

### B. Lattice-Based Cryptographic Primitives

**1) Ciphertext-Policy ABE** = (Setup, KeyGen, Encrypt, Decrypt):
- `Setup(1^λ) → (MPK, MSK)`: generate public matrix A and master trapdoor T_A; MPK=(A,q), MSK=T_A.
- `KeyGen(MSK, 𝔸) → SK_𝔸`: SamplePre to obtain short vectors encoding 𝔸 within Λ_q^⊥(A).
- `Encrypt(MPK, 𝒫, M) → CT`: represent access policy 𝒫 by LSSS matrix M; sample randomness y; output CT = (c₁ = Ay + ⌊q/2⌋·M, c₂ = My).
- `Decrypt(SK_𝔸, CT)`: if 𝔸 ⊨ 𝒫, use reconstruction coefficients {ω_i} to cancel My in c₁.

**2) Trapdoor-Based Key Delegation and Revocation.** Binary-tree key-update structure. Each nonrevoked user receives updated info via Kyber KEM encapsulation: KU_t = Enc_KEM(K_t), K_t the epoch key. `Deleg` allows fog-assisted nodes to update keys/ciphertext components without decrypting data.

**3) Verifiable Index Structures.** Each index partition maintains a local Merkle root: root_i = H(I_i). Global root: root_𝒯 = H(root₁ ‖ root₂ ‖ ⋯ ‖ root_n), periodically committed to blockchain. Given result set ℛ with auth path π, verification succeeds if H(ℛ‖π) = root_𝒯. H = SHA-3 → quantum-resilient, tamper-evident.

---

## IV. Proposed LV-PQ-ABSE Framework

### A. System Model — Five Entities (Fig. 1)

1. **Edge Devices** (IoT/medical sensors): collect data, apply hybrid protection (AES-GCM + Kyber KEM + Dilithium signature), transmit over a quantum-resistant channel.
2. **Fog Nodes**: verify signatures, enforce fine-grained access control via lattice CP-ABE, construct encrypted searchable indexes, batch data, compute integrity commitments (Merkle roots), maintain revocation state, periodically anchor to blockchain.
3. **Cloud Storage**: stores encrypted data/indexes, performs privacy-preserving search without accessing plaintext, returns matching ciphertexts + verifiable proofs.
4. **Data Users (DUs)**: hold attribute-based keys, generate trapdoors, query the cloud, verify returned proofs, recover session key if policy satisfied.
5. **Blockchain Network**: tamper-evident audit layer — integrity commitments, revocation states, query summaries via smart contracts.

### B. Design Goals (8)

1. Postquantum security (all primitives lattice-based / NIST-standardized: Kyber, Dilithium; no pairings, no number-theoretic hardness).
2. Leakage-resilient search privacy (formally defined leakage profile via PRF-based tokenization + lattice trapdoor generation; formalized as IND-CKA).
3. Expressive encrypted search (hybrid index: B⁺-trees + bitmap + n-gram).
4. Lightweight edge-side computation (client does only symmetric enc/hash/token-gen; lattice ops offloaded to fog — "near-constant trapdoor generation").
5. Verifiable retrieval with completeness and freshness (partitioned Merkle trees, blockchain anchoring).
6. Provenance awareness and auditability (each record cryptographically bound to origin).
7. Scalable fog–cloud operation (logarithmic verification complexity w.r.t. dataset size).
8. Forward security and efficient revocation (epoch-based key evolution, KEM-based updates) — **explicitly does NOT support fine-grained/immediate attribute- or ciphertext-level revocation**; noted as future work, not silently omitted.

### C. Cryptographic Construction — Five Phases

**Phase 1: System Setup and Initialization** (once, at global epoch transition)

- λ = 192 (**NIST Category 3**). Lattice params (n,q,σ) chosen "consistent with Kyber768 and Dilithium3" — **exact numeric (n,q,σ) not given in the paper body**; only asymptotic/security-category statements. This is the same class of "not published, benchmark decision required" gap as `thingom_pq_abse.attributes.u` — must be fixed and documented in `crypto.yaml` before implementation, not defaulted silently.
- Domain-separated hashes H₁,H₂,H₃; KDF = HKDF-SHA3-256. Symmetric encryption = AES-256-GCM.
- `ABE.Setup(1^λ) → (PP_ABE, MK_ABE)`.
- `Kyber.KeyGen() → (PK_Kyber, SK_Kyber)`, `Dilithium.KeyGen() → (VPK_Dilithium, SSK_Dilithium)`.
- Precomputes trapdoor matrices {(A_i, T_{A_i})}, A_i ∈ ℤ_q^{n×n} (seeded expansion, TrapGen with Gaussian parameter σ).
- Master key K_m sampled; (K_index, K_query, K_mac) = HKDF(K_m). Per-user query key K_query^(U) = HKDF(K_m, UserID_U) (prevents cross-user query linkability).
- mpk = {PP_ABE, PK_Kyber, VPK_Dilithium}, msk = {MK_ABE, SK_Kyber, SSK_Dilithium}.
- Attribute universe 𝒰 = {u₁,...,u_m}; commitment AttrRoot = SHA3-256(serialize(𝒰)‖ver‖t₀), anchored on-chain.
- Hybrid index primitives initialized: B⁺-trees (ordered attributes), bucketed bitmaps (range), equality bitmaps (categorical), time-partitioned indices, n-gram indices (fuzzy). All entries pseudorandomized via K_index, authenticated via HMAC_{K_mac}.
- Key evolution: K_ephem = HKDF(K_m, id_session) (forward secrecy). Epoch transition invalidates previously issued keys for future access — **coarse-grained revocation only** (whole-epoch, not per-attribute/per-ciphertext).

**Phase 2: Edge-Side Data Preparation and Hybrid Encryption** — `Algorithm 1: EdgeEncrypt(D_raw, policy, pk_recipient)`

1. Authenticated data capture: (seq,ts) ← GenMeta(); aad = seq‖ts; mac_tag = HMAC_{SHA3-256,K_mac}(H₂(D_raw)‖aad).
2. Privacy-preserving tokenization: attributes 𝔸={a₁,...,a_m} from D_raw. Each attribute → unlinkable token via PRF: τ_i = F_{K_index}(a_i). Numeric values → bucket IDs τ_b = F(⌊v/Δ⌋); temporal → epoch IDs τ_t = F(epoch(ts)); textual → n-grams 𝒢(w), tokenized τ_g = F(g).
3. Hybrid index preparation: token set 𝒯 = 𝒯_kw ∪ 𝒯_num ∪ 𝒯_cat ∪ 𝒯_time ∪ 𝒯_ngram, mapped to: keyword→B⁺-tree ℐ_kw[τ_w]↦{(ObjID,ProvDigest)}; numeric→bucketized bitmap ℬ_num[τ_b][ObjID]∈{0,1}; categorical→equality bitmap ℬ_cat[τ_c][ObjID]∈{0,1}; temporal→epoch-partitioned 𝒯_i[ObjID]=ProvDigest.
4. Symmetric record encryption: K_sym ← SecureRandom(256); (C_doc, auth_tag) = AES_GCM_Enc(K_sym, D_raw, iv, aad).
5. Hybrid postquantum key encapsulation: ct_abe = PQ-CP-ABE.Encapsulate(K_sym, policy); (ct_kem, K_kem) = Kyber768.Encapsulate(pk_recipient); K_hyb = HKDF_{SHA3-256}(K_sym‖K_kem, "lv-pq-abse-session") — **hybrid KEM combiner: secure as long as at least one of {ABE encapsulation, Kyber} remains secure.**
6. Edge-side authentication/nonrepudiation: σ_edge = Dilithium3.Sign(sk_edge, H₂(C_doc‖meta‖seq‖ts‖mac_tag)).
7. Secure transmission to fog node: {ct_abe, ct_kem, C_doc, σ_edge, mac_tag}. Fog verifies σ_edge, mac_tag; inserts leaf hash into local Merkle batch for the next anchoring epoch.

Provenance tag/digest (bound to source, unlinkable across epochs):
`tag_prov = H₂(PID ‖ PubKey ‖ seq)`, `ProvDigest = H₃(tag_prov ‖ H₂(C_doc) ‖ ts)`.

**Phase 3: Fog-Assisted Verification, Provenance Binding, and Hybrid Index Construction**

- **(a) Verification and provenance binding:** fog checks SigVer(VPK_edge, σ_edge, H₂(C_doc‖meta‖seq‖ts))=1 and MACVer(K_mac, H₂(C_doc)‖seq‖ts, mac_tag)=1; reject on either failure.
- **(b) Hybrid index construction:** τ_x = PRF_{K_index}(x) for each keyword/value/category attribute. Mapped as above.
- **(c) Merkle commitment and blockchain anchoring:** digest_payload = H₃(ObjID‖ProvDigest‖digest_ct‖meta‖ts), digest_ct = H₃(ct_abe‖ct_kem). Digests aggregated into Merkle tree 𝒯; root_𝒯 signed via **threshold Dilithium**: σ_root = Dilithium.Sign(sk_agg, root_𝒯); anchored on-chain.

**Phase 4: Verifiable Search and Trapdoor Execution** — `Algorithm 2: SearchExec(TD_𝒬, σ_user)`

Query: 𝒬 = (W, op, range, epoch), W={w₁,...,w_k}, op a Boolean operator.
Tokens: τ_i = PRF_{K_query^(U)}(w_i); fuzzy n-grams: 𝒯_i = {PRF(g) | g ∈ 𝒢(w_i)}; full token set 𝒯 = ⋃(τ_i ∪ 𝒯_i).
Trapdoor: TD_𝒬 = TokenTrapdoorGen(SK_{𝔸_U}, 𝒯, range, op, epoch), authenticated by σ_user = Dilithium3.Sign(sk_U, H₂(TD_𝒬)) (binds token to user's attribute-based key).

Algorithm:
1. If SigVer(VPK_U, σ_user, H₂(TD_𝒬)) ≠ 1 → reject (⊥).
2. If Revoked(UserID, epoch) ∨ Expired(epoch) → reject (⊥).
3. Cand_kw = BooleanEval({ℐ_kw[τ] | τ∈𝒯}, op); Cand_num = {ObjID | ℬ_num[range][ObjID]=1}; Cand_time = {ObjID | ObjID∈𝒯_epoch[epoch]}.
4. Cand = Cand_kw ∩ Cand_num ∩ Cand_time.
5. Fuzzy scoring: score(ObjID) = Σ_{τ∈𝒯} 𝟙[(ObjID,*) ∈ ℐ_kw[τ]]; keep Cand where score ≥ θ.
6. For each ObjID_i ∈ Cand: retrieve R_i = {ObjID_i, ct_kem,i, ct_abe,i, C_doc,i, π_i, ProvDigest_i, σ_edge,i}. ℛ = ⋃R_i.
7. AuditCommit = H₂("query" ‖ H₃(𝒯) ‖ root_𝒯 ‖ epoch) — optionally anchored on-chain.

**Phase 5: Secure Retrieval, Decryption, and Verification** — `Algorithm 3: RetrieveVerify(ℛ, SK_DU, SK_𝔸)`

For each R_i ∈ ℛ:
1. Hybrid key reconstruction: K_seed ← ABE.Dec(ct_abe,i, SK_𝔸); K_kem ← Kyber768.Decaps(ct_kem,i, SK_DU); K_sym = HKDF(K_seed‖K_kem‖H₂(ct_kem,i), "lv-pq-abse-session").
2. Decrypt: D_i = AES_GCM_Dec(K_sym, C_doc,i, iv, aad, auth_tag); reject (continue) if MACVer or SigVer fails.
3. Integrity/completeness: digest_ct,i = H₃("ct"‖ct_abe,i‖ct_kem,i); digest'_i = H₃("leaf"‖ObjID_i‖ProvDigest_i‖digest_ct,i‖meta_i‖ts_i); accept only if MerkleVerify(π_i, digest'_i, root_𝒯) = 1.
4. Freshness: root_𝒯 must equal root*_𝒯, the latest on-chain-anchored root (rejects stale/obsolete index snapshots).
5. AuditCommit = H₂("query"‖H₃(𝒯)‖root_𝒯‖epoch) — optionally anchored/logged.

---

## V. Security Analysis

Threat model: adversary may eavesdrop, replay, reorder, adaptively query trapdoors, collude with honest-but-curious fog/cloud servers. **Attribute authority (AA) and blockchain layer are trusted and noncolluding.** Fog/cloud are honest-but-curious. Assumes **fewer than t fog nodes collude** (else threshold signatures/anchored roots could be forged).

Four games, all reducing to standard assumptions (LWE-hardness of the lattice CP-ABE, Kyber IND-CPA, Dilithium EUF-CMA, SHA-3 collision resistance):

1. **IND-CPA Game** (Theorem 1, data confidentiality) — hybrid argument over CP-ABE/Kyber/AES-GCM; Adv ≤ ε_ABE + ε_Kyber + ε_AES.
2. **IND-CKA Game** (Theorem 2, trapdoor/keyword privacy) — Adv ≤ ε_PRF + ε_ABE, via PRF-indistinguishability lemma (token set indistinguishable from random without K_query).
3. **Merkle-Verifiability Game** (Theorem 3, soundness/completeness/freshness) — Adv ≤ ε_cr (collision resistance of H₃), relies on append-only blockchain.
4. **Provenance-Unforgeability Game** (Theorem 4, PACT) — Adv ≤ ε_Dilithium + ε_cr; forging a provenance digest requires either forging a Dilithium signature (breaking EUF-CMA) or a hash collision in H₂/H₃.

Also: Lemma 2 (Partition Completeness) — an omitted qualifying ciphertext implies either a Merkle forgery or a violation of a `RangeComplete` check per partition.

---

## VI. Evaluation

**Implementation note — different from this repo's methodology:** the paper's own reference implementation is in **Rust**, using the `pqcrypto` crate for postquantum primitives, on a system with 4 vCPUs/8GB RAM/Ubuntu 24.04 (fog/mid-tier cloud emulation) and a **Raspberry Pi 4 Model B** (quad-core ARM Cortex-A72, 1.5GHz, 4GB) for IoT client-side emulation. Blockchain interactions simulated via **Ganache** (local Ethereum-compatible chain), excluded from the critical query path. Dataset: **Synthea** (same generator this repo already uses). This repo re-implements each baseline in Python on the pinned AWS host per README §13's "implement as published, measure independently" rule — **the paper's own reported numbers below are not directly reusable and must be re-measured**, same as every other baseline here.

### Table II — Asymptotic Computational Cost Comparison

| Scheme | KeyGen | Encrypt | Trapdoor | Decrypt |
|---|---|---|---|---|
| MCP-ABSE-AR [24] | O(nm²T_mul+T_s+T_h) | O(krnmT_mul) | O(nmT_mul) | O(2T_mul) |
| ABAEKS [13] | 3T_G+k·T_mult+T_h | k·T_mult+T_h+T_G | k·T_mult+T_h+T_G | k·T_mult+m·T_mul |
| FS-MUAEKS [7] | (d+2)T_G | T_h+(d+k)T_mult+T_G | T_h+(d+k)T_mult+2T_G | m·ℓ_S·ℓ_R·T_mul |
| IBEKS [3] | nm²T_mul | L(n²+n²m+nm)T_mul | nm²T_mul | O(L²T_mul) |
| **Ours (LV-PQ-ABSE)** | O(n²T_mul+T_Kyber+T_v) | O(nmT_mult+T_E+T_Kyber) | **O(n+T_PRF)** | O(log N+T_Kyber+T_D+T_verify) |

Key claimed advantage: **trapdoor generation is O(n) — linear, PRF-dominated, no lattice sampling at query time** — vs. competitors' lattice-operation-heavy trapdoor costs. Decrypt is O(log N) via partitioned Merkle verification, not O(N).

### Baseline comparison

Compared against FS-MUAEKS [7], ABAEKS [13], IBEKS [3] (their own reference numbers) — chosen for forward security, authenticated SE, and lattice-based keyword search coverage. **Note: none of these three baselines are the schemes already implemented in this repo** (Guo=ref35, Thingom=ref41-this-repo, Zhuang=ref52-this-repo are different works) — no direct numeric overlap exists yet between this paper's reported comparisons and this repo's prior results.

- **Fig. 2:** encryption time near-constant vs. keyword count (decouples document encryption from keyword processing); trapdoor generation near-constant (PRF-based, no per-keyword lattice ops); client-side search latency lowest of all compared schemes (fog-assisted offload — client only generates tokens).
- **Fig. 3:** search time by query type (keyword/Boolean/range/fuzzy/composite) vs. number of occurrences — composite queries costliest (combine multiple primitives), Boolean cheapest.
- **Fig. 4 / Table III:** range and fuzzy queries cost more than Boolean as selectivity/range width grows (bitmap-filtering and string-matching costs dominate); client-side overhead stays low regardless (fog absorbs the cost).
- **Table IV:** Merkle verification latency/proof size vs. N — near-constant single-proof latency, proof size grows only logarithmically; batch verification throughput degrades from 723.5/s (n=10) to 14.0/s (n=1000) as expected.
- **Table V:** simulated blockchain gas cost of anchoring, amortized per record — $0.181/record at batch size 10 down to $0.0018/record at batch size 1000.

### Limitation stated by the authors themselves

"While the proposed framework provides efficient revocation with **forward security**, it does **not** support immediate or fine-grained revocation mechanisms, such as attribute-level revocation or ciphertext update. These capabilities typically incur significant computational and communication overhead in postquantum settings and are therefore beyond the scope of the current design." — **self-disclosed limitation, not found by inspection** (contrast with Thingom's undisclosed self-contradiction).

---

## VII. Conclusion

LV-PQ-ABSE: lightweight verifiable postquantum ABSE for IoT-enabled EHR systems. Combines lattice-based access control, hybrid encrypted indexing, Merkle-tree verification. Separates cryptographic enforcement from search execution. Future work: dynamic record updates, fine-grained user/attribute revocation with traceability, batch verification optimization, real-world deployment evaluation.

---

## Legitimacy / quality notes (assessed 2026-08-27, same due-diligence pass applied to Ref[41])

- **No duplicated paragraphs, no off-topic filler, no internal self-contradiction found** on a full read — unlike `Ref[41]` (Thingom), which self-refuted its own post-quantum claim twice in body text.
- **Genuinely post-quantum throughout**: every operation (Setup, KeyGen, Encrypt, Trapdoor, Decrypt) is LWE/lattice-based, Kyber768, or Dilithium3 — no pairings, no DBDH, no discrete-log assumption anywhere in the construction. The PQ claim is substantiated, not just asserted.
- **Security proofs are standard game-based reductions** to named, real hardness assumptions (LWE-hardness of the ABE, Kyber IND-CPA, Dilithium EUF-CMA, SHA-3 collision resistance) — internally consistent with the construction actually described.
- **Self-discloses its own limitation** (no fine-grained/immediate revocation) rather than glossing over it — a positive signal for research integrity.
- **Two real gaps for this benchmark to resolve before implementation** (flagged in `SCHEME.md`, same treatment as Thingom's undetermined `u`):
  1. Exact numeric lattice parameters (n, q, σ) are never given — only "consistent with Kyber768 and Dilithium3." Needs a benchmark decision, documented with a citation to this ambiguity, same as `thingom_pq_abse.attributes.u`.
  2. The paper's own evaluation numbers come from a **Rust** implementation on different hardware (Raspberry Pi 4 for edge, not this repo's pinned `m6i.xlarge`) — not directly comparable to this repo's Python/AWS measurements; must be independently re-measured here, per README §13.
- Journal (*IEEE Internet of Things Journal*) is a substantially more specialized, higher-standing venue for this subject matter than *IEEE Transactions on Consumer Electronics* (Ref[41]'s venue).

---

## References (this paper's own bibliography, its own numbering — do not conflate with this repo's Ref[N])

[1] D. Boneh, G. Di Crescenzo, R. Ostrovsky, and G. Persiano, "Public key encryption with keyword search," EUROCRYPT 2004, doi: 10.1007/978-3-540-24676-3_30.
[2] R. Behnia, M. O. Ozmen, and A. A. Yavuz, "Lattice-based public key searchable encryption from experimental perspectives," IEEE TDSC, vol. 17, no. 6, pp. 1269–1282, 2020, doi: 10.1109/TDSC.2018.2867462.
[3] Z. Lin, H. Li, X. Chen, M. Xiao, and Q. Huang, "Identity-based encryption with disjunctive, conjunctive and range keyword search from lattices," IEEE TIFS, vol. 19, pp. 8644–8657, 2024, doi: 10.1109/TIFS.2024.3459646.
[4] Y. Hou, W. Yao, S. Li, X. Yia, and M. Wang, "Lattice-based semantic-aware searchable encryption for IoT," IEEE IoT-J, vol. 11, no. 17, pp. 28370–28384, 2024, doi: 10.1109/JIOT.2024.3400816.
[5] C. Li et al., "Efficient medical big data management with keyword-searchable encryption in healthcare," IEEE Syst. J., vol. 16, no. 4, pp. 5521–5532, 2022, doi: 10.1109/JSYST.2022.3173538.
[6] L. Liu, S. Wang, B. He, and D. Zhang, "A keyword-searchable ABE scheme from lattice in cloud storage environment," IEEE Access, vol. 7, pp. 109038–109053, 2019, doi: 10.1109/ACCESS.2019.2928455.
[7] S. Xu et al., "Lattice-based forward secure multi-user authenticated searchable encryption for cloud storage systems," IEEE Trans. Comput., vol. 74, no. 5, pp. 1663–1677, 2025, doi: 10.1109/TC.2025.3540649.
[8] X. Yu, C. Xu, and L. Xu, "Lattice-based searchable encryption with keywords revocable and bounded trapdoor exposure resistance," IEEE Access, vol. 7, pp. 43179–43189, 2019, doi: 10.1109/ACCESS.2019.2908202.
[9] H. Wang, Y. Liao, Z. Zhang, Y. Dong, and Z. Zhou, "Lattice-based revocable IBEET scheme for mobile cloud computing," IEEE Trans. Cloud Comput., vol. 13, no. 3, pp. 807–820, 2025, doi: 10.1109/TCC.2025.3570332.
[10] B. Yang, R. Zhao, and J. Wei, "Lattice-based punctureable identity-based encryption with keyword search for cloud storage," ICNLP 2025, doi: 10.1109/icnlp65360.2025.11108368.
[11] L. Qi and J. Zhuang, "Efficient public key searchable encryption schemes from standard hard problems for cloud computing," Cryptol. ePrint Arch. 2022/1374.
[12] J. Jiang and D. Wang, "QPASE: Quantum-resistant password-authenticated searchable encryption for cloud storage," IEEE TIFS, vol. 19, pp. 4231–4246, 2024, doi: 10.1109/TIFS.2024.3372804.
[13] F. Luo, H. Wang, C. Lin, and X. Yan, "ABAEKS: Attribute-based authenticated encryption with keyword search over outsourced encrypted data," IEEE TIFS, vol. 18, pp. 4970–4983, 2023, doi: 10.1109/TIFS.2023.3301740.
[14] X. Zhang and C. Xu, "Trapdoor security lattice-based public-key searchable encryption with a designated cloud server," Wireless Pers. Commun., vol. 100, no. 3, pp. 907–921, 2018, doi: 10.1007/s11277-018-5357-6.
[15] G. Xu, Y. Cao, and S. Xu, "A searchable encryption scheme based on lattice for log systems in blockchain," Comput. Mater. Continua, vol. 72, no. 3, pp. 47564–47583, 2022.
[16-23], [25-42] — omitted here (standard SE/ABE literature); see PDF for full list.
[24] X. Shen, X. Li, H. Yin, C. Cao, and L. Zhang, "Lattice-based multi-authority ciphertext-policy attribute-based searchable encryption with attribute revocation for cloud storage," Comput. Netw., vol. 250, Aug 2024, Art. no. 110559, doi: 10.1016/j.comnet.2024.110559.
[38] U. S. Varri, S. K. Pasupuleti, and K. V. Kadambari, "CP-ABSEL: Ciphertext-policy attribute-based searchable encryption from lattice in cloud storage," Peer Peer Netw. Appl., vol. 14, no. 3, pp. 1290–1302, 2021, doi: 10.1007/s12083-020-01057-3.
[41] S. Fugkeaw, K. Tangtanawirut, R. Pattanasrisuk, and A. Changtor, "MK-WISE: Secure and efficient multi-keyword wildcard ABSE with keyword-level revocation for device–edge–cloud EHRs data sharing," IEEE Trans. Netw. Serv. Manage., vol. 23, pp. 2295–2311, 2026, doi: 10.1109/TNSM.2026.3657982. (**self-citation by this paper's second author**)
[43] G. Xu et al., "Toward authenticated encrypted search with constant trapdoor for mobile cloud systems," IEEE Trans. Mobile Comput., vol. 25, no. 4, pp. 4890–4903, 2026, doi: 10.1109/TMC.2025.3627241.
[44] Rust Project Developers, *The Rust Programming Language*. [Online]. Available: https://www.rust-lang.org
[45] Pqcrypto Rustpq Project, *Pqcrypto: Post-Quantum Cryptography in Rust*. [Online]. Available: https://github.com/rustpq/pqcrypto
[46] Truffle Suite, *Ganache: A Personal Blockchain for Ethereum Development*. [Online]. Available: https://trufflesuite.com/ganache
[47] *Synthea: Synthetic Patient Population Simulator*. [Online]. Available: https://synthetichealth.github.io/synthea/
