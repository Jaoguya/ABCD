# Verifiable Multilevel Dynamic Searchable Encryption With Forward and Backward Privacy in Cloud-Assisted IoT

Yue Ge, Ying Gao *(Member, IEEE)*, Jianting Ning *(Member, IEEE)*, Jie Ma, and Xiaofeng Chen

*IEEE Internet of Things Journal*, vol. 11, no. 24, 15 December 2024, pp. 40861–40874.
Received 28 May 2024; revised 7 August 2024 and 28 August 2024; accepted 3 September 2024. Date of publication 10 September 2024; date of current version 6 December 2024.
Supported by the National Key R&D Program of China under Grant 2022YFB2701600. Corresponding author: Ying Gao.
Beihang University (Ge, Gao, Ma, Chen) and Fujian Normal University (Ning).

Digital Object Identifier: **10.1109/JIOT.2024.3457270**

*Index Terms* — Access control, dynamic searchable symmetric encryption (DSSE), forward and backward privacy, smart contract, verification.

Source PDF: `Verifiable_Multilevel_Dynamic_Searchable_Encryption_With_Forward_and_Backward_Privacy_in_Cloud-Assisted_IoT.pdf` (14 pages).

---

## Abstract

Data and users are hierarchical in IoT applications, requiring fine-grained multilevel access control, and public verification is needed to resist a malicious server and clients. The authors propose **Peony**, a forward-private multilevel dynamic searchable symmetric encryption (MLDSSE) scheme built on multilevel linked lists and a constrained PRF. They then introduce a primitive named **multilevel symmetric revocable encryption (MSRE)** and give a generic construction of **Peony++**, a forward- and Type-II backward-private MLDSSE scheme. Multilevel digests plus an Ethereum smart contract provide public verification. Peony reduces search time by an average of 35.81% versus the state-of-the-art MLDSSE scheme (Alderman).

---

## 1. What this paper actually contributes

Three artifacts, in dependency order:

1. **MSRE** (§IV) — a multilevel generalization of Sun et al.'s symmetric revocable encryption (SRE, their [6] = Aura). SRE supports only single-keyword DSSE; MSRE carries `|L|` Bloom-filter arrays so revocation can be expressed per access level.
2. **Peony** (§V) — forward-private MLDSSE. No backward privacy. This is the *fast* scheme.
3. **Peony++** (§VI) — Peony + MSRE, giving forward **and Type-II backward** privacy, plus public verification via multilevel digests on a smart contract. This is the *secure* scheme.

Both are **symmetric-key** constructions (HMAC/SHA-256/AES/keccak256). There is no public-key operation and no pairing anywhere on the critical path.

---

## 2. Preliminaries used (§III)

| Primitive | Role | Repo equivalent |
|---|---|---|
| Constrained PRF `F.Constrain / F.Eval` | prefix-constrained token; server derives `3c` PRF values from one constrained key | `Common/crypto/prf.py` |
| Bloom filter `BF.Gen / BF.Upd / BF.Check` | compresses the revoked-tag list, one `b`-bit array per access level | `Common/crypto/bloom.py` |
| t-puncturable PRF `Ft.setup / Ft.punc / Ft.eval` | MSRE key revocation; **instantiated with a GGM tree** (§VI-B) | `Common/crypto/prf.py::PuncturablePRF` |
| Symmetric encryption `SE.Gen/Enc/Dec` | encrypts the file identifier under each BF-indexed leaf key | `Common/crypto/symmetric.py` |
| Ethereum smart contract | executes `Verify`, holds `prooflist` | not reproducible on the benchmark host — see §6 |

**Multilevel access (MLA) policy** (§V-A): a user at level `a(u)` may retrieve files with `a(id) <= a(u)`. Level 3 is highest, level 1 lowest.

---

## 3. Construction summary

### 3.1 MSRE (§IV-B)

- `MSRE.BGen(1^L, b, h, L)` produces `lsk = (sk <- Ft.Setup, H, B = {B_1..B_|L|})`, each `B_l = 0^b`.
- `MSRE.Enc(lsk, m, a(m), t)`: `j_i = H_i(t)` for `i in [h]`; `sk_{j_i} = F(sk, j_i)`; `ct_i = SE.Enc(sk_{j_i}, m)`; output `ct = (ct_1..ct_h)` and `t`.
- `MSRE.KLRev(lsk, R, L_R)`: classify `R` by level; `B_{R_l} <- BF.Upd(H, B_l, R_l)`. **Level propagation is upward:** entries set for level `l` are also set in every `B_x` with `x > l`. Then `I_l = {j : B_{R_l}[j] = 1}`, `sk_{I_l} <- Ft.punc(sk, I_l)`, `sk_{R_l} = (sk_{I_l}, H, B_{R_l})`.
- `MSRE.Dec(sk_{R_l}, ct, t)`: if `BF.Check(H, B_{R_l}, t) = 1` decryption fails; else find `j*` with `B_{R_l}[j*] = 0`, derive `sk_{j*} = Ft.eval(sk_{I_l}, j*)`, return `SE.Dec(sk_{j*}, ct_{j*})`.

Correctness error comes **only** from the Bloom filter false positive. The paper states this explicitly and calls the resulting `negl` "possibly non-negligible" — an honest admission.

### 3.2 Peony (§V-D, Algorithm 1)

- `KeyGen(1^L)` produces `K_O = ({k_l}, st_1, st_2, ...)`. One key per access level, plus per-update-batch states `st_c`.
- `ListGen(D_w, c, op)` produces `(L_w, X_w, N_w)`: `L_w` holds `(id||op)` sorted **descending by access level**; `X_w` holds the start index per level; `N_w` holds `|L_w|` distinct random addresses in array `A_c`.
- `Update(D_W, c, K_O)`: each `L_w` becomes an encrypted linked list in `A_c`. Node `j` stores `(L_w[j], N_w[j+1], F3_{k_a(L_w[j+1])}(w||st_c)) XOR H(F3_{k_a(L_w[j])}(w||st_c), r_j)` together with `r_j`. Table `T_c[F1_{k_l}(w||st_c)] <- N_w[X_w[l]] XOR F2_{k_l}(w||st_c)`, or bottom when level `l` sees nothing.
- `Search(k_{a(u)}, w, c; I)`: user sends `tk_{w,a(u)} <- F.Cons(k_{a(u)}, w)` and `ST = {st_1..st_c}`. Server derives `t1, t2, t3` per batch via `F.Eval`, locates `T_j[t1]`, decrypts to the start address, then walks the chain in `A_j` applying `add`/`del`.

**Forward privacy** comes from `st_c`: a token for batches `1..c` cannot address batch `c+1`.

The user's cost is **one constrained-PRF evaluation**, independent of result size — this is the paper's "suitable for resource-limited IoT users" claim.

### 3.3 Peony++ (§VI-A)

`Setup`, `ListGen`, `Add`, `Delete`, `Search`, `Verify`.

- Deletion no longer writes `del` entries into the index. Instead the owner inserts the tag `t <- F_{K_t}(w, id)` into the level-appropriate Bloom filters (`B_{w,l}` and every higher level) — an **O(1) local operation, no server round-trip**.
- `Add` additionally builds a `prooflist` entry per `(w, level)`:
  `prooflist[pt^c_{w,l}] = H(0, r^c_{w,l}) XOR (XOR_j H(1, C_{id_j}))` over all files at level `<= l`, where `r^c_{w,l} = H(F.Cons(k_l, w), c||2)`.
- `Search` is Peony's search plus `MSRE.Dec` per retrieved ciphertext; the data owner assists by supplying `B_{w,a(u)}` and the revoked key `sk_{R_l}`.
- `Verify(R_{w,a(u)}, prooflist, proof_del)`: XOR-combine the per-batch `prooflist` entries with the deletion digest to get `proof'`, compute `hash_R = XOR_{C_{id_j} in R} H(1, C_{id_j})`, accept iff equal. This is **multiset hashing over XOR** — order-independent, constant-size.

---

## 4. Published parameters

| Parameter | Value | Where |
|---|---|---|
| Access levels `\|L\|` | **3** (level 3 highest) | §VII-A |
| BF false-positive rate `p` | **1e-4** (same as Aura) | §VII-A |
| BF hash count `h` | **5** and **13** (both reported) | Tables V–VII |
| BF array size `b` | `b = -d * ln p / (ln 2)^2` | §VII-B |
| Deletions between searches `d` | 10, 100, 1000, 10 000 | Tables V–VII |
| File identifier length | <= **32 bytes** | §VII-A |
| MSRE instantiation | GGM-tree t-punc-PRF; `h = 2` in the worked example (§VI-B) | §VI-B |
| Hashes | SHA-256, keccak256 (OpenSSL) | §VII-A |
| SE | AES | §VII-A |
| Smart contract | Solidity 0.8.21, Remix, Ganache testnet; gas price 2 Gwei | §VII-A, §VII-B |
| `prooflist` entry size | **144 B** on-chain per added batch | §VII-B |
| Deletion digest size | **32 B** per level touched (96 B if a level-1 file is deleted) | §VII-B |
| Search comm. cost, Peony | **96 B** constant | §VII-B |
| Search comm. cost, Peony++ (`h=5`) | 132 B / 446 B / 3.636 KB / 35.466 KB for `d` = 10/100/1000/10 000 | §VII-B |
| Search comm. cost, Peony++ (`h=13`) | 120 B / 266 B / 2.436 KB / 23.496 KB | §VII-B |
| Data-user search time | **0.95 us**, constant | §VII-B |

### Reported timings (their hardware, not ours)

Addition time, ms/id (Table VI, LAN): Peony `1.40e-6` to `1.45e-6`; Peony++ `h=5` `0.051`–`0.089`; Peony++ `h=13` `0.089`–`0.210`; Aura `h=5` `0.050`–`0.090`; Guo `1.20e-4`–`1.24e-4`; SD_d `26.21`–`26.49`.

Deletion time for `d = 1000` (Table VII, us): Peony++ `h=5` level 3/2/1 = `0.84 / 1.2 / 2.2`; Peony++ `h=13` = `2.1 / 3.2 / 5.1`; Peony LAN = `1.4`.

BF storage (Table V, KiB) at `d = 10 000`: level 1 = `106.110` (`h=5`) / `70.200` (`h=13`); level 3 = `35.370` / `23.400`.

### Their evaluation environment (Table IV)

Laptop: Intel Core i7-13700H, 16 GB RAM, 512 GB, Ubuntu 20.04 x64. AliCloud `ecs.hfc6.4xlarge`: Intel Xeon Platinum 8269, 32 GB, 256 GB. C++ / G++ 11.4.0, OpenSSL, Apache Thrift. LAN 0.02 ms / 1000 Mb/s; WAN 200 Mb/s with 106 ms (Singapore) and 191 ms (Silicon Valley) RTT.

Dataset: **Wikipedia**, 34 390 712 keyword/file pairs, 2 208 469 files, 726 092 keywords, Porter-stemmed.

---

## 5. What the paper does NOT publish

These become benchmark decisions and must be recorded deliberately (same treatment as `thingom_pq_abse.attributes.u` and `perera_lv_pqabse`'s `(n,q,sigma)`):

1. **`lambda` is never fixed numerically.** "OpenSSL ... HMAC, SHA-256, keccak256" and "AES" are named, but no key length is stated. AES-128 vs AES-256 is unresolved.
2. **The number of update batches `c` is never fixed.** §V-D says only "We implement batch updating; thus, `c` is relatively small." Search cost is `O(c)` PRF evaluations, so `c` is directly results-affecting.
3. **The GGM tree domain size** (tree depth) is not stated. It bounds how many BF positions the t-punc-PRF can address.
4. **How files map to access levels** is never specified — the Wikipedia corpus carries no level attribute, and the paper does not say how it assigned one. Any reimplementation must invent this.
5. **`h = 5` vs `h = 13`** is reported as two settings with no default declared. Both must be run or one must be chosen and justified.
6. **Which `d` is the default** for the search experiments is not stated; Figs. 6–7 sweep it.

---

## 6. Legitimacy / quality notes (assessed 2026-08-28, same due-diligence pass as Ref[41] and Ref[54])

- **Venue gate: PASSES.** *IEEE Internet of Things Journal* — IEEE-published, DOI `10.1109/JIOT.2024.3457270`. Same journal as Ref[54]. Not MDPI, not Springer/Elsevier/ACM, not a preprint.
- **No duplicated paragraphs, no off-topic filler, no self-contradiction** found on a full read of all 14 pages. Contrast Ref[41] (Thingom), which self-refuted its own post-quantum claim twice.
- **The claimed security matches the construction.** Forward privacy is delivered by the per-batch state `st_c` (the mechanism is visible in Algorithm 1, not just asserted). Type-II backward privacy is delivered by MSRE revoking the server's ability to decrypt deleted entries — again visible in `MSRE.KLRev`/`MSRE.Dec`. Security reduces to named assumptions (t-punc-PRF security, BF parameters, IND-CPA of SE).
- **Does NOT claim post-quantum security, and does not need to.** This is a symmetric-key construction (HMAC-SHA-256, AES, keccak256, GGM-PRF). There is no pairing, no DBDH, no discrete log — so the Ref[41] failure mode is structurally absent. Grover gives only a quadratic speedup against symmetric primitives. **Note for the manuscript:** this makes it a legitimate baseline, but it is **not** a post-quantum *claim* to compare against ours — cite it for verifiability and forward/backward privacy, not for PQ.
- **Quantifies its own leakage** — `sp(q)` (search pattern) and `UpHist(q)` (update history) are written out explicitly in §V-B, and the update phase is stated to leak nothing. Positive integrity signal.
- **Lists its own limitations and future work** honestly (§IX): Peony++ still needs data-owner assistance at search time; no Type-I backward privacy; single-keyword only.
- **Full security proofs are in supplementary material**, not the main PDF. We hold the main paper only. The *constructions* are complete in Algorithm 1 and §VI-A, so implementation is not blocked, but the proofs cannot be independently checked from what we have.
- **Two gaps for this benchmark**, both carried into `Schemes/yue_ge/SCHEME.md`:
  1. The evaluation is **C++ on an i7-13700H laptop + AliCloud Xeon**, not this repo's pinned `m6i.xlarge`, and the dataset is **Wikipedia**, not our Synthea corpus. Their absolute numbers are not comparable to ours and must be independently re-measured here (README §13).
  2. **Access-level assignment is undefined** (§5 item 4) and must be a documented benchmark choice.

### Single-keyword only

Peony and Peony++ search **one keyword** per query (`Search(k_{a(u)}, w, c; I)`). The paper never defines a conjunctive form. A `q`-keyword query therefore runs as `q` independent tokens with client-side intersection — the same native-mode rule README §3 applies to Exp. 3, and the same treatment `thingom_pq_abse` already uses for Ref[41].

### Ethereum is not reproducible on the benchmark host

`Verify` executes inside a Solidity contract on Ganache. The benchmark host (`m6i.xlarge`) runs no Ethereum node, and gas cost is not a latency measurement.

This is **not** the Ref[36]/SGX situation. There, the *search algorithm itself* ran inside an enclave, so simulating it would have omitted enclave-transition and EPC-paging cost and flattered the baseline. Here the verification **computation** (multiset hashing, XOR combination, equality check) is ordinary CPU work that runs identically off-chain; only the *transaction* is chain-bound. Measuring the computation and excluding the transaction matches how README §5 already scopes Exp. 4 for the proposed scheme ("client-side verification only ... IPFS fetch and decryption excluded"). Gas cost is recorded from the paper as a reported figure and never re-measured.

---

## 7. Relationship to the other baselines in this repo

- **Ref[35] (Guo VDSSE)** — this paper implements and benchmarks Guo directly, as its "Guo [37]" (forward-private SSE with smart-contract digests). Peony++ and Guo are reported as comparable for on-chain verification cost, with Peony++ additionally achieving Type-II backward privacy. That makes Ref[55] a **direct peer of Ref[35]** and the natural second baseline for Exp. 4.
- **Aura (their [6], Sun et al.)** — the SRE-based scheme MSRE generalizes. Not implemented in this repo.
- **Alderman (their [5])** — the multilevel SSE scheme Peony beats by 35.81%. Not implemented in this repo.

---

## 8. This paper's own bibliography (its numbering — do not conflate with this repo's Ref[N])

Key entries referenced above:

- [5] J. Alderman et al., multilevel SSE — the MLDSSE baseline Peony is compared against.
- [6] S. Sun et al., "Practical non-interactive searchable encryption with forward and backward privacy" (Aura) — source of SRE, which MSRE generalizes.
- [12] R. Bost, B. Minaud, O. Ohrimenko, "Forward and backward private searchable encryption from constrained cryptographic primitives," ACM CCS 2017 — Types I/II/III backward privacy.
- [15] I. Demertzis et al., "Dynamic searchable encryption with small client storage" (SD_a, SD_d), NDSS 2020.
- [19] R. Bost, "Sophos: Forward secure searchable encryption," ACM CCS 2016.
- [37] Guo et al. — **this repo's Ref[35]**, smart-contract digests with forward privacy.
- [40] Y. Zhang, J. Katz, C. Papamanthou, "All your queries are belong to us: The power of file-injection attacks on searchable encryption," USENIX Security 2016.
- [43] Ethereum; [47] smart contracts.

Full list in the PDF, pp. 40873–40874.
