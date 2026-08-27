# Feng et al. BL-ABSE — Scheme Experiment Guide (Ref[57])

**Back to main README:** [README.md](../../README.md)
**Paper:** Z. Feng, W. Yang, Y. Hu, Y. Yin, T. Ma, X. Tian, X. Deng, "Blockchain-Enabled Lattice-Based Attribute-Based Searchable Encryption with Instant Revocation," *Electronics* (MDPI), vol. 15, no. 11, art. 2471, June 2026, doi: `10.3390/electronics15112471`. Open access (CC-BY). Extracted text: [References/Ref[57]/Ref[57].md](../../References/Ref[57]/Ref[57].md).

**Status (2026-08-28): NOT YET IMPLEMENTED.** `src/` does not exist. This file records what the paper publishes, what it does not, and the decisions needed before implementation — same treatment as `thingom_pq_abse/SCHEME.md` and `perera_lv_pqabse/SCHEME.md`.

---

## Why this was added

Added 2026-08-28 as a **fifth** scheme (additive — nothing was dropped for it). Before it, no baseline covered Exp. 6 (authorization sync) at all, and only `guo_vdsse` covered Exp. 5. `perera_lv_pqabse` (Ref[54]) could not fill those slots: it defines no incremental-update primitive and explicitly self-discloses that it has no fine-grained revocation, only coarse whole-epoch key evolution.

BL-ABSE's **headline contribution is exactly the mechanism Exp. 6 measures**: instant, on-chain, single-transaction permission revocation with no re-encryption and no key redistribution, with a proven O(1) revocation bound (Theorem 9) and measured flat ~2s latency across N=100→50,000 (vs. baselines that blow up to 28 minutes at the same scale). That makes it the natural Exp. 6 comparator.

**Venue note (raised by the user, recorded deliberately):** this is the only non-IEEE venue among the implemented baselines (`guo_vdsse`=IEEE TDSC, `thingom_pq_abse`=IEEE TCE, `perera_lv_pqabse`=IEEE IoT-J). MDPI *Electronics* is a real Scopus/Web-of-Science-indexed journal, not predatory or delisted, but MDPI as a publisher carries less prestige in the security community than IEEE. The decision to include it was made on **content quality** — on the legitimacy checks this repo applies (see `Ref[57].md`'s assessment section) it is the most rigorous of the three reference papers vetted here, and the only one that quantifies its own leakage, labels its simulated baseline numbers as simulated, and self-identifies five limitations. Cite it plainly as MDPI *Electronics*; do not obscure the venue.

---

## Experiments (2 of 8 confirmed, 1 pending a decision)

| # | Experiment | Fit | Notes |
|---|-----------|-----|-------|
| 1 | Trapdoor Generation Latency | **Yes** | `Trapdoor` (Alg. 4) is purely local — one NTT polynomial multiplication + one signature, no network/blockchain round-trip. The paper's own Table 8 gives `O(n log n)` token generation. |
| 2 | Search Latency | **Yes, strong** | `BC-Search` (Alg. 5) is a real linear scan over the whole DB. Paper's measured data (Table 9, 8 points N=100→50,000, reps=30) gives a stable **28.8–29.7 μs/record** — useful as an independent sanity check on a from-scratch implementation, though not reusable as this repo's number (see below). |
| 6 | Authorization Sync | **Yes, strong** | The scheme's headline mechanism. `RevokeAccess` is one blockchain transaction, ~2s, proven O(1) in system size (Theorem 9), measured flat 2019–2065ms across N=100→50,000. Directly measures what Exp. 6's δ sweep asks for. |
| 3 | Cross-Domain Scalability | **Decision needed** | The system model has **no notion of a domain at all** (six entities, none of them domain-scoped). Either apply the same native-mode rule used for Guo/Thingom (`d` independent searches + client-side aggregation), or exclude Exp. 3 on the grounds that native mode isn't faithful for a scheme with no domain concept. **Must be an explicit decision, not a default.** |
| 4 | Verification Overhead | **Probably not** | The scheme has on-chain audit logging and hash-chain tamper-evidence (Theorem 8), but no client-side Merkle-proof verification of *search-result completeness*, which is what this repo's Exp. 4 boundary measures (README §5). Do not map audit-log immutability onto result verification — they are different properties. |
| 5 | Dynamic Keyword Update | **No** | No standalone update primitive. `BC-Encrypt` (data upload) is the only path by which records enter the system; there is no distinguished incremental-update algorithm to time. Same reason `perera_lv_pqabse` was excluded from Exp. 5 — measuring a full re-encrypt-and-upload and labelling it an "update" would misrepresent the construction. |
| 7, 8 | Throughput / Load Balancing | **No** | Proposed-scheme-only ablations (README §5). No baseline participates. |

---

## Published parameters (all concrete, unlike Ref[54])

Unusually complete — the paper fixes every cryptographic parameter numerically, which removes the "benchmark decision required" burden that `thingom_pq_abse.attributes.u` and `perera_lv_pqabse`'s lattice parameters both carry.

| Parameter | Value | Source |
|---|---|---|
| Security parameter λ | 128 | Table 1 |
| Lattice dimension `n` | 1024 | Table 1, Alg. 1 line 1 |
| Prime modulus `q` | 12,289 | Table 1 — the *smallest* prime satisfying the NTT constraint `q ≡ 1 (mod 2n)`, a real derivable choice |
| Gaussian std dev σ | 3.2 | Table 1 |
| Commitment-match threshold `B` | 40 | Alg. 1 line 1; derived from noise analysis (§4.11) |
| Ring | `R_q = Z_q[x]/(x^1024 + 1)` | Table 1 |
| Symmetric encryption | AES-256-GCM, 96-bit nonce | Alg. 3 |
| Hashes | `H : {0,1}* → R_q` (keyword encoding), `H_seed : {0,1}* → {0,1}^256` (seed derivation) — independence is load-bearing for the security proof | Alg. 1 design notes |
| Threshold config | `(t,n)`, typical `(3,5)`, tolerates `⌊(n−1)/3⌋` Byzantine | Assumption 3, Theorem 1 |
| Blockchain | Hyperledger Fabric, PBFT, 2s block time | Alg. 1 lines 5–6 |
| Storage | IPFS, CID ≈ 46 bytes on-chain, policy hash 32 bytes | §3.1.2 |

Claimed security: 128-bit PQ. The paper backs this with an actual root-Hermite-factor calculation (δ≈1.0082 → BKZ β≈456 → 2^133 classical Core-SVP, 2^121 quantum sieving), not a bare assertion.

**One thing to note for `Common/` scope (README §8):** this repo's existing `Common/crypto/lattice.py` implements the **MP12 gadget-trapdoor toolkit** (TrapGen/SamplePre) that the dropped Ref[52] needed. BL-ABSE needs **neither** — its commitment is `a·s + H(w) mod q` with `s` derived by hashing, no trapdoor sampling anywhere. What it *does* need and this repo does not yet have is an **NTT implementation** over `R_q` with negacyclic (negative-wrapped) convolution. That is a paper-*cited* standard primitive, not a paper-*contributed* one, so per README §8's `Common/` scope rule it likely belongs in `Common/crypto/`, not in this scheme's `src/` — worth confirming when a second scheme needs it, per the rule's own "if two schemes need the same construction" test.

---

## Construction summary (nine algorithms, Definition 12)

`BC-Setup` · `ThresholdKeyGen` · `BC-Encrypt` · `Trapdoor` · `BC-Search` · `Decrypt` · `RevokeAccess` · `UpdatePolicy` · `QueryAuditLog`

**The core mechanism, and why it is fast:** the keyword commitment is `commit = a·s + H(w) mod q`, where `s = GaussianSample(H_seed(w), σ)` is derived from the keyword via a **public** hash — not from any user secret. Encryption and trapdoor generation run *identical* Steps 1–3, so the same keyword always yields byte-identical commitments and matching is a plain distance check: `dist = Σ_j centered(commit_i − commit_q)[j]²  ≤  B`.

`BC-Search` (Alg. 5) walks **every** `(I_i, CID_i)` in the database — policy check, revocation check, then the distance computation. So it is an **unfiltered linear scan, structurally the same shape as Thingom's**, but the per-record work is `n=1024` centered modular subtractions and squares (cheap integer arithmetic) instead of `2u+1` real bilinear pairings. That mechanism — same scan shape, ~4 orders of magnitude cheaper per record — is the honest explanation for the gap between its 29 μs/record and Thingom's ~14.8 ms/entry, and is worth stating that way rather than implying an algorithmic advantage it does not claim.

Security: six properties proven under a QPT adversary via sequential game reductions to RLWE and SIS hardness. No pairings, no DBDH, anywhere.

---

## Decisions needed before implementation

| # | Decision | Why it can't be defaulted |
|---|---|---|
| 1 | **Exp. 3 in or out** (see table above) | The scheme has no domain concept. Native mode is defensible but is a benchmark reading, not the published construction — same class of call as Thingom's `independent_trapdoors` mode, which is recorded in `crypto.yaml` with its reasoning. |
| 2 | **Blockchain dependency for Exp. 6** | `RevokeAccess`'s ~2s latency is *dominated by PBFT block confirmation*, not by cryptography. Measuring it faithfully needs a real Hyperledger Fabric instance (the repo already provisions one for `ma_lb_pq_vdse` — `infra/fabric/docker-compose.yaml`). Decide whether Exp. 6 for this scheme uses that same Fabric deployment (fair, comparable) or a stubbed 2s constant (cheap, but then it is not a measurement). |
| 3 | **Multi-keyword handling** | The paper is **single-keyword exact-match only** and self-discloses this as limitation #1. This repo's default `q=5` therefore needs the same native-mode treatment as Thingom: `q` independent trapdoors + `q` independent searches, client-side intersection. Record it in `crypto.yaml` alongside `thingom_pq_abse.multi_keyword.mode`. |
| 4 | **NTT implementation placement** | See the `Common/` scope note above. |

---

## Implementation note: the paper's own numbers are not reusable

Reference implementation is **Python 3.10 + NumPy 1.24** on an Intel Xeon E5-2680 v4 (2.4 GHz, 14 cores), 64 GB RAM, Ubuntu 22.04, with Hyperledger Fabric 2.5 in Docker. Language matches this repo (unlike Ref[54]'s Rust), but the hardware does not — 14 cores / 64 GB vs. the pinned `m6i.xlarge`'s 4 vCPU / 16 GB. Per README §13, re-implement and re-measure here; use the paper's Table 6/9 figures only as a sanity check on asymptotic shape (17.4× NTT speedup at n=1024; ~29 μs/record flat), never as reported results.

---

## Folder Structure (planned, not yet created)

```
feng_bl_abse/
├── SCHEME.md                       # This file
├── src/
│   ├── scheme.py                   # BC-Setup, ThresholdKeyGen, BC-Encrypt, Trapdoor, BC-Search, Decrypt
│   ├── ntt.py                      # NTT / negacyclic convolution  (or Common/crypto/ — see scope note)
│   ├── revocation.py               # RevokeAccess, UpdatePolicy, on-chain revocation list
│   ├── experiments.py              # Exp. 1, 2, 6 (+3 if decision 1 says yes)
│   ├── harness.py                  # Timing, 95% CI, CSV/meta output (mirror thingom_pq_abse/src/harness.py)
│   └── main.py                     # CLI + reportability gating
├── exp1_trapdoor_generation/
├── exp2_search_latency/
└── exp6_authorization_sync/
```

---

## Output

Same format as every other scheme — see main [README.md](../../README.md) §9.
