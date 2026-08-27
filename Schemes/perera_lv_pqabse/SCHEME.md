# Perera & Fugkeaw LV-PQ-ABSE — Scheme Experiment Guide (Ref[54])

**Back to main README:** [README.md](../../README.md)
**Paper:** M. Perera and S. Fugkeaw, "LV-PQ-ABSE: A Lightweight Verifiable Postquantum Attribute-Based Searchable Encryption Scheme with Hybrid Indexing and Provenance-Aware Verification for IoT-Based EHRs," *IEEE Internet of Things Journal*, vol. 13, no. 15, pp. 34302–34317, Aug. 2026, doi: `10.1109/JIOT.2026.3695855`. Extracted text: [References/Ref[54]/Ref[54].md](../../References/Ref[54]/Ref[54].md).

**Status (2026-08-27): NOT YET IMPLEMENTED.** `src/` does not exist yet. This file records what the paper publishes, what it doesn't, and the decisions needed before implementation starts — same rigor `thingom_pq_abse/SCHEME.md` and `crypto.yaml` already apply to Ref[41].

---

## Why this replaced Ref[52] (Zhuang)

Zhuang's `exp2_search_latency/runner.py` never built a real N-record index — it encrypted one real ciphertext and approximated an N-record scan by replaying `search()` on that single entry N times inside each of the 30 measured reps. That's a different methodology from every other scheme here (`guo_vdsse`, `thingom_pq_abse`, and this repo's own `ma_lb_pq_vdse` all build a real index of the swept size once, untimed, then measure the real search 30×). Fixing it properly meant vectorizing the unbatched `p6_encrypt.py` loop — real crypto-engineering work with a real correctness risk already flagged in `debug_history.md` (int64→float64 overflow at `n=284, q=2^24`). Rather than either accept that risk under a tight schedule or ship a disclosed approximation, the team replaced the baseline with Ref[54] — already cited in the manuscript's related work (`\cite{ref54}`), and confirmed genuinely lattice-based end-to-end (see legitimacy notes in `Ref[54].md`).

---

## Experiments (3 of 8) — narrower than Zhuang's old slot, deliberately

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | PRF-based tokenization, no lattice sampling at query time — paper's own headline claim (Table II: `O(n + T_PRF)`) |
| 2 | Search Latency | Fog-offloaded hybrid index (B⁺-tree + bitmap + n-gram); client only generates tokens |
| 3 | Cross-Domain Search Scalability | Paper has no native multi-domain notion — same native-mode treatment (independent per-domain trapdoors/searches, client-side aggregation) as `thingom_pq_abse` and `guo_vdsse` will be needed; not detailed by the paper, a benchmark decision |

**Not** Exp. 4 (verification overhead is comparable in spirit — partitioned Merkle proofs — but this repo's Exp. 4 boundary is defined against `ma_lb_pq_vdse`'s own verification path; needs a decision before inclusion, not defaulted to "yes").

**Excluded 2026-08-27, was in Zhuang's slot:**
- **Exp. 5 (Dynamic Keyword Update)** — the paper defines no incremental-update algorithm. Indexes are constructed fresh at Phase 3 (fog-side); there is no update primitive to measure. Including it would mean measuring a full rebuild and calling it an "update," which is exactly the kind of mischaracterization README §13 forbids.
- **Exp. 6 (Authorization Sync)** — the paper **self-discloses** (its own Sec. IV.C, quoted in full in `Ref[54].md`): *"it does not support immediate or fine-grained revocation mechanisms, such as attribute-level revocation or ciphertext update... beyond the scope of the current design."* Only coarse, whole-epoch key evolution exists (`K_ephem = HKDF(K_m, id_session)`, epoch transitions invalidate keys wholesale). Using this as "the representative baseline for authorization sync" — as Zhuang's slot did — would claim a capability the paper explicitly disclaims. Exp. 6 is now an internal ablation of the proposed scheme's IAS mechanism only, with no baseline (matches Exp. 7–8's existing framing).

---

## Construction (Phases 1–5, from the paper)

Single Trusted Authority (TA) — **not** multi-authority, same caveat as `thingom_pq_abse` (README §3 calls Thingom "multi-authority ABSE" when it isn't either; don't repeat that mistake here — this paper never claims multi-authority).

1. **Phase 1 — System Setup.** `ABE.Setup`, `Kyber768.KeyGen`, `Dilithium3.KeyGen`; precomputed trapdoor matrices via `TrapGen`; `mpk = {PP_ABE, PK_Kyber, VPK_Dilithium}`.
2. **Phase 2 — Edge-Side Encryption** (`Algorithm 1: EdgeEncrypt`). AES-256-GCM record encryption + dual encapsulation (`ct_abe` via lattice CP-ABE, `ct_kem` via Kyber768) combined through an HKDF-based hybrid combiner (`K_hyb`, secure if *either* primitive remains secure) + Dilithium3 edge signature + provenance tag/digest (`tag_prov`, `ProvDigest`).
3. **Phase 3 — Fog-Side Verification, Provenance Binding, Hybrid Index Construction.** Signature/MAC verification; PRF-based tokenization into a hybrid index (B⁺-tree for keywords, bucketed bitmap for numeric ranges, equality bitmap for categorical, epoch-partitioned for temporal, n-gram for fuzzy); per-partition Merkle roots aggregated into a global root, **threshold**-Dilithium-signed, anchored on-chain.
4. **Phase 4 — Search** (`Algorithm 2: SearchExec`). Trapdoor = signed PRF token set + range/op/epoch; candidate sets intersected across keyword/numeric/temporal indices; fuzzy scoring by n-gram overlap against threshold θ; returns result set + `AuditCommit`.
5. **Phase 5 — Retrieval, Decryption, Verification** (`Algorithm 3: RetrieveVerify`). Hybrid key reconstruction (`ABE.Dec` + `Kyber768.Decaps` → HKDF), AES-GCM decrypt, MAC/signature check, Merkle inclusion proof, **freshness check** (`root_𝒯 == root*_𝒯`, the latest on-chain root — rejects stale index snapshots).

Security: standard game-based reductions (IND-CPA for confidentiality, IND-CKA for trapdoor privacy, a Merkle-verifiability game for soundness/completeness/freshness, a provenance-unforgeability game) to LWE-hardness of the CP-ABE, Kyber IND-CPA, Dilithium EUF-CMA, SHA-3 collision resistance. No pairing, no DBDH, no discrete-log assumption anywhere — see `Ref[54].md`'s legitimacy notes for the full comparison against Ref[41]'s self-contradicted claim.

---

## Decisions needed before implementation (not published by the paper)

Both must be fixed and recorded in `crypto.yaml`'s `perera_lv_pqabse` block before any code is written — the same discipline `thingom_pq_abse.attributes.u` already follows, not a default to drift into.

| Gap | What the paper says | What's needed |
|---|---|---|
| Lattice `(n, q, σ)` | "follow established configurations consistent with Kyber768 and Dilithium3" — no concrete triple given anywhere | A specific `(n,q,σ)` triple, with a stated reason (e.g. adopting Kyber768's own ring-LWE parameters `n=256,k=3,q=3329` as the closest citable anchor) |
| Attribute universe size `\|𝒰\|` | Never numerically fixed | A benchmark value — consider matching `thingom_pq_abse.attributes.u = 10` for cross-baseline comparability, per the precedent already set between `thingom_pq_abse` and the now-dropped `zhuang_lattice_mabse.attributes.l` |
| Exp. 3 native cross-domain treatment | Paper has no multi-domain concept at all | Decide: independent per-domain trapdoors + client aggregation (matches `thingom_pq_abse`/`guo_vdsse`'s existing native-mode rule) — needs an explicit decision recorded here, not assumed |

---

## Implementation note: the paper's own evaluation is not reusable

The paper's reference implementation is **Rust** (`pqcrypto` crate), on a 4-vCPU/8GB-RAM fog host + a Raspberry Pi 4 for IoT-client emulation — different language and different hardware from this repo's Python/AWS `m6i.xlarge` methodology (README §13: implement independently, measure on the pinned host, never reuse a paper's own numbers). Its reported figures (Table II asymptotic costs, Figs. 2–4, Tables III–V) are useful for **sanity-checking** a from-scratch implementation's asymptotic behavior, not for citing directly as this repo's Ref[54] numbers.

---

## Folder Structure (planned, not yet created)

```
perera_lv_pqabse/
├── SCHEME.md                          # This file
├── src/
│   ├── scheme.py                      # Phases 1-5: ABE.Setup/KeyGen/Encrypt/Decrypt,
│   │                                   #   Kyber768/Dilithium3 wrappers (via Common/crypto/kem.py
│   │                                   #   once liboqs coverage is confirmed for Dilithium)
│   ├── hybrid_index.py                # B+-tree / bitmap / n-gram construction (Phase 3)
│   ├── merkle.py                      # Partitioned Merkle trees + threshold signing (reuse Common/crypto/merkle.py where possible)
│   ├── experiments.py                 # Exp. 1, 2, 3
│   ├── harness.py                     # Timing, 95% CI, CSV/meta output (mirror thingom_pq_abse/src/harness.py)
│   └── main.py                        # CLI + reportability gating
├── exp1_trapdoor_generation/
├── exp2_search_latency/
└── exp3_crossdomain_scalability/
```

---

## Running

Not runnable yet — `src/` is empty. Once implemented, expected invocation (mirroring `thingom_pq_abse`):

```bash
python3 -m Schemes.perera_lv_pqabse.src.main \
    --experiment 1,2,3 \
    --dataset Dataset/derived \
    --runs 30
```

Dilithium3 availability needs checking against `Common/crypto/kem.py`'s existing multi-backend probe (currently covers ML-KEM via liboqs/cryptography/kyber-py) — liboqs also exposes Dilithium (ML-DSA), so this likely extends the same probe rather than needing a new dependency, but must be verified before implementation, not assumed.

---

## Output

Same format as every other scheme — see main [README.md](../../README.md) §9.
