# Perera & Fugkeaw LV-PQ-ABSE — Scheme Experiment Guide (Ref[54])

**Back to the operator's guide:** [SystemConfiguration.md](../../SystemConfiguration.md)
**Paper:** M. Perera and S. Fugkeaw, "LV-PQ-ABSE: A Lightweight Verifiable Postquantum Attribute-Based Searchable Encryption Scheme with Hybrid Indexing and Provenance-Aware Verification for IoT-Based EHRs," *IEEE Internet of Things Journal*, vol. 13, no. 15, pp. 34302–34317, Aug. 2026, doi: `10.1109/JIOT.2026.3695855`. Extracted text: [References/Ref[54]/Ref[54].md](../../References/Ref[54]/Ref[54].md).

**Status (2026-08-29): IMPLEMENTED.** `src/` and all three experiment runners exist; `src/test_scheme.py` passes 18 tests covering Phases 1–5 including the lattice CP-ABE. The three gaps this file recorded as "decisions needed" are now decided, with reasons, in `crypto.yaml`'s `perera_lv_pqabse` block.

---

## Why this replaced Ref[52] (Zhuang)

Zhuang's `exp2_search_latency/runner.py` never built a real N-record index — it encrypted one real ciphertext and approximated an N-record scan by replaying `search()` on that single entry N times inside each of the 30 measured reps. That's a different methodology from every other scheme here (`guo_vdsse`, `thingom_pq_abse`, and this repo's own `ma_lb_pq_vdse` all build a real index of the swept size once, untimed, then measure the real search 30×). Fixing it properly meant vectorizing the unbatched `p6_encrypt.py` loop — real crypto-engineering work with a real correctness risk already flagged (int64→float64 overflow at `n=284, q=2^24`). Rather than either accept that risk under a tight schedule or ship a disclosed approximation, the team replaced the baseline with Ref[54] — already cited in the manuscript's related work (`\cite{ref54}`), and confirmed genuinely lattice-based end-to-end (see legitimacy notes in `Ref[54].md`).

---

## Experiments (3 of 8) — narrower than Zhuang's old slot, deliberately

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | PRF-based tokenization, no lattice sampling at query time — paper's own headline claim (Table II: `O(n + T_PRF)`) |
| 2 | Search Latency | Fog-offloaded hybrid index (B⁺-tree + bitmap + n-gram); client only generates tokens |
| 3 | Cross-Domain Search Scalability | Paper has no native multi-domain notion — same native-mode treatment (independent per-domain trapdoors/searches, client-side aggregation) as `thingom_pq_abse` and `guo_vdsse` will be needed; not detailed by the paper, a benchmark decision |

| 4 | Verification Overhead | Algorithm 3's verification half — ML-DSA-65 signature verify, Merkle inclusion against the per-epoch partition root, freshness check against the latest root |

**Exp. 4 was excluded 2026-09-03 (DECIDE-1) and re-included 2026-09-04.** The exclusion was on TIME, never on capability, and named two blockers. Both are now cleared:

1. **O(N) verification, fixed.** `retrieve_verify` rebuilt the whole partition tree on every call (`tree = MerkleTree(leaves)`) plus a linear `leaves.index(...)` scan — O(N) where Table II claims O(log N). `finalize()` now retains the tree it was already building (`_partition_trees`, `_leaf_positions`) and `verify_record` proves against it. Measured flat at **0.777 ms/call from N=500 to N=4000**, with the Merkle path growing 9 → 12, i.e. log₂(N). Measuring the old code would have been an accidental strawman; measuring this one is the published construction.
2. **Boundary matched, not assumed.** This repo's Exp. 4 times client-side verification and excludes fetch/decryption, but Algorithm 3 does verification *and* hybrid key reconstruction in one call. `scheme.verify_record` is its verification half alone and is what the runner times, so this arm's number covers the same work as every other arm's. `retrieve_verify` is unchanged in behaviour and still performs both halves — it is what the scheme's own tests exercise.

Note that per-record cost here is dominated by an ML-DSA-65 signature verification **per returned record**, which is what Algorithm 3 specifies. That is genuinely heavier than an accumulator-tag check; it is not removed, because removing it would flatter the baseline just as measuring the O(N) rebuild would have penalised it.

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

## Decisions taken (the paper publishes none of these)

All recorded in `crypto.yaml`'s `perera_lv_pqabse` block on 2026-08-29 with the full reasoning; summarised here.

| Gap | Decision | Why |
|---|---|---|
| Lattice `(n, q, σ)` | `n = 768`, `q = 2²²`, `m = 2·n·log q = 33,792`, `σ = 4.0` | Kyber768's security comes from module-LWE of rank 3 over a degree-256 ring — an effective LWE dimension of **768**, which is the number that carries the paper's own λ=192 / Category 3 claim for a plain-LWE construction. Taking Kyber's ring degree 256 as `n` would name the right number for the wrong parameter and would not be Category 3 here. Kyber's `q=3329` cannot be reused at all: this is a trapdoor construction, where `q` must exceed noise accumulated over `m` columns or decryption fails. `2²²` is the largest exponent for which `Common/crypto/lattice.py`'s int64 matmul guard still holds — the overflow class that corrupts results silently rather than raising. |
| Attribute universe `\|𝒰\|` | `10` | Matches `thingom_pq_abse.attributes.u`, so the two attribute-based baselines are compared at the same policy size. Not results-affecting here (see the measurement boundary below), so alignment is free. |
| Exp. 3 cross-domain | Native mode — `d` independent trapdoors, `d` independent searches, client-side aggregation | README §3's existing rule, already applied to `guo_vdsse` and `thingom_pq_abse`. The paper has one TA, one fog tier, no federation. |
| Fuzzy `n` and `θ` | trigrams, `θ = 0.6` | The paper names "n-gram" and `θ` but fixes neither. |

---

## Measurement boundary: `ct_abe` is not on the Exp. 1–3 path

`crypto.yaml`'s `abe_on_measured_path: false`, and this is the one decision most worth reading.

Exp. 1 times trapdoor generation, which here is PRF tokenization plus one Dilithium3 signature — the paper's own headline claim (Table II: `O(n + T_PRF)`, "no lattice sampling at query time"). Exp. 2 times search over the fog-side hybrid index, which holds **PRF tokens, not ciphertexts**. Exp. 3 is `d` independent Exp. 2 searches. **None of the three reads `ct_abe`**: it is payload-key encapsulation, consumed only by Phase 5 retrieval.

So the Exp. 1–3 index build does not generate a `ct_abe` per record. Everything else in Phase 2 is still real and still verified at Phase 3 — AES-256-GCM body, ML-KEM-768 encapsulation, provenance tag and digest, and the Dilithium3 edge signature the fog actually checks before indexing.

Measured cost of generating them anyway, on the dev host at the parameters above: **758 ms per record** — 21 h at `N = 10⁵`, 211 h at `N = 10⁶`. It would consume the entire 24 h track budget as untimed setup **while changing no measured number in either direction**. This does not flatter the baseline: no Exp. 1/2/3 quantity gets faster, because none of them touched `ct_abe` to begin with.

`src/test_scheme.py::test_full_retrieve_verify_accepts_a_fresh_authorised_record` exercises the complete Phase 2 → Phase 5 path *with* `ct_abe`, including policy enforcement, Merkle inclusion and the freshness check — which is the condition under which skipping it in the experiments is honest rather than convenient.

---

## Measured runtime

Full campaign ≈ **7.95 h** against the 24 h track cap (`Experiment Configuration/planning/runtime_estimates.csv`): Exp. 2 builds 5.37 h, Exp. 3 builds 2.57 h, Exp. 1 negligible. Derived from 6.86 ms/record ingest measured on the macOS dev host, with the repo's standard 1.5× derate for `m6i.xlarge` already applied. Ingest cost is dominated by the ML-DSA-65 sign/verify pair and the ML-KEM-768 encapsulation, not by indexing.

---

## Implementation note: the paper's own evaluation is not reusable

The paper's reference implementation is **Rust** (`pqcrypto` crate), on a 4-vCPU/8GB-RAM fog host + a Raspberry Pi 4 for IoT-client emulation — different language and different hardware from this repo's Python/AWS `m6i.xlarge` methodology (README §13: implement independently, measure on the pinned host, never reuse a paper's own numbers). Its reported figures (Table II asymptotic costs, Figs. 2–4, Tables III–V) are useful for **sanity-checking** a from-scratch implementation's asymptotic behavior, not for citing directly as this repo's Ref[54] numbers.

---

## Folder Structure (planned, not yet created)

```
perera_lv_pqabse/
├── SCHEME.md                          # This file
├── src/
│   ├── params.py                      # crypto.yaml -> SchemeParams; nothing hardcoded
│   ├── abe.py                         # Lattice CP-ABE (ABBB shape over Common/crypto/lattice.py)
│   ├── hybrid_index.py                # B+-tree / epoch / categorical / n-gram (Phase 3)
│   ├── scheme.py                      # Phases 1-5, incl. the HKDF hybrid combiner
│   ├── workload.py                    # corpus field -> index structure mapping
│   ├── harness.py                     # Timing, 95% CI, CSV/run_meta output
│   ├── test_scheme.py                 # 18 tests, Phases 1-5 incl. ct_abe
│   └── main.py                        # CLI + reportability gating
├── exp1_trapdoor_generation/runner.py
├── exp2_search_latency/runner.py
└── exp3_crossdomain_scalability/runner.py
```

Partitioned Merkle roots reuse `Common/crypto/merkle.py` rather than getting a
local copy, per README §8's `Common/` scope rule. Dilithium3 needed a new shared
primitive — `Common/crypto/signature.py` (ML-DSA-65), written the same way
`kem.py` is, with probed backends so a `cryptography` version lacking the classes
falls through to the next backend instead of failing the whole run.
```

---

## Running

Not runnable yet — `src/` is empty. Once implemented, expected invocation (mirroring `thingom_pq_abse`):

```bash
python3 -m Schemes.perera_lv_pqabse.src.main \
    --experiment 1,2,3 \
    --dataset Dataset/derived \
    --runs 10
```

Dilithium3 availability needs checking against `Common/crypto/kem.py`'s existing multi-backend probe (currently covers ML-KEM via liboqs/cryptography/kyber-py) — liboqs also exposes Dilithium (ML-DSA), so this likely extends the same probe rather than needing a new dependency, but must be verified before implementation, not assumed.

---

## Output

Same format as every other scheme — see [SystemConfiguration.md](../../SystemConfiguration.md).
