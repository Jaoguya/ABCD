# MA-LB-PQ-VDSE — Scheme Experiment Guide

**Back to main README:** [README.md](../../README.md)

---

## Protocol Phases

Status as of 2026-08-10. Implementation plans: [PHASE_I_II_PLAN.md](PHASE_I_II_PLAN.md),
[PHASE_III_PLAN.md](PHASE_III_PLAN.md), [PHASE_IV_PLAN.md](PHASE_IV_PLAN.md).

| Phase | Name | Module | Status |
|-------|------|--------|--------|
| I | System Initialization | `src/authority/initializer.py`, `src/fsn/fsn.py` | done (Step 2 needs the pairing backend) |
| II | Multi-Authority Registration & Authorization-State Commitment | `src/authority/authority.py`, `revocation.py`, `src/aim/aim.py` | done |
| III | User Registration & Version-Bound Authorization Profile (VAP) | `src/user/registration.py`, `delivery.py`, `profile.py`, `src/authority/keygen.py` | done (Step 2 needs the pairing backend) |
| IV | Policy-Bound Dynamic Search Index (PDSI) Construction | `src/index/extract.py`, `tokens.py`, `dsi.py`, `commit.py` | done |
| V | Secure Data Outsourcing | `src/chain/ipfs.py`, `chain/outsourcing.py`, `src/shard/propagation.py` | done |
| VI | Adaptive Authorization-Aware Search Scheduling (AASS) | `src/user/token.py`, `src/aim/verification.py`, `src/scheduler/aass.py`, `src/fsn/search.py` | done |
| VII | Dynamic Index Evolution & Incremental Auth. Synchronization (IAS) | `src/sync/ias.py` | done |
| VIII | Verifiable Retrieval | `src/verify/proof.py`, `ledger.py` | Steps 1–3 done (the Exp. 4 path); Steps 4–6 lie outside the measurement rule and are not implemented |

**All eight phases are implemented.** `src/tests/test_integration.py` walks a
record from Phase V outsourcing through Phase VI search to Phase VIII verified
retrieval with no value hand-constructed along the way. What remains is the
measurement layer (`src/main.py`, `src/harness/`) and the decisions below.

Shared foundations, used by every phase: `src/types.py` (canonical encodings for
every published record), `src/config.py` (all five config files),
`src/chain/ledger.py` (the append-only ledger).

### Blocked on decisions, not on code

| Item | Blocks |
|------|--------|
| Type-III pairing backend absent from `Common/crypto/pairing.py` | Phase I Step 2 and Phase III Step 2 arithmetic; reportability of anything cryptographic |
| Keyed vs unkeyed `H` for index tokens (`TokenScheme` requires an explicit choice) | the Exp. 1 curve — and an unkeyed `H` is invertible over the 2,006-keyword vocabulary |
| `\|PID\|` and the record→policy mapping (`extract.py` requires an explicit `PolicyAssignment`) | `n_eff` in Exp. 2 |
| λ₁…λ₅ still `pending_sweep` in `scheduler.yaml` | Exp. 7–8 (the reportable gate raises) |
| `Dataset/dataset_manifest.json` is the superseded v1 | every corpus-reading experiment |

### Construction issues found in the manuscript

Recorded here because they change what the code can do, not merely how it reads.
Each is implemented as published where that is possible, and reported otherwise.

| Where | Issue |
|-------|-------|
| Phase IV Step 2 vs Phase VI Steps 1/4 | The index token binds `(w, PID, VID, Dom)`, the query token binds `(w, VID_U)`, and the matching relation `T_Q → I_i` is undefined. Resolved as Option D (see [PHASE_IV_PLAN.md](PHASE_IV_PLAN.md) §1) — `T_j = T_Q = H(w)`, with policy and domain enforced by bitmap filtering, which is what §V `:1892` describes. |
| Throughout | `VID` denotes four different counters — record, authority, user, FSN. `VID_U` and `VID_j` both aggregate as the minimum so `\|VID_U − VID_j\|` subtracts comparable quantities. |
| Phase III Step 3 (`:547`) | Claims forward secrecy from encapsulation to a **static** user KEM key, which does not provide it. Implemented as published; reported as an observation. |
| Phase VII Step 5 (`:1092`) | `ΔVID` is integer arithmetic, `ΔC^auth` is a value, and `ΔRoot = Root' − Root` is written as a subtraction of hash digests. Also: `ΔVID` makes synchronisation require gap-free, in-order delivery. |
| Phase VIII Step 2 (`:1167`) | Recomputes `Commit_i*` with `AuthRoot_U` while Phase IV Step 5 binds `AuthRoot_DO`. As written, verification fails for every user who is not the data owner. |
| Phase VIII Step 2 (`:1167`) | Requires `VID_i = VID_U`, equating a record's version with a user's profile version — two of the four `VID` namespaces above. |
| Phase V Step 1 (`:741`) | **Circular.** `CT_i = (C_i, I_i, Commit_i)` and `CID_i = IPFS.Upload(CT_i)`, but every entry of `I_i` contains `CID_i` — content whose hash depends on its own hash. `C_i` is what is uploaded and addressed; `Root_i` and `Commit_i` travel as metadata, which is exactly what Steps 2–3 register and would be redundant if they were already inside the addressed content. |
| Phases II / IV / V (`:483`, `:621`, `:767`) | **`Meta_i` denotes three different tuples**: `(Dom_i, VID_i, C_i^auth)`, `(PID_i, VID_i, Dom_i, TS_i)`, and `(CID_i, PID_i, VID_i, Root_i, Commit_i)`. Three distinct types here. |
| Phase V Step 3 vs Phase VII Step 7 | `BC_i` is keyed by the **record's** `VID_i` while Step 7's `BC_i'` was read as the **authority's** `VID_k` — two counters into one key namespace, which collide. Step 7's `VID_i'` is the primed *record* version, matching Step 2's `I_j'`, so the record's version advances on any index-touching update and a revocation anchors nothing. A concrete instance of the `VID` overloading above. |
| §V vs Ref[41] | Ref[41] is positioned as post-quantum but rests on DBDH. Implemented as published (README §14). |
| RW15 citation | The multi-authority ABE construction is Rouselakis–Waters **FC 2015**, not CCS 2013; the published `(MSK_i, PK_i)` shape matches FC 2015 exactly. |

Eleven issues. The two that change reported numbers rather than only the text are
the Phase IV/VI token relation (settled as Option D) and Phase VIII Step 2's
`AuthRoot_U`, which as written yields a 0% acceptance rate in Exp. 4.

---

## Experiments (all 8)

| # | Experiment | Role |
|---|-----------|------|
| 1 | Trapdoor Generation Latency | Participant |
| 2 | Search Latency | Participant |
| 3 | Cross-Domain Search Scalability | Single authorization-bound trapdoor reused across domains |
| 4 | Verification Overhead | Client-side Merkle proof check |
| 5 | Dynamic Keyword Update | Participant |
| 6 | Authorization Synchronization | **IAS ablation** (3 variants) |
| 7 | Search Throughput under Workload | **Scheduler ablation** (4 variants) |
| 8 | Load-Balancing Effectiveness | **Scheduler ablation** (4 variants) |

### Per-Experiment Measurement Rules

- **Exp. 1** — Measure **online trapdoor generation only**. ML-KEM-768 encapsulation runs once at session establishment and is *excluded*; report it separately as a one-time setup cost in the text, not inside the per-query curve.
- **Exp. 2** — Measure the full online path: AIM authorization check → AASS selection → shard search → response assembly. Index construction is offline and excluded. Report `n_eff` alongside latency.
- **Exp. 3** — Issues **one** authorization-bound trapdoor reused across domains. Count trapdoors issued as a secondary metric.
- **Exp. 4** — Verification is client-side: Merkle proof check, `Commit_i*` recomputation, and blockchain-consistency check. IPFS fetch and decryption are **excluded**.
- **Exp. 5** — Measure incremental update only. A global index rebuild indicates a Phase VII implementation bug.
- **Exp. 6** — Measure IAS **propagation**: authority commitment recomputation → Merkle path update → IAS message → selective FSN propagation, until all affected FSNs report the new `VID`. **Phase VII Step 7 (anchoring `BC_i'`) is excluded** and reported separately as a per-update constant, the same treatment Exp. 1 gives ML-KEM encapsulation. Report FSNs touched — but see the ablation below: reported alone the number is a constant 1 and evidences nothing.
- **Exp. 7–8** — Closed-loop load generator with fixed concurrency and a recorded arrival trace, which all 4 variants replay. The trace is identical in *content* — keyword tokens, authorization root, user id, AIM decision — and deliberately NOT byte-identical, since every `SearchToken` carries a fresh random nonce that must vary. Utilization sampled every 100 ms.

### IAS Ablation (Exp. 6)

| Variant | Propagation rule |
|---------|------------------|
| `broadcast` | Deliver `IAS_i` to **every** FSN — the alternative `:1111` names and rejects. Tests **selective**. |
| `full_rebuild` | **Every** authority recomputes `C_k^auth` and the AIM republishes it — the alternative `:1045` rejects. Tests **incremental**. |
| `ias` (proposed) | Selective delivery to the FSNs holding the affected shard; only the affected authority evolves. |

**Why this ablation exists.** `fsns_touched` was reported alone in every campaign
through 2026-09-03 and was a constant `1.000` at every δ.
`fsn.py::assign_domains_to_fsns` gives each domain to exactly **one** node, and an
`IASMessage` carries exactly **one** domain, so selective delivery touches one node
for any `d` and `m`. The constant is a property of the design, not a measurement of
it — the claim is only observable against `broadcast`'s `m`.

`full_rebuild` calls the same `Authority.commitment()` the proposed path calls and
differs only in **how many authorities** it calls it for. The superseded O(δ²)
`RevocationList` is deliberately **not** the comparison: measuring against a fixed
bug would overstate the advantage.

`synchronize()` takes an injected `select_nodes`, the same shape as
`verify_bundle`'s injected Step 3 check; the default is `affected_nodes`, the
published rule. `apply_ias`'s `require_shard` guard is relaxed **only** on the
injected path, so selective propagation cannot silently accept a misrouted message.

The Exp. 7–8 scheduler variants are **refused** here. A scheduler decides which FSN
serves a *query* and plays no part in propagating an authorization change; passing
one previously ran the identical measurement under a different directory name,
which is what `exp6_authorization_sync__no_lb` is — within 3% of the main run at
every point. That directory is kept as the record of the independence check.

Run with `--experiment 6 --variant all`.

### Scheduler Ablation (Exp. 7 & 8)

| Variant | Node selection rule |
|---------|---------------------|
| `no_lb` | All requests to a fixed FSN (no balancing) |
| `round_robin` | Cyclic assignment, authorization-oblivious |
| `least_loaded` | Minimum current queue length, authorization-oblivious |
| `aass` (proposed) | `arg min SC_j`, with `SC_j = λ₁C^auth + λ₂C^index + λ₃C^verify + λ₄C^sync + λ₅C^queue` (Alg. 1) |

Exp. 7 and Exp. 8 measure **different properties of the same runs** — throughput and distribution fairness. Run the workload once per variant and emit both metrics.

---

## Scheme-Specific Dependencies

| Library | Purpose | Platform | Status |
|---------|---------|----------|--------|
| `liboqs-python` | ML-KEM-768 (Phase III Step 3) | Cross-platform | **live** — liboqs 0.16.0 on both the AWS host and the macOS dev host |
| `charm-crypto` | Type-III bilinear groups for MA-CP-ABE | Linux only | built on the AWS host, but `pairing.py` exposes **no Type-III backend yet** |
| `petrelic` | Type-III fallback | Cross-platform in principle | does **not** build; not a usable fallback |
| Hyperledger Fabric v2.5 | Blockchain ledger | Requires Docker | not built; `chain/ledger.py` is in-process |
| IPFS daemon | Content-addressed ciphertext storage | Separate install | not built; `CID_i` is a labelled placeholder |

> **Pairing status.** `crypto.yaml → ma_lb_pq_vdse.pairing` records
> `backend_implemented: false`. `initializer.resolve_group()` and
> `keygen.UnavailableABEOperations` both **raise** rather than falling back to the
> installed SS512 backend — that is Type-I, contradicts the published
> `e : G₁ × G₂ → G_T`, and sits at ~80-bit security. Group operations are injected
> at both call sites, so the rest of the scheme is testable; any context built on
> an unfaithful group reports `reportable = False` and `assert_reportable()`
> refuses.

> **Windows note:** `charm-crypto` does not support Windows and `petrelic` does not
> build, so Windows is development-only for this scheme. Reportable runs need the
> Linux experiment host.

---

## Folder Structure

```
ma_lb_pq_vdse/
├── SCHEME.md                          # This file
├── PHASE_I_II_PLAN.md · PHASE_III_PLAN.md · PHASE_IV_PLAN.md
├── src/
│   ├── types.py                       # canonical encodings for every record
│   ├── config.py                      # global/index/scheduler/workload + crypto/dataset
│   ├── authority/
│   │   ├── initializer.py             # Phase I Steps 1, 3
│   │   ├── authority.py               # Phase I Step 2, Phase II Steps 1–3
│   │   ├── revocation.py              # RevRoot_i
│   │   └── keygen.py                  # Phase III Step 2 (RW15)
│   ├── user/
│   │   ├── registration.py            # Phase III Step 1
│   │   ├── delivery.py                # Phase III Step 3 (ML-KEM + HKDF + AES-GCM)
│   │   ├── profile.py                 # Phase III Step 4 (AuthRoot_U, VAP_U)
│   │   └── token.py                   # Phase VI Step 1 (ST) — the Exp. 1 path
│   ├── index/
│   │   ├── extract.py                 # Phase IV Step 1
│   │   ├── tokens.py                  # Phase IV Step 2 (Option D)
│   │   ├── dsi.py                     # Phase IV Step 3 + bitmaps
│   │   └── commit.py                  # Phase IV Steps 4–5 (Root_i, Commit_i)
│   ├── shard/propagation.py           # Phase V Steps 4–5 (Sync_i, Catalog)
│   ├── aim/
│   │   ├── aim.py                     # Authorization Index Manager
│   │   └── verification.py            # Phase VI Step 2 (four checks + nonce)
│   ├── fsn/
│   │   ├── fsn.py                     # Phase I Step 4; owns its PDSI shard
│   │   └── search.py                  # Phase VI Step 4
│   ├── scheduler/aass.py              # Phase VI Step 3 (Alg. 1) + ablation variants
│   ├── sync/ias.py                    # Phase VII Steps 2–7
│   ├── verify/
│   │   ├── proof.py                   # Phase VIII Steps 1–2
│   │   └── ledger.py                  # Phase VIII Step 3
│   ├── chain/
│   │   ├── ledger.py                  # append-only ledger; Fabric behind the interface
│   │   ├── ipfs.py                    # Phase V Step 1 (content-addressed store)
│   │   └── outsourcing.py             # Phase V Steps 2–3 (Meta_i, BC_i)
│   ├── harness/                       # the measurement layer (README §7/§9)
│   │   ├── stats.py · provenance.py · runner.py · experiments.py
│   ├── main.py                        # CLI entry point
│   └── tests/                         # test_phase1_2 · 3 · 4 · 5 · 6 · 7 · 8
│                                      # · test_integration · test_harness
├── exp1_trapdoor_generation/
├── exp2_search_latency/
├── exp3_crossdomain_scalability/
├── exp4_verification_overhead/
├── exp5_keyword_update/
├── exp6_authorization_sync/
├── exp7_search_throughput/
└── exp8_load_balance/
```

`src/shard/` rather than `src/chain/` for Phase V: `chain/` holds the ledger and
IPFS adapters, and shard distribution is neither. Fabric v2.5 implements
`chain/ledger.py`'s `Ledger` interface and is required before Exp. 4 produces
reportable numbers; the in-process adapter is a real append-only hash chain, so
the Phase VIII Step 3 consistency check does the work Exp. 4 times rather than
being a no-op that Fabric later makes expensive.

**Exp. 6 does not wait on Fabric** (changed 2026-09-03). It was gated alongside
Exp. 4 until then, justified by "Exp. 6 times IAS through to blockchain
anchoring" — but `sync/ias.py::synchronize` takes `ledger` as **optional** and
anchors only inside `if ledger is not None`, and the Exp. 6 runner has never
passed one. That justification cited a protocol step rather than a measurement
boundary. README §5 ends Exp. 6 at "until all affected FSNs report the new
`VID`", and `tab:cost`'s authorization-synchronization row is
`O(δ)T_H + O(log d)T_MT` with no chain term. If Step 7 is ever brought inside the
boundary, the runner must pass a ledger and `exp6_authorization_sync` must go back
into the gate — `test_exp6_propagation_ablation.py` pins both directions.

### Tests

Standalone, no framework required; each file also collects under pytest.

```bash
python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase4.py          # one phase group
python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase4.py dsi      # one area
```

Every test targets a defining property of the construction rather than a return
type, and each module's claims are checked by mutating the source and confirming
the right tests fail.

---

## Running

### Linux

```bash
# All experiments
python3 -m Schemes.ma_lb_pq_vdse.src.main \
    --experiment all \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30

# Single experiment
python3 -m Schemes.ma_lb_pq_vdse.src.main \
    --experiment 2 \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30
```

### Windows (PowerShell)

```powershell
# All experiments
python -m Schemes.ma_lb_pq_vdse.src.main `
    --experiment all `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 30

# Single experiment
python -m Schemes.ma_lb_pq_vdse.src.main `
    --experiment 2 `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 30
```

---

## Output

Each experiment folder produces:

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run, never aggregated |
| `results.csv` | Aggregated means with 95% CI |
| `run_meta.json` | Provenance (git commit, Python version, dataset SHA-256, etc.) |

See main [README.md](../../README.md) §9 for column format.
