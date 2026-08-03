# MA-LB-PQ-VDSE — Scheme Experiment Guide

**Back to main README:** [README.md](../../README.md)

---

## Protocol Phases Implemented

| Phase | Name | Module |
|-------|------|--------|
| I | System Initialization | `src/authority/` |
| II | Multi-Authority Registration & Authorization-State Commitment | `src/authority/` |
| III | User Registration & Version-Bound Authorization Profile (VAP) | `src/user/` |
| IV | Policy-Bound Dynamic Search Index (PDSI) Construction | `src/index/` |
| V | Secure Data Outsourcing | `src/chain/` |
| VI | Adaptive Authorization-Aware Search Scheduling (AASS) | `src/scheduler/` |
| VII | Dynamic Index Evolution & Incremental Auth. Synchronization (IAS) | `src/sync/` |
| VIII | Verifiable Retrieval | `src/verify/` |

---

## Experiments (all 8)

| # | Experiment | Role |
|---|-----------|------|
| 1 | Trapdoor Generation Latency | Participant |
| 2 | Search Latency | Participant |
| 3 | Cross-Domain Search Scalability | Single authorization-bound trapdoor reused across domains |
| 4 | Verification Overhead | Client-side Merkle proof check |
| 5 | Dynamic Keyword Update | Participant |
| 6 | Authorization Synchronization | IAS end-to-end |
| 7 | Search Throughput under Workload | **Scheduler ablation** (4 variants) |
| 8 | Load-Balancing Effectiveness | **Scheduler ablation** (4 variants) |

### Per-Experiment Measurement Rules

- **Exp. 1** — Measure **online trapdoor generation only**. ML-KEM-768 encapsulation runs once at session establishment and is *excluded*; report it separately as a one-time setup cost in the text, not inside the per-query curve.
- **Exp. 2** — Measure the full online path: AIM authorization check → AASS selection → shard search → response assembly. Index construction is offline and excluded. Report `n_eff` alongside latency.
- **Exp. 3** — Issues **one** authorization-bound trapdoor reused across domains. Count trapdoors issued as a secondary metric.
- **Exp. 4** — Verification is client-side: Merkle proof check, `Commit_i*` recomputation, and blockchain-consistency check. IPFS fetch and decryption are **excluded**.
- **Exp. 5** — Measure incremental update only. A global index rebuild indicates a Phase VII implementation bug.
- **Exp. 6** — Measure IAS end-to-end: authority commitment recomputation → Merkle path update → IAS message → selective FSN propagation, until all affected FSNs report the new `VID`. Report FSNs touched.
- **Exp. 7–8** — Closed-loop load generator with fixed concurrency and a recorded arrival trace. All 4 variants see byte-identical workloads. Utilization sampled every 100 ms.

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

| Library | Purpose | Platform |
|---------|---------|----------|
| `charm-crypto` | Type-III bilinear groups for MA-CP-ABE | Linux only (use `petrelic` on Windows) |
| `petrelic` | Alternative pairing library | Cross-platform |
| Hyperledger Fabric v2.5 | Blockchain ledger | Requires Docker |
| IPFS daemon | Content-addressed ciphertext storage | Separate install |

> **Windows note:** `charm-crypto` does not natively support Windows. Use `petrelic` or run under WSL2.

---

## Folder Structure

```
ma_lb_pq_vdse/
├── SCHEME.md                          # This file
├── src/
│   ├── authority/                     # Phase I–II
│   ├── user/                          # Phase III
│   ├── index/                         # Phase IV: PDSI
│   ├── aim/                           # Authorization Index Manager
│   ├── scheduler/                     # Phase VI: AASS (Alg. 1)
│   ├── fsn/                           # Fog Search Node
│   ├── sync/                          # Phase VII: IAS
│   ├── verify/                        # Phase VIII
│   └── chain/                         # Fabric + IPFS adapters
├── exp1_trapdoor_generation/
├── exp2_search_latency/
├── exp3_crossdomain_scalability/
├── exp4_verification_overhead/
├── exp5_keyword_update/
├── exp6_authorization_sync/
├── exp7_search_throughput/
└── exp8_load_balance/
```

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
