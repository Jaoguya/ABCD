# MA-LB-PQ-VDSE — Experimental Benchmark

This repository contains the experimental implementation and evaluation harness for the paper:

> **"Achieving Post-Quantum and Dynamic Load-Balanced Verifiable Searchable Encryption for Multi-Authority IoMT Data Sharing"**
> Submitted to *IEEE Open Journal of the Communications Society* (OJ-COMS).
> Manuscript source: [Overleaf/PQ-AVDSE-OJCOMS](Overleaf/PQ-AVDSE-OJCOMS)

The framework under evaluation is **MA-LB-PQ-VDSE** — *Multi-Authority Load-Balanced Post-Quantum Verifiable Dynamic Searchable Encryption* — a fog–cloud framework for encrypted IoMT data sharing that unifies multi-authority authorization, policy-bound dynamic searchable encryption, authorization-aware search scheduling, incremental authorization synchronization, blockchain-anchored verifiable retrieval, and ML-KEM post-quantum key establishment.

This codebase is in the **experimental phase**. Its purpose is to implement the protocol phases and the four baseline schemes, execute the eight experiments defined in Section V of the manuscript, and produce the measured data and figures that the paper reports. Every number in the paper must be traceable to a `results.csv` produced by code in this repository.

---

## 1. Hardware & Environment

| Component | Specification |
|-----------|--------------|
| **Compute** | Amazon AWS EC2 `c6i.xlarge` (4 vCPU, 8 GB RAM) |
| **Topology** | 4 Fog Search Nodes + 1 cloud server inside a single AWS VPC |
| **OS** | Ubuntu 22.04 LTS |
| **Language** | Python 3.11 |
| **PQ KEM** | ML-KEM-768 (FIPS 203) |
| **Symmetric** | AES-256-GCM |
| **Hash / ADS** | SHA-256, Merkle tree |
| **Ledger** | Hyperledger Fabric v2.5 (consortium, off-chain data / on-chain commitments) |
| **Storage** | IPFS (content-addressed ciphertext storage) |
| **Pairing** | Type-III bilinear groups for MA-CP-ABE (`charm-crypto` / `petrelic`) |

Each FSN runs as an independent process (or instance) holding its own searchable-index shard, its own authorization version `VID_j`, and its own request queue. The cloud server holds encrypted EHRs and blockchain metadata. Instances must be in the **same VPC and availability zone** so that inter-node latency is a property of the topology and not of the region.

> **Environment parity is part of the result.** Every scheme — ours and all four baselines — must run on the *same* instance type, the same Python build, and the same dataset. Do not benchmark one scheme on a laptop and another on EC2.

### 1.1 System Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| **Python** | 3.11+ | Both Linux and Windows supported |
| **OS** | Ubuntu 22.04 LTS / Windows 10+ | Cross-platform experiment execution |
| **pip** | 23.0+ | For installing dependencies |
| **Docker** | 24.0+ | Required for Hyperledger Fabric (proposed scheme only) |
| **IPFS** | 0.20+ | Required for content-addressed storage (proposed scheme only) |
| **Git** | 2.30+ | For provenance tracking in `run_meta.json` |

#### Python Libraries

All dependencies are declared in [`requirements.txt`](requirements.txt). Key libraries:

| Library | Version | Purpose | Platform |
|---------|---------|---------|----------|
| `cryptography` | ≥43.0.0 | ML-KEM-768 (FIPS 203), AES-256-GCM | Linux + Windows |
| `pycryptodome` | ≥3.20.0 | Symmetric crypto utilities | Linux + Windows |
| `charm-crypto` | ≥0.50 | Type-III bilinear groups (MA-CP-ABE) | **Linux only** |
| `petrelic` | ≥0.1.5 | Cross-platform pairing alternative | Linux + Windows |
| `numpy` | ≥1.26.0 | Array operations | Linux + Windows |
| `scipy` | ≥1.12.0 | Confidence interval computation | Linux + Windows |
| `pandas` | ≥2.2.0 | CSV handling and aggregation | Linux + Windows |
| `matplotlib` | ≥3.8.0 | Figure generation (vector PDF) | Linux + Windows |
| `mmh3` | ≥4.0.0 | MurmurHash3 for Bloom filters | Linux + Windows |
| `pyyaml` | ≥6.0.0 | YAML config file parsing | Linux + Windows |
| `psutil` | ≥5.9.0 | FSN utilization sampling | Linux + Windows |

Install all dependencies:

```bash
# Linux
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Windows (PowerShell)
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Windows note:** `charm-crypto` does not natively support Windows. On Windows, the experiment harness uses `petrelic` as the pairing backend, or you can run under WSL2.

---

## 2. Protocol Phases Under Evaluation

The manuscript defines eight protocol phases. The benchmark exercises them as follows:

| Phase | Name | Exercised by |
|-------|------|--------------|
| I | System Initialization | setup (not timed) |
| II | Multi-Authority Registration & Authorization-State Commitment | setup (not timed) |
| III | User Registration & Version-Bound Authorization Profile (VAP) | setup (not timed) |
| IV | Policy-Bound Dynamic Search Index (PDSI) Construction | Exp. 2 (index build), Exp. 5 |
| V | Secure Data Outsourcing | setup (not timed) |
| VI | Adaptive Authorization-Aware Search Scheduling (AASS) | **Exp. 1, 2, 3, 7, 8** |
| VII | Dynamic Index Evolution & Incremental Auth. Synchronization (IAS) | **Exp. 5, 6** |
| VIII | Verifiable Retrieval | **Exp. 4** |

The three mechanisms that carry the paper's novelty claims — **PDSI** (Phase IV), **AASS** (Phase VI, Alg. 1), and **IAS** (Phase VII) — must each be measured by at least one experiment. They are, respectively, by Exp. 2, Exp. 7–8, and Exp. 6.

---

## 3. Baseline Schemes

Four baselines are implemented, chosen to cover the four research directions the paper positions itself against.

| Folder | Ref | Paper | Direction Represented | Experiment Guide |
|--------|-----|-------|----------------------|------------------|
| `ma_lb_pq_vdse/` | [ours] | This work | Proposed framework | [SCHEME.md](Schemes/ma_lb_pq_vdse/SCHEME.md) |
| `guo_vdsse/` | Ref[35] | Guo *et al.*, IEEE TDSC 2024 — *Forward Private Verifiable DSSE with Efficient Conjunctive Query* | Verifiable dynamic SSE | [SCHEME.md](Schemes/guo_vdsse/SCHEME.md) |
| `xb_muse/` | Ref[36] | Jiang *et al.*, IEEE IoT-J 2025 — *XB-Muse: Practical Multiuser DSSE for Adaptive Revocation* | State-of-the-art dynamic SSE | [SCHEME.md](Schemes/xb_muse/SCHEME.md) |
| `thingom_pq_abse/` | Ref[41] | Thingom *et al.*, IEEE TCE 2026 — *Post-Quantum Attribute-Based Searchable Encryption for Edge-Driven Transportation* | Multi-authority ABSE | [SCHEME.md](Schemes/thingom_pq_abse/SCHEME.md) |
| `zhuang_lattice_mabse/` | Ref[52] | Zhuang *et al.*, IEEE DSC — *MA Attribute-Based Multi-Keyword SE with Dynamic Membership from Lattices* | Lattice-based post-quantum SE | [SCHEME.md](Schemes/zhuang_lattice_mabse/SCHEME.md) |

Each scheme's `SCHEME.md` contains experiment-specific measurement rules, run commands (Linux + Windows), folder structure, and output details. The baseline paper references and direction summaries are maintained here in this README only.

Reference PDFs and extracted text live in [References/](References/).

> **Note on Ref[36].** `References/Ref[36].pdf` is corrupted — its text streams cannot be extracted (see `References/Ref[36].txt`). Obtain a clean copy from IEEE Xplore (doi: 10.1109/JIOT.2025.3561287) before implementing `xb_muse/`; do **not** implement it from the abstract or from the comparison table alone.

Since the baselines do not natively support cross-domain search, in Exp. 3 they are run in their **native mode**: one independent trapdoor and one independent search per domain, with client-side result aggregation. This is the honest way to model them and is exactly what the cost analysis in Table VI assumes. Do not "improve" a baseline beyond its published construction, and do not cripple it either.

---

## 4. Dataset

| Property | Value |
|----------|-------|
| Source | **Synthea** (MITRE), Apache 2.0 — Walonoski *et al.*, *JAMIA* 25(3), 2018, doi: 10.1093/jamia/ocx079 |
| Record unit | One clinical encounter |
| Records | 10⁴ – 10⁶ encrypted EHRs |
| Keyword sources | SNOMED CT conditions (`cond:`), RxNorm medications (`med:`), SNOMED procedures (`proc:`) |
| Distribution | Across 4 administrative healthcare domains, derived from `encounters.ORGANIZATION` |
| Derived artifact | Keyword set `W_i` + metadata `(PID_i, VID_i, Dom_i, TS_i)` per record |

Two corpus types exist, and the distinction is load-bearing:

| `corpus_type` | Source | Reportable? |
|---------------|--------|-------------|
| `synthea` | Synthea CSV export — epidemiologically grounded disease modules, openly licensed, citable generator | **Yes** |
| `synthetic` | `synthetic_generator.py` — a fitted Zipf law with no clinical structure | **No** |

Both are "not real patients", but only Synthea is a *citable instrument* with real keyword co-occurrence. Do not conflate them.

**Why Synthea.** Keyword **co-occurrence** is what Exp. 2 depends on: the claim is that latency tracks the candidate set `n_eff` rather than total index size, and `n_eff` is driven by posting-list overlap. Synthea's disease modules produce genuine co-occurrence — a diabetes condition really does pull metformin — which a fitted Zipf law cannot reproduce. It is also unbounded in size, needs no credentialing, and is openly licensed, so the derived corpus can be committed and a reviewer can reproduce the exact index instead of re-deriving it. Finally, `encounters.ORGANIZATION` gives a **real institutional domain split** rather than an arbitrary partition.

**Stating it honestly in §V.** The evaluation measures cryptographic and search performance, not clinical validity, so a synthetic corpus with realistic keyword structure is appropriate — and Synthea is a peer-reviewed, citable generator, not an ad-hoc script. Say this plainly; do not imply the data is real.

Generate the corpus with:

```bash
git clone https://github.com/synthetichealth/synthea && cd synthea
./run_synthea -p 400000        # ~2–3 encounters/patient → past 10⁶
```

`Dataset/` contains:

- `corpus.py` — shared corpus schema, manifest, and distribution statistics,
- `prepare_dataset.py` — Synthea CSV export → derived corpus,
- `synthetic_generator.py` — development-only corpus for pipeline smoke tests,
- `dataset_manifest.json` — record counts, keyword-universe size, per-domain split, fitted frequency profile, and the SHA-256 of the derived corpus.

Every `results.csv` records which corpus it came from (see §7); a `synthetic` run can never be mistaken for a reportable one.

> **Paper-side issue to fix in the .tex:** two `\bibitem{ref55}` entries share one key. Resolve the duplicate and point the §V dataset citation at the Synthea reference.

---

## 5. Experiment Definitions

Each experiment varies exactly **one** independent variable and holds every other parameter at the default in §6. Not every scheme participates in every experiment — a scheme participates only where its published construction supports the operation being measured.

| # | Experiment | Independent Variable | Range | Primary Metric | Secondary Metrics | Schemes |
|---|-----------|---------------------|-------|---------------|-------------------|---------|
| 1 | Trapdoor Generation Latency | Queried keywords `q` | 1 → 20 | Trapdoor gen. latency (ms) | Trapdoor size (bytes) | All 5 |
| 2 | Search Latency | Searchable index size `N` | 10⁴ → 10⁶ | End-to-end search latency (ms) | Candidate set `n_eff`, entries traversed, filter-prune ratio | All 5 |
| 3 | Cross-Domain Search Scalability | Participating domains `d` | 2 → 10 | Cross-domain search latency (ms) | Trapdoors issued, cross-node messages | All 5 |
| 4 | Verification Overhead | Returned records `r` | 10 → 1000 | Verification latency (ms) | Proof size (KB), Merkle path length | Ours, Ref[35] |
| 5 | Dynamic Keyword Update | Updated keywords `k` | 10² → 10⁵ | Update latency (ms) | Merkle nodes recomputed, entries rewritten | Ours, Ref[35], Ref[36], Ref[52] |
| 6 | Authorization Synchronization | Authorization/revocation updates `δ` | 10² → 10⁵ | Synchronization latency (ms) | IAS message size (KB), FSNs touched | Ours, Ref[52] |
| 7 | Search Throughput under Workload | Concurrent search requests | 100 → 5000 | Throughput (queries/s) | p50 / p95 latency, rejected requests | Ours — scheduler ablation |
| 8 | Load-Balancing Effectiveness | Concurrent search requests | 100 → 5000 | Std. dev. of FSN utilization | Max-node utilization, cross-node forwards | Ours — scheduler ablation |

### Scheduler ablation (Experiments 7 and 8)

Experiments 7 and 8 are **internal ablations** of the AASS scheduler, not cross-scheme comparisons. Four configurations are run over the identical workload trace:

| Variant | Node selection rule |
|---------|--------------------|
| `no_lb` | All requests to a fixed FSN (no balancing) |
| `round_robin` | Cyclic assignment, authorization-oblivious |
| `least_loaded` | Minimum current queue length, authorization-oblivious |
| `aass` (proposed) | `arg min SC_j`, with `SC_j = λ₁C^auth + λ₂C^index + λ₃C^verify + λ₄C^sync + λ₅C^queue` (Alg. 1) |

Exp. 7 and Exp. 8 measure **different properties of the same runs** — throughput and distribution fairness. Run the workload once per variant and emit both metrics; do not run the trace twice, or the two figures will describe two different executions.

The point of separating them is that throughput alone can hide congestion: a scheduler can post acceptable aggregate throughput while pinning one node at saturation. Exp. 8 exists to show that the proposed scheduler's throughput advantage comes from *distribution*, not from overloading a single fast node.

### Per-experiment measurement rules

These rules decide what the numbers mean. Getting them wrong invalidates the figure even if the code is correct.

- **Exp. 1** — Measure **online trapdoor generation only**. ML-KEM-768 encapsulation runs once at session establishment and is *excluded*; report it separately as a one-time setup cost in the text, not inside the per-query curve.
- **Exp. 2** — Measure the full online path: AIM authorization check → AASS selection → shard search → response assembly. Index construction is offline and excluded. Report `n_eff` alongside latency; the paper's claim is that latency tracks `n_eff` rather than total index size, and only the secondary metric can demonstrate that.
- **Exp. 3** — Baselines issue `d` trapdoors and `d` searches; ours issues **one** authorization-bound trapdoor reused across domains. Count trapdoors issued as a secondary metric so the mechanism behind the curve is visible.
- **Exp. 4** — Verification is client-side: Merkle proof check, `Commit_i*` recomputation, and blockchain-consistency check. IPFS fetch and decryption are **excluded** — they are not verification.
- **Exp. 5** — Measure incremental update only. If a run triggers a global index rebuild, that is a bug in the implementation of Phase VII, not a measurement.
- **Exp. 6** — Measure IAS end-to-end: authority commitment recomputation → Merkle path update → IAS message → selective FSN propagation, until all affected FSNs report the new `VID`. Report FSNs touched; selective (not broadcast) propagation is the claim.
- **Exp. 7–8** — Use a **closed-loop** load generator with a fixed concurrency level per data point and a recorded arrival trace, so all four variants see byte-identical workloads. Utilization is sampled at a fixed interval (default 100 ms) across all FSNs.

---

## 6. Default Parameters

Every experiment holds these fixed unless it is sweeping that variable.

| Parameter | Default | Source |
|-----------|---------|--------|
| Keywords per query `q` | 5 | Paper §V |
| Administrative domains `d` | 4 | Paper §V |
| Fog Search Nodes `m` | 4 | Paper §V |
| Searchable index size `N` | 10⁵ | *benchmark choice* (mid-point of the 10⁴–10⁶ sweep) |
| Returned results `r` | 100 | *benchmark choice* |
| Repetitions per data point | 30 | Paper §V |
| Confidence interval | 95% | Paper §V |
| Warm-up runs (discarded) | 5 | *benchmark choice* |
| ML-KEM parameter set | ML-KEM-768 | Paper §V |
| Scheduler weights `λ₁…λ₅` | see `Experiment Configuration/scheduler.yaml` | **not specified in the paper** |
| Bitmap / Bloom filter parameters | see `Experiment Configuration/index.yaml` | **not specified in the paper** |
| Keyword universe size | see `dataset_manifest.json` | derived from the Synthea corpus |

The rows marked *not specified in the paper* are open parameters. Fix them **once**, in [Experiment Configuration/](Experiment%20Configuration/), before generating any reportable data — and record the chosen values in the manuscript. The λ weights in particular are load-bearing: they determine the AASS selection rule, and a reviewer will ask how they were set. Choose them by a documented procedure (e.g. a one-time sweep on a held-out workload), commit that procedure's output, and do not retune them per experiment.

---

## 7. Measurement Methodology

- **Repetitions.** 30 independent runs per data point, preceded by 5 discarded warm-up runs (JIT/page-cache/connection-pool effects). Report mean with a 95% confidence interval.
- **Clock.** `time.perf_counter_ns()` for latency; wall-clock over the full trace for throughput. Never `time.time()`.
- **Isolation.** One experiment at a time per instance. No other tenant workload, no plotting, no dataset preprocessing running concurrently.
- **Cold vs. warm.** State which one each experiment reports. Defaults: Exp. 1–4 warm (index resident), Exp. 5–6 warm, Exp. 7–8 warm after a 30 s ramp-up.
- **Outliers.** Do not delete them. Report mean ± CI over all 30 retained runs. If a run fails (crash, timeout, network partition), record the failure in `raw_runs.csv` with `status=failed` and re-run to restore n = 30 — never silently drop it.
- **Provenance.** Every `results.csv` is accompanied by a `run_meta.json` capturing: git commit, instance type, Python version, library versions, dataset SHA-256, corpus type (`synthea` \| `synthetic`), config file hashes, and UTC start time.

A figure whose underlying runs cannot be traced to a commit and a dataset hash cannot go in the paper.

---

## 8. Repository Structure

```
PQ-AVDSE/
├── README.md                             # This file — source of truth (DO NOT let AI agents edit)
├── AGENT_RULES.md                        # AI agent goal, constraints, and debug workflow
├── debug_history.md                      # Append-only debugging log
├── requirements.txt                      # Python dependencies (cross-platform)
├── run_benchmark.sh                      # Automated: build → run all schemes → plot
├── Common/                               # Shared PRIMITIVES — never constructions
│   └── crypto/
│       ├── config.py                     # Loads Experiment Configuration/*.yaml
│       ├── hashes.py                     # SHA-256 (+truncation), BLAKE2b, HMAC, HKDF
│       ├── rng.py                        # Secure RNG + seeded reproducible RNG
│       ├── symmetric.py                  # AES-256-GCM
│       ├── prf.py                        # PRF and t-puncturable PRF (Ref[35])
│       ├── merkle.py                     # Merkle tree, proofs, incremental update
│       ├── bloom.py                      # Bloom filter BF(l,k) (Ref[52])
│       ├── lattice.py                    # Z_q, discrete Gaussian, TrapGen/SamplePre
│       ├── pairing.py                    # Type-I (Ref[41]) / Type-III backends
│       ├── kem.py                        # ML-KEM-768 (proposed scheme only)
│       └── tests/
│           └── test_primitives.py        # Property tests for every primitive
├── Dataset/
│   ├── corpus.py                         # Shared corpus schema, manifest, statistics
│   ├── prepare_dataset.py                # Synthea → derived searchable corpus
│   ├── synthetic_generator.py            # Development-only corpus (not reportable)
│   ├── dataset_manifest.json             # Counts, keyword universe, SHA-256
│   └── derived/                          # Generated corpus (git-ignored)
├── Experiment Configuration/
│   ├── global.yaml                       # Domains, FSNs, repetitions, CI level
│   ├── scheduler.yaml                    # λ₁…λ₅ and AASS cost-estimator params
│   ├── index.yaml                        # Bitmap/Bloom, shard, Merkle parameters
│   ├── crypto.yaml                       # ML-KEM, AES, pairing-curve selection
│   ├── dataset.yaml                      # Corpus shape, Synthea extraction, synthetic
│   └── workload/                         # Recorded arrival traces for Exp. 7–8
├── Schemes/
│   ├── ma_lb_pq_vdse/                    # [ours] → see SCHEME.md
│   │   ├── SCHEME.md                     # Experiment guide for this scheme
│   │   ├── src/                          # Phases I–VIII
│   │   │   ├── authority/                # Phase I–II: AA setup, commitments
│   │   │   ├── user/                     # Phase III: VAP, ML-KEM key delivery
│   │   │   ├── index/                    # Phase IV: PDSI, Merkle commitments
│   │   │   ├── aim/                      # Authorization Index Manager
│   │   │   ├── scheduler/                # Phase VI: AASS (Alg. 1)
│   │   │   ├── fsn/                      # Fog Search Node: search + proof gen
│   │   │   ├── sync/                     # Phase VII: IAS
│   │   │   ├── verify/                   # Phase VIII: verifiable retrieval
│   │   │   └── chain/                    # Fabric + IPFS adapters
│   │   ├── exp1_trapdoor_generation/
│   │   ├── exp2_search_latency/
│   │   ├── exp3_crossdomain_scalability/
│   │   ├── exp4_verification_overhead/
│   │   ├── exp5_keyword_update/
│   │   ├── exp6_authorization_sync/
│   │   ├── exp7_search_throughput/
│   │   └── exp8_load_balance/
│   ├── guo_vdsse/                        # Ref[35] → see SCHEME.md
│   │   ├── SCHEME.md
│   │   ├── src/
│   │   ├── exp1_trapdoor_generation/
│   │   ├── exp2_search_latency/
│   │   ├── exp3_crossdomain_scalability/
│   │   ├── exp4_verification_overhead/
│   │   └── exp5_keyword_update/
│   ├── xb_muse/                          # Ref[36] → see SCHEME.md
│   │   ├── SCHEME.md
│   │   ├── src/
│   │   ├── exp1_trapdoor_generation/
│   │   ├── exp2_search_latency/
│   │   ├── exp3_crossdomain_scalability/
│   │   └── exp5_keyword_update/
│   ├── thingom_pq_abse/                  # Ref[41] → see SCHEME.md
│   │   ├── SCHEME.md
│   │   ├── src/
│   │   ├── exp1_trapdoor_generation/
│   │   ├── exp2_search_latency/
│   │   └── exp3_crossdomain_scalability/
│   └── zhuang_lattice_mabse/             # Ref[52] → see SCHEME.md
│       ├── SCHEME.md
│       ├── src/
│       ├── exp1_trapdoor_generation/
│       ├── exp2_search_latency/
│       ├── exp3_crossdomain_scalability/
│       ├── exp5_keyword_update/
│       └── exp6_authorization_sync/
├── Plots/
│   ├── generate_plots.py                 # Central plotting script
│   └── output/                           # Generated figures (PDF for the paper)
├── Overleaf/
│   ├── PQ-AVDSE-OJCOMS                   # Manuscript LaTeX source
│   └── PQ-Explaination.txt               # System model & phases (EN/TH)
└── References/                           # Baseline papers (PDF + extracted text)
```

The four empty placeholder files currently in `Schemes/` (`1`, `2`, `3`, `4`) should be replaced by the five named scheme directories above.

### `Common/` — scope rule

`Common/` exists so that every scheme measures the *same* primitive cost, making a latency difference between two schemes attributable to their constructions rather than to two different AES wrappers (§1, environment parity). It is the sanctioned exception to §14's "do not copy implementation logic between scheme folders" — sharing one primitive is the opposite of copying five.

The boundary is strict:

- **Belongs in `Common/`** — anything a paper *cites*: SHA-256, HMAC, AES-GCM, Merkle trees, Bloom filters, discrete Gaussian sampling, bilinear pairings, ML-KEM.
- **Never belongs in `Common/`** — anything a paper *contributes*: Guo's forward index, Zhuang's attribute key derivation, Thingom's LSSS policy encoding, our PDSI/AASS/IAS. Those live in `Schemes/<name>/src/` and stay independent.

If two schemes would need the same *construction*, that is a sign one of them is being implemented unfaithfully — not a reason to share code.

### Supporting Documents

This README is the source of truth, but several supporting documents contain details that would overload this file. **Read them when needed.**

| File | Purpose | When to read |
|------|---------|--------------|
| [`AGENT_RULES.md`](AGENT_RULES.md) | AI agent goal definition, execution loop, reviewer-level validation checklist, constraints, and debug workflow | Before any AI agent begins work on this repository |
| [`debug_history.md`](debug_history.md) | Append-only chronological log of all debugging activity (date, cause, fix, status) | When debugging — append every fix here; review before re-running failed experiments |
| [`requirements.txt`](requirements.txt) | Python dependencies split into global (all schemes) and local (proposed scheme only) | When setting up the environment or adding a dependency |
| `Schemes/*/SCHEME.md` | Per-scheme experiment guide: which experiments, measurement rules, run commands (Linux + Windows), folder structure | Before implementing or running a specific scheme's experiments |

### Scheme Experiment Guides

Per-scheme experiment details, measurement rules, and run commands (Linux + Windows) are in each scheme's `SCHEME.md`:

| Scheme | Guide | Experiments |
|--------|-------|-------------|
| MA-LB-PQ-VDSE (ours) | [SCHEME.md](Schemes/ma_lb_pq_vdse/SCHEME.md) | 1, 2, 3, 4, 5, 6, 7, 8 |
| Guo VDSSE (Ref[35]) | [SCHEME.md](Schemes/guo_vdsse/SCHEME.md) | 1, 2, 3, 4, 5 |
| XB-Muse (Ref[36]) | [SCHEME.md](Schemes/xb_muse/SCHEME.md) | 1, 2, 3, 5 |
| Thingom PQ-ABSE (Ref[41]) | [SCHEME.md](Schemes/thingom_pq_abse/SCHEME.md) | 1, 2, 3 |
| Zhuang Lattice MA-BSE (Ref[52]) | [SCHEME.md](Schemes/zhuang_lattice_mabse/SCHEME.md) | 1, 2, 3, 5, 6 |

---

## 9. Output Format

Each experiment folder produces **three** files. All three are required.

**`raw_runs.csv`** — one row per individual run, never aggregated:

```csv
scheme,experiment,variable_value,run_id,primary_metric,secondary_metric_1,secondary_metric_2,status
ma_lb_pq_vdse,exp2,10000,1,4.812,318,0.968,ok
ma_lb_pq_vdse,exp2,10000,2,4.771,318,0.968,ok
```

**`results.csv`** — aggregated, consumed by the plotting script:

```csv
variable_value,primary_mean,primary_ci95,secondary_1_mean,secondary_1_ci95,secondary_2_mean,secondary_2_ci95,n_runs
10000,4.79,0.11,318.0,4.2,0.968,0.003,30
100000,7.31,0.19,2971.0,31.5,0.970,0.002,30
1000000,12.64,0.42,29688.0,204.7,0.970,0.001,30
```

- `variable_value` — the independent variable for that experiment.
- `primary_mean` / `primary_ci95` — mean and 95% CI half-width of the primary metric.
- `secondary_*` — leave blank where a metric does not apply to that scheme.
- `n_runs` — retained runs (must equal 30 in reportable data).

**`run_meta.json`** — provenance, as specified in §7.

Units are fixed per experiment and declared in the config: latency in **ms**, sizes in **KB**, throughput in **queries/s**. Never mix.

---

## 10. Figure Mapping

The plotting script writes directly to the filenames the manuscript expects. Do not rename figures on either side.

| Exp. | `Plots/output/` file | Manuscript `\includegraphics` | Label |
|------|---------------------|------------------------------|-------|
| 1 | `fig_exp1_trapdoor.pdf` | `images/fig_exp1_trapdoor.pdf` | `fig:exp1` |
| 2 | `fig_exp2_search.pdf` | `images/fig_exp2_search.pdf` | `fig:exp2` |
| 3 | `fig_exp3_crossdomain.pdf` | `images/fig_exp3_crossdomain.pdf` | `fig:exp3` |
| 4 | `fig_exp4_verify.pdf` | `images/fig_exp4_verify.pdf` | `fig:exp4` |
| 5 | `fig_exp5_update.pdf` | `images/fig_exp5_update.pdf` | `fig:exp5` |
| 6 | `fig_exp6_sync.pdf` | `images/fig_exp6_sync.pdf` | `fig:exp6` |
| 7 | `fig_exp7_throughput.pdf` | `images/fig_exp7_throughput.pdf` | `fig:exp7` |
| 8 | `fig_exp8_balance.pdf` | `images/fig_exp8_balance.pdf` | `fig:exp8` |

Figure conventions: **vector PDF** (never PNG for plots), single-column width, 8 pt minimum font, 95% CI drawn as error bars on every point, log-scaled x-axis where the sweep is logarithmic (Exp. 2, 5, 6), and one consistent color/marker per scheme across all figures. Figures must remain legible in grayscale — distinguish schemes by marker shape and line style, not by color alone.

---

## 11. Running the Benchmark

### Automated (Linux only)

```bash
chmod +x run_benchmark.sh
./run_benchmark.sh                       # all schemes, all experiments, then plots
./run_benchmark.sh --scheme ma_lb_pq_vdse --experiment 2
```

### Manual — Linux

```bash
# 1. Environment
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Dataset — generate a Synthea corpus first:
#      git clone https://github.com/synthetichealth/synthea && cd synthea
#      ./run_synthea -p 400000
python3 Dataset/prepare_dataset.py --input /path/to/synthea/output/csv --output Dataset/derived
#    development smoke test only, NOT reportable:
python3 Dataset/synthetic_generator.py --records 100000 --domains 4 --output Dataset/derived

# 3. Infrastructure (proposed scheme only)
docker compose -f infra/fabric/docker-compose.yaml up -d     # Hyperledger Fabric v2.5
ipfs daemon &

# 4. Run one scheme
python3 -m Schemes.ma_lb_pq_vdse.src.main \
    --experiment all \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30

# 5. Baselines (same dataset, same config)
python3 -m Schemes.guo_vdsse.src.main --experiment 1,2,3,4,5 --dataset Dataset/derived --runs 30

# 6. Figures
python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

### Manual — Windows (PowerShell)

```powershell
# 1. Environment
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Dataset — generate a Synthea corpus first (see Linux block above)
python Dataset/prepare_dataset.py --input C:\path\to\synthea\output\csv --output Dataset/derived
#    development smoke test only, NOT reportable:
python Dataset/synthetic_generator.py --records 100000 --domains 4 --output Dataset/derived

# 3. Infrastructure (proposed scheme only)
docker compose -f infra/fabric/docker-compose.yaml up -d
# IPFS: run 'ipfs daemon' in a separate terminal

# 4. Run one scheme
python -m Schemes.ma_lb_pq_vdse.src.main `
    --experiment all `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 30

# 5. Baselines (same dataset, same config)
python -m Schemes.guo_vdsse.src.main --experiment 1,2,3,4,5 --dataset Dataset/derived --runs 30

# 6. Figures
python Plots/generate_plots.py --input Schemes --output Plots/output
```

See each scheme's `SCHEME.md` for scheme-specific run commands and notes.

`generate_plots.py` walks `Schemes/*/exp<N>_*/results.csv`, overlays every scheme present for that experiment, and skips schemes with no `results.csv` — so partial runs still plot.

---

## 12. Collaboration Guide

This repository is built for parallel work. Each collaborator owns one or more scheme folders.

> **Always `git fetch` / `git pull` before starting any work.** This ensures you are working against the latest code, configs, and documentation. Stale local state is a source of merge conflicts and wasted runs.

1. **Fetch first.** `git fetch origin && git pull` every time before you begin work — no exceptions.
2. Work only inside your assigned `Schemes/<your_scheme>/` folder.
3. Implement the scheme in `src/`, faithfully to its published construction.
4. Run each relevant experiment; emit `raw_runs.csv`, `results.csv`, and `run_meta.json` into the matching `exp<N>_*/` folder.
5. Do **not** modify `Dataset/`, `Plots/`, `Experiment Configuration/`, or another member's scheme folder.
6. When all schemes have produced results, run the plotting script once to generate the final figure set.
7. **Update this README** to reflect whatever you changed (see §13), in the same commit.

### Commit Message Guide

Every commit must have a clear, traceable message. Use this format:

```
<type>(<scope>): <short summary>

<optional body — what and why, not how>

<optional footer — results-affecting flag, references>
```

#### Types

| Type | When to use |
|------|-------------|
| `feat` | New functionality (scheme implementation, experiment code, plotting feature) |
| `fix` | Bug fix in existing code |
| `data` | Dataset preparation, synthetic generator, or derived corpus changes |
| `exp` | Experiment execution — running benchmarks, producing results |
| `config` | Changes to `Experiment Configuration/` files (λ weights, index params, crypto params) |
| `docs` | Documentation only (README, SCHEME.md, AGENT_RULES.md) |
| `refactor` | Code restructuring with no behavior change |
| `plot` | Plotting script or figure output changes |
| `chore` | Dependency updates, CI, tooling, cleanup |

#### Scope

The scope identifies **what** was changed:

| Scope | Meaning |
|-------|---------|
| `ma_lb_pq_vdse` | Proposed scheme |
| `guo_vdsse` | Ref[35] baseline |
| `xb_muse` | Ref[36] baseline |
| `thingom_pq_abse` | Ref[41] baseline |
| `zhuang_lattice_mabse` | Ref[52] baseline |
| `dataset` | Dataset preparation or synthetic generator |
| `config` | Experiment configuration files |
| `plots` | Plotting script or output |
| `infra` | Infrastructure (Fabric, IPFS, Docker) |
| `readme` | This README |
| `all` | Cross-cutting change affecting multiple schemes |

#### Rules

1. **First line ≤ 72 characters.**
2. **One logical change per commit.** Do not mix a scheme implementation with an unrelated config change.
3. **Mark results-affecting commits** in the footer with `Results-Affecting: yes` — this flags that results generated before this commit are not comparable to results generated after it.
4. **Reference the experiment** when committing results: `Experiment: exp2` or `Experiment: exp7,exp8`.
5. **Never commit results and code changes in the same commit** — separate them so provenance is unambiguous.

#### Examples

```
feat(ma_lb_pq_vdse): implement Phase IV PDSI index construction

Bitmap-based searchable index with Merkle commitments.
Supports incremental updates per Phase VII contract.
```

```
exp(guo_vdsse): run exp1 trapdoor generation (n=30, Synthea)

Experiment: exp1
Dataset: synthea (SHA-256: a3f8...)
```

```
config(config): fix λ weights for AASS scheduler

λ₁=0.25, λ₂=0.20, λ₃=0.20, λ₄=0.15, λ₅=0.20
Determined by one-time sweep on held-out workload (see sweep_log.csv).

Results-Affecting: yes
```

```
fix(xb_muse): correct trapdoor size calculation in exp1

Was double-counting the nonce; trapdoor size was inflated by 32 bytes.

Results-Affecting: yes
```

```
docs(readme): add commit message guide to §12
```

---

## 13. Keeping This README Current

This README is the single source of truth for how the benchmark is defined, configured, and run — it is what the team, and the paper's Evaluation section, are written against. It is a **living document**.

> **Standing rule: every time you complete work in this repository, update this README in the same commit as the change it describes.** This applies to every **human** contributor. A change that alters how the benchmark behaves but leaves the README describing the old behavior is an incomplete change.

> **AI Agent exception:** AI agents must **NOT** edit this `README.md` file. This file is the source of truth — if an AI agent could edit it, the specification would lose consistency. If an AI agent identifies that `README.md` needs an update, it must ask the user to make the change. AI agents may update scheme-specific `SCHEME.md` files. See [`AGENT_RULES.md`](AGENT_RULES.md) for the full AI agent behavioral specification.

### Update triggers

| When you… | Update |
|-----------|--------|
| Implement or modify a scheme | §3 baseline table (status), §8 structure tree |
| Add, remove, or re-scope an experiment | §5 experiment table, §10 figure mapping, §8 tree |
| Fix an open parameter (λ₁…λ₅, bitmap/Bloom, index size) | §6 defaults table — move it out of *not specified in the paper* |
| Change what a timer includes or excludes | §5 per-experiment measurement rules |
| Change repetitions, warm-up, CI level, or clock | §6 defaults, §7 methodology |
| Add or rename a file, folder, or module | §8 structure tree |
| Change CSV columns, units, or metric names | §9 output format |
| Rename a figure or change plot conventions | §10 figure mapping |
| Change environment, library, or instance type | §1 environment table |
| Change the dataset or its preprocessing | §4 dataset, and re-record the SHA-256 |
| Deviate from the manuscript for any reason | §6 (mark as *benchmark choice*) and the Change Log |
| Discover an issue in the manuscript | §15 checklist, and the relevant section's note |
| Complete a checklist item | §15 pre-submission checklist |

### How to record it

1. Edit the affected section(s) above — do not append a note at the bottom describing a change that contradicts an unedited section.
2. Append one dated line to the **Change Log** (§16).
3. If the change alters a reported number, say so explicitly in the Change Log entry — results generated before that commit are no longer comparable to results generated after it.

If a change turns out to need no README edit, that is a valid outcome — but it should be a conclusion you reached after checking the trigger table, not a step you skipped.

---

## 14. Critical Constraints — What NOT To Do

> These rules apply to every contributor, including AI coding agents.

### Do NOT bias or fabricate results
- **Do NOT hardcode, precompute, or fabricate measurements** so that the proposed scheme wins. The manuscript's claims are hypotheses this benchmark tests.
- **Do NOT tune parameters per experiment** to flatter one scheme — no artificial delays, no scaling factors, no per-figure λ retuning.
- **Do NOT weaken a baseline** below its published construction (e.g. skipping its verification step, shrinking its security parameter) or strengthen it beyond it.
- If the proposed scheme loses on a metric, **report it as measured**. A paper with one honest negative result and a stated reason survives review; a paper with fabricated uniform wins does not.

### Do NOT break the structure
- **Do NOT rename or move** `Schemes/`, `Dataset/`, `Plots/`, or `Experiment Configuration/` — the plotting script depends on this exact layout.
- **Do NOT create experiment folders** not listed in §5. If a scheme does not participate in an experiment, it must not have that folder.
- **Do NOT place source code** inside experiment folders. Code lives in `src/`; experiment folders hold configuration and output only.

### Do NOT cross-contaminate schemes
- **Do NOT copy implementation logic** between scheme folders. Each baseline must be an independent, faithful implementation of its own paper.
- **Do NOT share runtime state, caches, or indexes** across scheme processes. Each scheme reads the shared dataset and writes only its own results.

### Do NOT modify shared resources without approval
- **Do NOT modify the derived dataset** once results generation has begun — it is the single source of truth, and its SHA-256 is recorded in every `run_meta.json`.
- **Do NOT modify** `Plots/generate_plots.py` or any file in `Experiment Configuration/` without team consensus; both affect every scheme's reported numbers.
- **Do NOT commit the derived corpus.** Synthea's licence permits redistribution, so this is a repository-size rule, not a legal one: a 10⁶-record `corpus.jsonl` is hundreds of MB. Share it as a release artifact or via Zenodo, and let `dataset_manifest.json` (counts + SHA-256, committed) carry the provenance.

### Do NOT compute what you should measure
- **Do NOT generate results analytically** from the complexity expressions in Table VI. The asymptotic analysis and the empirical evaluation are two independent pieces of evidence; deriving one from the other collapses them into one and makes the evaluation section worthless.

### Do NOT let this README go stale
- **Do NOT ship a change without updating this README** (§13). An undocumented parameter change, renamed metric, or altered timer boundary silently invalidates every earlier result it touches, and no one downstream can tell which numbers are still comparable.
- **Do NOT describe intended behavior as implemented behavior.** If a section documents something not yet built, mark it explicitly.

### AI Agent Constraints
- **AI agents must `git fetch` / `git pull` before starting any work** — every time, no exceptions. This prevents working against stale code or configs.
- **AI agents must read the supporting markdown files** — the `README.md` is the source of truth, but agents must also read `AGENT_RULES.md`, `debug_history.md`, and the relevant `SCHEME.md` before taking action.
- **AI agents must NOT edit this `README.md`** — it is the source of truth for the benchmark specification. If it needs updating, ask the user.
- **AI agents must follow [`AGENT_RULES.md`](AGENT_RULES.md)** — this includes the goal definition, execution loop, reviewer-level validation checks, ask-user-when-unsure policy, and debug logging requirements.
- **AI agents must append to [`debug_history.md`](debug_history.md)** every time they debug an issue — entries are never deleted or overwritten.
- **AI agents must ask the user** if they are unsure about any scheme's construction, a parameter value, or any decision that affects reported numbers. Do not guess.

---

## 15. Pre-Submission Checklist

- [ ] All 8 experiments produce `results.csv` with `n_runs = 30` for every participating scheme
- [ ] Every `results.csv` has a matching `run_meta.json` with a real git commit and dataset SHA-256
- [ ] All reportable runs used the Synthea corpus (`corpus_type: synthea`), not `synthetic`
- [ ] Open parameters (λ₁…λ₅, bitmap/Bloom, index size defaults) are fixed, committed, and stated in the manuscript
- [ ] All 8 figures regenerate from scratch with a single `generate_plots.py` invocation
- [ ] Figure filenames match the `\includegraphics` paths in §10
- [ ] Every numeric claim in the Evaluation section traces to a specific `results.csv` cell
- [ ] Duplicate `\bibitem{ref55}` resolved in the manuscript
- [ ] Ref[36] obtained in a readable form and `xb_muse/` verified against the real construction
- [ ] This README matches the code as committed, and the Change Log covers every change affecting a reported number

---

## 16. Change Log

Newest last. One line per change, dated `YYYY-MM-DD`. Mark entries that invalidate previously generated results with **[results-affecting]**.

| Date | Change | Sections updated |
|------|--------|-----------------|
| 2026-08-02 | Initial benchmark specification: environment, protocol-phase coverage, 4 baselines, 8 experiments, defaults, measurement methodology, repository structure, output format, figure mapping. No code implemented yet. | all |
| 2026-08-03 | Restructured: split per-scheme details into `SCHEME.md` files (one per scheme folder). Added `AGENT_RULES.md` (AI agent goal, reviewer-level validation, constraints, debug workflow), `debug_history.md` (append-only debug log), `requirements.txt` (cross-platform Python dependencies). Added §1.1 system requirements, cross-platform (Linux + Windows) run instructions in §11, scheme guide links in §3 and §8, AI agent constraints in §14. | §1, §3, §8, §11, §13, §14, §16 |
| 2026-08-03 | Added shared primitive layer `Common/crypto/` (hashes, RNG, AES-256-GCM, PRF + t-puncturable PRF, Merkle, Bloom, lattice trapdoor toolkit, pairing backends, ML-KEM-768) with the `Common/` scope rule in §8; added `Experiment Configuration/crypto.yaml` and `dataset.yaml` fixing every cryptographic and corpus parameter with published-vs-benchmark provenance per value; implemented `Dataset/corpus.py`, `prepare_dataset.py` (MIMIC-IV v3.1, record unit `admission` or `icu_stay`), and `synthetic_generator.py`. No experiment code and no results yet. | §8, §16 |
| 2026-08-03 | Corrected `requirements.txt`: pairing libraries were listed as proposed-scheme-only, but Ref[41] is itself pairing-based (Type-I, DBDH — `References/Ref[41].txt:510-513`), so a pairing library is required to run a **baseline**. Reportable Ref[41] runs need `charm-crypto` (symmetric SS512, Linux-only); `petrelic` is Type-III and development-only. Also flagged that the `cryptography>=43.0.0` ML-KEM-768 attribution is unverified. | `requirements.txt` |
| 2026-08-03 | **Dataset change: MIMIC-IV removed entirely; Synthea (MITRE, Apache 2.0) is the sole corpus.** Rationale: Synthea has no size ceiling (MIMIC-IV v3.1 caps at 546,028 hospitalizations / 94,458 ICU stays, so 10⁶ records was unreachable), needs no credentialing or DUA, is a peer-reviewed citable generator, produces real keyword co-occurrence that Exp. 2's `n_eff` claim depends on, and supplies a real institutional domain split via `encounters.ORGANIZATION`. `corpus_type` is now `synthea` (reportable) or `synthetic` (not reportable); `mimic` is gone. `prepare_dataset.py` rewritten Synthea-only. **[results-affecting]** — no results exist yet so nothing is invalidated, but manuscript §V must be rewritten to match, including the dataset citation. | §4, §6, §7, §8, §11, §12, §14, §15, §16 |
| 2026-08-03 | Added `Common/crypto/tests/test_primitives.py` — property tests for every primitive (framing injectivity, GCM tamper detection, t-Pun-PRF correctness off/on the punctured set, Merkle incremental-update equivalence and odd-leaf promotion, Bloom no-false-negatives, gadget exactness, TrapGen/SamplePre/SampleLeft defining equations, pairing bilinearity, ML-KEM round trip). Runs standalone or under pytest; optional backends skip rather than fail. Added `.gitignore` covering `Dataset/derived/` so credentialed-derived data cannot be committed (§14). | §8, §16 |
