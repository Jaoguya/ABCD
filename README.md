# MA-LB-PQ-VDSE — Experimental Benchmark

Experimental implementation and evaluation harness for:

> **"Achieving Post-Quantum and Dynamic Load-Balanced Verifiable Searchable Encryption for Multi-Authority IoMT Data Sharing"**
> Submitted to *IEEE Open Journal of the Communications Society* (OJ-COMS).
> Manuscript: [Overleaf/PQ-AVDSE-OJCOMS](Overleaf/PQ-AVDSE-OJCOMS)

**MA-LB-PQ-VDSE** is a fog–cloud framework for encrypted IoMT data sharing combining multi-authority authorization, policy-bound dynamic searchable encryption, authorization-aware search scheduling, incremental authorization synchronization, blockchain-anchored verifiable retrieval, and ML-KEM key establishment.

This repo implements the protocol phases and four baselines, runs the eight experiments in §V of the manuscript, and produces the paper's figures. Every number in the paper should trace back to a `results.csv` produced here.

**Status (2026-08-04):** primitives, dataset pipeline, and configs are built and the corpus is frozen. **No scheme is implemented yet** — every `Schemes/*/src/` is empty.

---

## 1. Environment

| Component | Specification |
|-----------|--------------|
| Compute | AWS EC2 `m6i.xlarge` (4 vCPU, 16 GB, Xeon 8375C) |
| Topology | 4 Fog Search Nodes + 1 cloud server, one VPC/AZ |
| OS | Ubuntu 22.04 LTS |
| Language | Python 3.11 |
| PQ KEM | ML-KEM-768 (FIPS 203) |
| Symmetric | AES-256-GCM |
| Hash / ADS | SHA-256, Merkle tree |
| Ledger | Hyperledger Fabric v2.5 (on-chain commitments, off-chain data) |
| Storage | IPFS |
| Pairing | Type-III for our MA-CP-ABE; **Type-I (SS512) for Ref[41]** |

Each FSN is an independent process holding its own index shard, authorization version `VID_j`, and request queue. Same instance type for every scheme — a latency difference should come from the construction, not the hardware.

`m6i.xlarge` rather than the `c6i.xlarge` originally specified: same CPU, 8 → 16 GiB. Ref[52] allocates a 381 MB lattice trapdoor per attribute, and running near memory saturation contaminates latency with GC and page-cache effects. Avoid `t3`/`t4g` (CPU credits make latency non-reproducible) and Spot (an interruption kills a trace).

### Dependencies

Declared in [`requirements.txt`](requirements.txt). The two that need attention:

- **`charm-crypto`** — provides the Type-I SS512 curve Ref[41] requires. Linux only; needs a source build. Without it, Ref[41] cannot produce reportable numbers.
- **ML-KEM backend** — `cryptography>=43` does *not* include ML-KEM despite the requirements comment. `Common/crypto/kem.py` probes `cryptography`, `liboqs`, then `kyber-py` and reports which is live. Install `liboqs-python` on the experiment host.

`petrelic` works on Windows but is Type-III only, so `pairing.py` refuses it for reportable Ref[41] runs. Windows is fine for development.

Setup on a fresh instance: `bash infra/provision.sh` — installs everything and gates on the primitive tests.

---

## 2. Protocol Phases

| Phase | Name | Exercised by |
|-------|------|--------------|
| I | System Initialization | setup (not timed) |
| II | Multi-Authority Registration & Authorization-State Commitment | setup (not timed) |
| III | User Registration & Version-Bound Authorization Profile | setup (not timed) |
| IV | Policy-Bound Dynamic Search Index (PDSI) | Exp. 2, 5 |
| V | Secure Data Outsourcing | setup (not timed) |
| VI | Adaptive Authorization-Aware Search Scheduling (AASS) | Exp. 1, 2, 3, 7, 8 |
| VII | Dynamic Index Evolution & Incremental Auth. Sync (IAS) | Exp. 5, 6 |
| VIII | Verifiable Retrieval | Exp. 4 |

The three novelty claims — PDSI, AASS, IAS — are measured by Exp. 2, Exp. 7–8, and Exp. 6 respectively.

---

## 3. Baseline Schemes

| Folder | Ref | Paper | Direction |
|--------|-----|-------|-----------|
| `ma_lb_pq_vdse/` | ours | This work | Proposed framework |
| `guo_vdsse/` | Ref[35] | Guo *et al.*, IEEE TDSC 2024 | Verifiable dynamic SSE |
| `xb_muse/` | Ref[36] | Jiang *et al.*, IEEE IoT-J 2025 | State-of-the-art dynamic SSE |
| `thingom_pq_abse/` | Ref[41] | Thingom *et al.*, IEEE TCE 2026 | Multi-authority ABSE |
| `zhuang_lattice_mabse/` | Ref[52] | Zhuang *et al.*, IEEE DSC | Lattice-based post-quantum SE |

Per-scheme experiment lists and run commands are in each `SCHEME.md`. Reference PDFs in [References/](References/).

**Published parameters extracted from the references** (recorded in `Experiment Configuration/crypto.yaml` with line citations):

- **Ref[35]** — SHA-256 hashes, HMAC-SHA256 PRFs, t-Pun-PRF from two HMACs (SHA256 + Blake2b), λ=128, 192-bit hash output. Note the VBTree `L=32` in that paper belongs to a *compared* scheme (Wu et al.), not Guo's own.
- **Ref[41]** — Type-I symmetric pairing `e : I₁×I₁→I₂` under DBDH. The paper calls itself post-quantum while resting on DBDH, which Shor breaks; it also states elsewhere that pairings aren't post-quantum. Implement as published and report the observation.
- **Ref[52]** — n=284, m=13812, q=2²⁴, Bloom BF(32,3), 10 attributes, 50 users, 5 keywords per ciphertext. The published `m` matches an MP12 gadget-trapdoor decomposition exactly (6816 gadget + 6996 uniform columns).
- **Ref[36]** — clean copy obtained 2026-08-05 (the original was corrupted; archived under `References/corrupted_archive/`). Construction: **SRE (Symmetric Revocable Encryption)** built from a **multi-puncturable PRF** and a **Bloom filter** of revoked tags, plus keyed PRFs `F`/`G` for address derivation and on-chain revocation status. Our existing `prf.py` (puncturable PRF, punctures at a set of points) and `bloom.py` cover the SRE building blocks. **Requires Intel SGX** — key provisioning and part of the algorithm run inside an enclave with SGX attestation (`Ref[36].txt:341,359`). See §14.

In Exp. 3 the baselines run in native mode: `d` independent trapdoors and `d` searches with client-side aggregation. That's what Table VI assumes.

---

## 4. Dataset

| Property | Value |
|----------|-------|
| Source | **Synthea** (MITRE), Apache 2.0 — Walonoski *et al.*, *JAMIA* 25(3), 2018, doi: 10.1093/jamia/ocx079 |
| Record unit | One clinical encounter |
| Keyword sources | SNOMED conditions/procedures, RxNorm medications, LOINC observations (quantile-binned), CVX immunizations, allergies, devices, care plans, imaging body sites |
| Domains | 4, derived from `encounters.ORGANIZATION` |
| Record schema | `W_i` + `(PID_i, VID_i, Dom_i, TS_i)` |

Two corpus types: **`synthea`** (reportable) and **`synthetic`** (`synthetic_generator.py`, a fitted Zipf law with no clinical structure — development only). Both produce identical file formats; the manifest's `corpus_type` distinguishes them.

Observations are value-binned per code (`obs:8867-4:b3` = "heart rate, third quintile") because a raw numeric value would make every record unique and exercise no index. `DESCRIPTION` is deliberately not indexed alongside `CODE` — same concept, aliased.

### Generating

```bash
git clone https://github.com/synthetichealth/synthea && cd synthea
./run_synthea -p 18000 -s 20260804 -cs 20260804 \
    --exporter.fhir.export=false --exporter.ccda.export=false \
    --exporter.text.export=false --exporter.csv.export=true \
    --exporter.csv.excluded_files=claims.csv,claims_transactions.csv,payer_transitions.csv \
    --exporter.baseDirectory=./output_full

python3 Dataset/prepare_dataset.py --input ./output_full/csv \
    --output Dataset/derived --synthea-version 7e08387
```

Measured: **≈62 encounters per patient** (not the 2–3 that "encounters per patient" suggests), so 18k patients gives ~1.22M encounters. Turning off the FHIR/CCDA/text exporters matters — FHIR JSON is ~10× the CSV size and is never read.

### Frozen corpus — measured 2026-08-04

Synthea `7e08387`, 38,000 patients, seed 20260804.

| | |
|---|---|
| Records | 1,141,072 |
| Keyword universe | 2,006 distinct |
| Keyword/document pairs | 36,172,487 |
| `|W_i|` min / median / mean | **5** / 29 / 31.70 |
| Zipf exponent | 2.7078 |
| Domains | **285,268 × 4** (exact) |
| SHA-256 | `fd4b7654e4c20186163f0b8c390c2c50b4bc4f908bdfbca585779b8d0792dc47` |

`min_keywords_per_record: 5` comes from the published `q=5` — a record with fewer keywords than the query size can never match a conjunctive query, so it would be index weight that is never returned. Domains are balanced by packing whole organizations largest-first, which keeps them real institutional boundaries while satisfying §V's "uniformly distributed".

Pinned in `dataset.yaml`. `prepare_dataset.py` refuses to overwrite an existing corpus without `--force`; `Dataset.corpus.load_verified_corpus()` verifies the SHA-256 at startup and fails on mismatch.

**Known properties** — see §14 for the ones that still need a decision:

- The vocabulary is 2,102, not the tens of thousands a real EHR carries. This is a hard ceiling, not a tuning failure: Synthea `7e08387` ships **85 top-level modules (242 JSON files) containing 1,960 distinct codes in total**, and a generator can only emit codes its modules reference. We already extract *more* keywords than that (2,102) because observation value-binning splits one LOINC code into up to five. More patients cannot help — the 1,544 → 2,102 growth from 1k to 18k patients was rare codes crossing the `min_document_frequency` threshold, and it asymptotes there. The only way to widen it further is authoring new modules, i.e. inventing clinical content to move a benchmark number.
- `|W_i|` is bimodal: median 4, 21% of records hold one keyword, 7% are capped at 64.
- Domains are uneven (34/21/23/22%) because they follow real organizations.

---

## 5. Experiments

Each experiment varies one variable and holds the rest at §6 defaults.

| # | Experiment | Variable | Range | Primary Metric | Secondary | Schemes |
|---|-----------|----------|-------|---------------|-----------|---------|
| 1 | Trapdoor Generation | keywords `q` | 1 → 20 | latency (ms) | trapdoor size (B) | All 5 |
| 2 | Search Latency | index size `N` | 10⁴ → 10⁶ | latency (ms) | `n_eff`, entries traversed, prune ratio | All 5 |
| 3 | Cross-Domain Scalability | domains `d` | 2 → 10 | latency (ms) | trapdoors issued, cross-node msgs | All 5 |
| 4 | Verification Overhead | records `r` | 10 → 1000 | latency (ms) | proof size (KB), path length | Ours, Ref[35] |
| 5 | Dynamic Keyword Update | (keyword, doc) pairs `k` | 10² → 10⁵ | latency (ms) | Merkle nodes recomputed, entries rewritten | Ours, Ref[35], Ref[36], Ref[52] |
| 6 | Authorization Sync | updates `δ` | 10² → 10⁵ | latency (ms) | IAS message size (KB), FSNs touched | Ours, Ref[52] |
| 7 | Search Throughput | concurrency | 100 → 5000 | throughput (q/s) | p50/p95 latency, rejected | Ours — ablation |
| 8 | Load Balancing | concurrency | 100 → 5000 | std dev of FSN utilization | max-node util, cross-node forwards | Ours — ablation |

### Scheduler ablation (Exp. 7–8)

Internal ablation, not a cross-scheme comparison. Four variants over one workload trace:

| Variant | Node selection |
|---------|---------------|
| `no_lb` | fixed FSN |
| `round_robin` | cyclic, authorization-oblivious |
| `least_loaded` | min queue length, authorization-oblivious |
| `aass` | `arg min SC_j`, `SC_j = λ₁C^auth + λ₂C^index + λ₃C^verify + λ₄C^sync + λ₅C^queue` |

Exp. 7 and 8 report different metrics from **the same runs** — run the trace once per variant and emit both. Throughput alone can hide congestion: a scheduler can post good aggregate numbers while pinning one node at saturation, which is what Exp. 8 exists to expose.

### Measurement boundaries

These decide what the numbers mean.

- **Exp. 1** — online trapdoor generation only. ML-KEM encapsulation happens once at session establishment; report it separately as a setup cost, not in the per-query curve.
- **Exp. 2** — full online path: AIM check → AASS selection → shard search → response assembly. Index construction is offline. Report `n_eff` alongside latency; that secondary metric is the only thing that can demonstrate the paper's claim.
- **Exp. 3** — baselines issue `d` trapdoors and `d` searches; ours issues one reused across domains. Count trapdoors issued so the mechanism is visible.
- **Exp. 4** — client-side verification only: Merkle proof, `Commit_i*` recomputation, chain consistency. IPFS fetch and decryption excluded.
- **Exp. 5** — incremental update only. A global rebuild means Phase VII is implemented wrong. `k` counts (keyword, document) pairs — the corpus has 18.8M of them, so 10⁵ is available; read as distinct keywords it would be impossible against a 2,102 vocabulary.
- **Exp. 6** — IAS end-to-end: commitment recomputation → Merkle path update → IAS message → selective FSN propagation until all affected FSNs report the new `VID`. Report FSNs touched; selective propagation is the claim.
- **Exp. 7–8** — closed-loop generator, fixed concurrency per point, recorded arrival trace so all variants see identical workloads. Utilization sampled every 100 ms.

---

## 6. Default Parameters

| Parameter | Default | Source |
|-----------|---------|--------|
| Keywords per query `q` | 5 | Paper §V ("each query contains five keywords") |
| Domains `d` | 4 | Paper §V |
| Fog Search Nodes `m` | 4 | Paper §V |
| Index size `N` | 10⁵ | benchmark choice (mid-sweep) |
| Returned results `r` | 100 | benchmark choice |
| Repetitions | 30 | Paper §V |
| Confidence interval | 95% | Paper §V |
| Warm-up runs (discarded) | 5 | benchmark choice |
| ML-KEM parameter set | ML-KEM-768 | Paper §V |
| Keyword universe | 2,102 | measured from the corpus |
| Scheduler weights `λ₁…λ₅` | `scheduler.yaml` | **not in the paper — must be fixed** |
| Bitmap / Bloom parameters | `index.yaml` | **not in the paper — must be fixed** |

The λ weights are load-bearing — they define the AASS selection rule and a reviewer will ask how they were set. Choose them once by a documented procedure (e.g. a sweep on a held-out workload), commit that output, and leave them alone.

---

## 7. Measurement Methodology

- **Repetitions.** 30 runs per point after 5 discarded warm-ups. Report mean ± 95% CI.
- **Clock.** `time.perf_counter_ns()` for latency; wall-clock for throughput.
- **Isolation.** One experiment at a time per instance, no concurrent plotting or preprocessing.
- **Cold vs warm.** State which. Defaults: Exp. 1–6 warm, Exp. 7–8 warm after a 30 s ramp.
- **Outliers.** Keep them. If a run fails, record `status=failed` in `raw_runs.csv` and re-run to restore n=30 rather than dropping it.
- **Provenance.** Each `results.csv` gets a `run_meta.json`: git commit, instance type, Python and library versions, dataset SHA-256, corpus type, config hashes, UTC start time.

BLAS threads must be pinned (`OMP_NUM_THREADS` etc.) — numpy claims all cores by default, which would make Ref[52]'s latency depend on core count. `provision.sh` sets this; `environment_report()` records what was in force.

---

## 8. Repository Structure

```
├── README.md · AGENT_RULES.md · debug_history.md · requirements.txt
├── Common/crypto/          # Shared primitives (see scope note below)
│   ├── config.py hashes.py rng.py symmetric.py prf.py
│   ├── merkle.py bloom.py lattice.py pairing.py kem.py
│   └── tests/test_primitives.py
├── Dataset/
│   ├── corpus.py prepare_dataset.py synthetic_generator.py
│   ├── dataset_manifest.json
│   └── derived/            # git-ignored
├── Experiment Configuration/
│   ├── global.yaml scheduler.yaml index.yaml crypto.yaml dataset.yaml
│   └── workload/
├── Schemes/<scheme>/
│   ├── SCHEME.md
│   ├── src/                # implementation — ALL EMPTY as of 2026-08-04
│   └── exp<N>_*/           # config + results only, no code
├── infra/provision.sh · infra/fabric/
├── Plots/generate_plots.py · Plots/output/
├── Overleaf/ · References/
```

**`Common/` scope.** Primitives a paper *cites* (SHA-256, HMAC, AES-GCM, Merkle, Bloom, Gaussians, pairings, ML-KEM) live here so every scheme measures the same cost. Anything a paper *contributes* (Guo's forward index, Zhuang's key derivation, Thingom's LSSS encoding, our PDSI/AASS/IAS) stays in its own `src/`. If two schemes seem to need the same construction, one of them is probably being implemented unfaithfully.

Per-scheme experiment coverage: ours 1–8 · Guo 1,2,3,4,5 · XB-Muse 1,2,3,5 · Thingom 1,2,3 · Zhuang 1,2,3,5,6.

---

## 9. Output Format

Three files per experiment folder.

**`raw_runs.csv`** — one row per run, never aggregated:
```csv
scheme,experiment,variable_value,run_id,primary_metric,secondary_metric_1,secondary_metric_2,status
ma_lb_pq_vdse,exp2,10000,1,4.812,318,0.968,ok
```

**`results.csv`** — aggregated, consumed by the plotting script:
```csv
variable_value,primary_mean,primary_ci95,secondary_1_mean,secondary_1_ci95,secondary_2_mean,secondary_2_ci95,n_runs
10000,4.79,0.11,318.0,4.2,0.968,0.003,30
```

**`run_meta.json`** — provenance per §7.

Blank secondary columns where a metric doesn't apply. `n_runs` must be 30 in reportable data. Units: latency **ms**, sizes **KB**, throughput **queries/s**.

---

## 10. Figure Mapping

| Exp. | File | Label |
|------|------|-------|
| 1 | `fig_exp1_trapdoor.pdf` | `fig:exp1` |
| 2 | `fig_exp2_search.pdf` | `fig:exp2` |
| 3 | `fig_exp3_crossdomain.pdf` | `fig:exp3` |
| 4 | `fig_exp4_verify.pdf` | `fig:exp4` |
| 5 | `fig_exp5_update.pdf` | `fig:exp5` |
| 6 | `fig_exp6_sync.pdf` | `fig:exp6` |
| 7 | `fig_exp7_throughput.pdf` | `fig:exp7` |
| 8 | `fig_exp8_balance.pdf` | `fig:exp8` |

Written to `Plots/output/`, referenced from the manuscript as `images/<same name>`. Vector PDF, single-column width, 8 pt minimum, 95% CI error bars on every point, log x-axis for Exp. 2/5/6. Distinguish schemes by marker and line style so the figures survive grayscale.

---

## 11. Running

```bash
# Environment (fresh instance)
bash infra/provision.sh

# Dataset — see §4
python3 Dataset/prepare_dataset.py --input <synthea>/output_full/csv \
    --output Dataset/derived --synthea-version 7e08387

# Infrastructure (proposed scheme only)
docker compose -f infra/fabric/docker-compose.yaml up -d
ipfs daemon &

# Schemes
python3 -m Schemes.ma_lb_pq_vdse.src.main --experiment all \
    --config "Experiment Configuration/global.yaml" --dataset Dataset/derived --runs 30
python3 -m Schemes.guo_vdsse.src.main --experiment 1,2,3,4,5 \
    --dataset Dataset/derived --runs 30

# Figures
python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

`generate_plots.py` walks `Schemes/*/exp<N>_*/results.csv` and skips schemes with no results, so partial runs still plot. Windows works for development — substitute `python` and backtick line continuations — but reportable Ref[41] runs need Linux.

---

## 12. Collaboration

Each collaborator owns one or more scheme folders. `git pull` before starting. Work inside your `Schemes/<scheme>/`; leave `Dataset/`, `Plots/`, and `Experiment Configuration/` alone unless the team agrees — they affect everyone's numbers.

Commit format: `<type>(<scope>): <summary>` with types `feat` `fix` `data` `exp` `config` `docs` `refactor` `plot` `chore` and scope naming the scheme or area. Keep the first line under 72 chars, one logical change per commit, and separate results commits from code commits so provenance stays clear. Add `Results-Affecting: yes` in the footer when a change means earlier results are no longer comparable, and `Experiment: exp2` when committing results.

```
exp(guo_vdsse): run exp1 trapdoor generation (n=30, Synthea)

Experiment: exp1
Dataset: synthea (SHA-256: d991c695...)
```

---

## 13. Ground Rules

Short version: the benchmark tests the paper's claims rather than confirming them.

**Integrity.** Don't hardcode, precompute, or derive measurements analytically from Table VI — the asymptotic analysis and the empirical results are meant to be independent evidence. Don't tune parameters per experiment or per figure. Implement each baseline as published: no skipped verification steps, no reduced security parameters, no improvements it doesn't claim. If the proposed scheme loses on a metric, report it — one honest negative result with an explanation survives review; uniform wins invite scrutiny.

**Structure.** `Schemes/`, `Dataset/`, `Plots/`, and `Experiment Configuration/` are load-bearing paths for the plotting script. Code lives in `src/`, never in experiment folders. A scheme that doesn't participate in an experiment shouldn't have that folder.

**Isolation.** Each baseline is an independent implementation of its own paper — shared primitives come from `Common/`, but no scheme logic crosses folders and no runtime state, cache, or index is shared between scheme processes.

**The corpus is frozen.** Its SHA-256 is pinned and verified at startup. Regenerating it mid-campaign silently makes earlier results incomparable, which is why `prepare_dataset.py` refuses without `--force`. Don't commit the corpus itself (422 MB) — ship it as a release artifact and let the manifest carry provenance.

**Keep this file current.** If you change a parameter, timer boundary, metric name, file layout, or the dataset, update the relevant section and add a Change Log line in the same commit. Mark anything that invalidates existing results. A section describing behavior that isn't built yet should say so.

**For AI agents.** Read `AGENT_RULES.md` and `debug_history.md` before starting; log debugging there as you go. Ask rather than guess on scheme constructions, parameter values, or anything affecting reported numbers. Edit this README only when asked to.

---

## 14. Open Issues

Decisions still needed, roughly in order of impact.

| # | Issue | Options |
|---|-------|---------|
| 1 | **`\|W_i\|` median 4 vs `q=5`.** Conjunctive search needs `\|W_i\| ≥ q`; 55% of records have ≤4 keywords and can never match a default query. | Set `min_keywords_per_record ≥ 5`, regenerate at ~42k patients, re-freeze (~1.5 h) |
| 2 | **Domains aren't uniform** (34/21/23/22%) but §V claims "uniformly distributed". Also a confound for Exp. 8, which measures utilization spread. | Balanced org-to-domain assignment (greedy largest-first), or reword §V |
| 3 | **§V still says MIMIC-IV** ([`:1902`](Overleaf/PQ-AVDSE-OJCOMS#L1902), already flagged in red) and `c6i.xlarge` ([`:1899`](Overleaf/PQ-AVDSE-OJCOMS#L1899)). | Update to Synthea + `m6i.xlarge`; fixes the duplicate `\bibitem{ref55}` at the same time |
| 4 | **Observations are 72% of the index**, conditions 4%. | Per-source cap, or disclose |
| 5 | **λ₁…λ₅ undetermined.** Blocks Exp. 7–8. | One-time sweep on a held-out workload, committed |
| 6 | **`charm-crypto` not installed.** Blocks Ref[41]. | Source build; may fail |
| 7 | **Primitive tests never run.** The crypto layer is unverified. | `python Common/crypto/tests/test_primitives.py` |
| 8 | **Ref[36] requires Intel SGX** — key provisioning and part of the algorithm run in an enclave with SGX attestation. `m6i.xlarge` does not expose SGX (AWS provides Nitro Enclaves, a different trust and attestation model). | (a) Simulate the enclave as a process boundary and disclose — the cryptographic work is identical, only hardware isolation is absent, and omitting SGX's enclave-transition and EPC-paging overhead makes the baseline look *faster* than reality, which is the conservative direction; (b) run Ref[36] on an SGX-capable instance, breaking §1 parity; (c) drop it and say so in §V |
| 9 | `load_verified_corpus()` materialises 1.2M records (~1–2 GB per process). | Add a streaming variant |

---

## 15. Pre-Submission Checklist

- [ ] All 8 experiments produce `results.csv` with `n_runs = 30` for every participating scheme
- [ ] Every `results.csv` has a matching `run_meta.json` with a real commit and dataset SHA-256
- [ ] All reportable runs used `corpus_type: synthea`
- [ ] λ₁…λ₅ and index parameters fixed, committed, and stated in the manuscript
- [ ] All 8 figures regenerate from one `generate_plots.py` invocation
- [ ] Every numeric claim in §V traces to a `results.csv` cell
- [ ] §V updated: Synthea (not MIMIC-IV), `m6i.xlarge`, domain distribution as measured
- [ ] Duplicate `\bibitem{ref55}` resolved
- [x] Ref[36] obtained (2026-08-05) — `xb_muse/` still to be verified against the construction
- [ ] SGX approach for Ref[36] decided and stated in §V

---

## 16. Change Log

Newest last. Mark entries that invalidate existing results **[results-affecting]**.

| Date | Change |
|------|--------|
| 2026-08-02 | Initial specification: environment, phases, 4 baselines, 8 experiments, defaults, methodology, structure, output format, figures. |
| 2026-08-03 | Split per-scheme detail into `SCHEME.md`; added `AGENT_RULES.md`, `debug_history.md`, `requirements.txt`, cross-platform run instructions. |
| 2026-08-03 | Added `Common/crypto/` (hashes, RNG, AES-GCM, PRF + t-Pun-PRF, Merkle, Bloom, lattice toolkit, pairing, ML-KEM) and `crypto.yaml`/`dataset.yaml` with per-value provenance. Added `test_primitives.py` and `.gitignore`. |
| 2026-08-03 | Corrected `requirements.txt`: Ref[41] is itself pairing-based (Type-I, DBDH), so a pairing library is needed for a **baseline**, not just ours. Flagged the unverified ML-KEM attribution. |
| 2026-08-03 | Instance `c6i.xlarge` → **`m6i.xlarge`**: same CPU, 8 → 16 GiB, because Ref[52]'s per-attribute 381 MB trapdoor puts 8 GiB near saturation and contaminates latency. **[results-affecting]** |
| 2026-08-03 | **MIMIC-IV removed; Synthea is the sole corpus.** No size ceiling, no credentialing, citable generator, real keyword co-occurrence, real institutional domain split. `corpus_type` is `synthea` or `synthetic`. **[results-affecting]** |
| 2026-08-03 | Widened keyword sources 3 → 9 (added LOINC observations quantile-binned, immunizations, allergies, devices, care plans, imaging). Cap 32 → 64. **[results-affecting]** |
| 2026-08-03 | Corpus freeze enforced in code: overwrite guard, startup SHA-256 verification against manifest and pin, `--synthea-version` recorded, BLAS threads pinned, `infra/provision.sh` gated on primitive tests. |
| 2026-08-04 | **Corpus generated and frozen.** Synthea `7e08387`, 18,000 patients, seed 20260804 → 1,206,159 records, 2,102 keywords, 18.8M pairs, SHA-256 `d991c695…`. Generation 21m48s, build 1m59s. Freeze/overwrite/tamper guards verified working. |
| 2026-08-04 | Corrected stale README content against measurements: `-p 400000` → `-p 18000` (measured 62 encounters/patient, not 2–3); pairing description (charm provides the Type-I curve Ref[41] needs); Exp. 5 `k` as (keyword, document) pairs; implementation status. |
| 2026-08-04 | Rewrote for brevity — condensed the constraint sections into §13 Ground Rules and moved actionable items into §14 Open Issues. Confirmed from [`:1902`](Overleaf/PQ-AVDSE-OJCOMS#L1902) that `q=5` **is** stated in §V ("each query contains five keywords"); an earlier note claiming otherwise was wrong. |
| 2026-08-04 | **Corpus v1 superseded and v2 frozen.** v1 had median \|W_i\|=4 against `q=5`, leaving 55% of records unmatchable by a conjunctive query, and uneven domains against §V's "uniformly distributed". Added `min_keywords_per_record: 5` (from the published `q`) and `balance_domains()` (whole organizations packed largest-first). Regenerated at 38,000 patients → **1,141,072 records, min \|W_i\|=5, domains 285,268 × 4 exactly**, 36.2M pairs, 2,006 keywords, SHA-256 `fd4b7654…` pinned. v1 archived, never used for results. **[results-affecting]** |
| 2026-08-05 | **Ref[36] recovered.** Clean copy from IEEE Xplore extracted cleanly (108,474 bytes, 1,030 lines) where the corrupted original yielded 0; originals archived under `References/corrupted_archive/`. Construction identified: SRE from a multi-puncturable PRF + Bloom filter of revoked tags — both already covered by `Common/crypto/prf.py` and `bloom.py`. **New finding: the scheme requires Intel SGX** (`Ref[36].txt:341,359`), which `m6i.xlarge` does not expose. Options recorded in §14. |
| 2026-08-04 | **Environment complete and crypto layer verified.** liboqs 0.16.0 supplies ML-KEM-768 (`cryptography` 50.0.0 does not expose it, contrary to the requirements.txt comment). `charm-crypto` built after fixing `configure.sh`'s `which python3-config` probe — only `python3.11-config` exists under deadsnakes — with PBC 0.5.14 built from source first; SS512 bilinearity verified. **65 primitive tests: 64 passed, 1 skipped, 0 failed** on first execution. Noted that SS512 provides ~80-bit security (charm DeprecationWarning); Ref[41] specifies Type-I but no curve, so this is a decision to make before reportable runs. |
