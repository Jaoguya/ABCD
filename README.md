# MA-LB-PQ-VDSE — Experimental Benchmark

Experimental implementation and evaluation harness for:

> **"Achieving Post-Quantum and Dynamic Load-Balanced Verifiable Searchable Encryption for Multi-Authority IoMT Data Sharing"**
> Submitted to *IEEE Open Journal of the Communications Society* (OJ-COMS).
> Manuscript: [Overleaf/PQ-AVDSE-OJCOMS](Overleaf/PQ-AVDSE-OJCOMS)

**MA-LB-PQ-VDSE** is a fog–cloud framework for encrypted IoMT data sharing combining multi-authority authorization, policy-bound dynamic searchable encryption, authorization-aware search scheduling, incremental authorization synchronization, blockchain-anchored verifiable retrieval, and ML-KEM key establishment.

This repo implements the protocol phases and four baselines, runs the eight experiments in §V of the manuscript, and produces the paper's figures. Every number in the paper should trace back to a `results.csv` produced here.

New to this project? Start with **[SystemConfiguration.md](SystemConfiguration.md)** — the operator's guide: what the experiment is, how it is configured, how to run it, and the flag points that are not obvious from the code. This README stays the *specification*.

**Status (2026-08-29):** **all five schemes are implemented and run** — `ma_lb_pq_vdse` (proposed), `guo_vdsse` (Ref[35]), `thingom_pq_abse` (Ref[41]), `perera_lv_pqabse` (Ref[54]), `yue_ge` (Ref[55]). Corpus v4 is frozen at 10 domains, the Type-III pairing backend is in place, FSNs execute as independent processes, and the λ weights are fixed by the documented sweep. Every runner of every scheme has been executed end to end; the full test suite is 651 passed / 5 skipped.

**Campaign cost:** 74.4 h of compute, ~$14–36. Wall-clock is 25 h at one instance per scheme, or **~11 h** split by sweep point with `--points` (§11).

**Blocking a complete campaign:** Exp. 4 and Exp. 6 depend on a Fabric ledger adapter that does not exist yet — they run, but `run_meta.json` records that their chain-consistency cost is understated. Exp. 6's O(δ²) blocker was **resolved 2026-08-29** (§14 item 10).

---

## Branching: there is one branch, and it is `main`

**Never create a branch. Never work on one. Commit straight to `main`.**

Set by the user on 2026-09-03 after `exp78-diagnosis`, `final-debug`, `Zhuang`,
`ma-lb-pq-vdse` and `ref-36-XB-Muse` had to be reconciled by hand. That merge hit
59 add/add conflicts, every one of them on generated artefacts -- results.csv,
raw_runs.csv, run_meta.json and figures -- because two branches had independently
produced results for the same experiment. Resolving those by hand is exactly the
operation that silently replaces a fresh measurement with a stale one, and it
nearly did: one side held guo/Scheme35 Exp. 2 at the commit with both correctness
fixes, the other held the superseded run, and only the `git_commit` field inside
each `run_meta.json` distinguished them.

Result files are tracked, so a branch is not a cheap experiment here the way it is
in ordinary code. Two branches that both run a scheme produce two conflicting
histories of the same number, and git cannot tell you which is real.

If an experiment needs isolating, isolate it with `--points` and a separate output
directory, not with a branch.


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
| ~~`xb_muse/`~~ | Ref[36] | Jiang *et al.*, IEEE IoT-J 2025 | **DROPPED 2026-08-23** — no SGX on the benchmark host (§14 item 8). Folder removed; the citation remains in related work. |
| `thingom_pq_abse/` | Ref[41] | Thingom *et al.*, IEEE TCE 2026 | Multi-authority ABSE |
| `perera_lv_pqabse/` | Ref[54] | Perera and Fugkeaw, IEEE IoT-J 2026 | Lattice-based post-quantum ABSE — replaced Ref[52] on 2026-08-27, implemented 2026-08-29 |
| `yue_ge/` | Ref[55] | Ge *et al.*, IEEE IoT-J 2024 | Verifiable multilevel DSSE (Peony/Peony++), forward + Type-II backward privacy — added 2026-08-28 |

Per-scheme experiment lists and run commands are in each `SCHEME.md`. Reference PDFs in [References/](References/).

**Published parameters extracted from the references** (recorded in `Experiment Configuration/crypto.yaml` with line citations):

- **Ref[35]** — SHA-256 hashes, HMAC-SHA256 PRFs, t-Pun-PRF from two HMACs (SHA256 + Blake2b), λ=128, 192-bit hash output. Note the VBTree `L=32` in that paper belongs to a *compared* scheme (Wu et al.), not Guo's own.
- **Ref[41]** — Type-I symmetric pairing `e : I₁×I₁→I₂` under DBDH. The paper calls itself post-quantum while resting on DBDH, which Shor breaks; it also states elsewhere that pairings aren't post-quantum. Implement as published and report the observation.
- **Ref[54]** — λ=192 (NIST Category 3), Kyber768 KEM, Dilithium3 signatures, SHA3-256/HKDF, AES-256-GCM — all published. Lattice CP-ABE parameters `(n,q,σ)` are **not published**, stated only as "consistent with Kyber768 and Dilithium3" (`Ref[54].md` §IV.C); attribute universe size is also unpublished. Both were decided on 2026-08-29 — `n=768` (Kyber768's security is module-LWE of rank 3 over a degree-256 ring, i.e. an effective LWE dimension of 768; the ring degree 256 would name the right number for the wrong parameter), `q=2²²`, `σ=4.0`, `|U|=10` — with the full reasoning in `Experiment Configuration/crypto.yaml`'s `perera_lv_pqabse` block.
- **Ref[36]** — clean copy obtained 2026-08-05 (the original was corrupted; archived under `References/corrupted_archive/`). Construction: **SRE (Symmetric Revocable Encryption)** built from a **multi-puncturable PRF** and a **Bloom filter** of revoked tags, plus keyed PRFs `F`/`G` for address derivation and on-chain revocation status. Our existing `prf.py` (puncturable PRF, punctures at a set of points) and `bloom.py` cover the SRE building blocks. **Requires Intel SGX** — key provisioning and part of the algorithm run inside an enclave with SGX attestation (`Ref[36].txt:341,359`). See §14.

In Exp. 3 the baselines run in native mode: `d` independent trapdoors and `d` searches with client-side aggregation. That's what Table VI assumes.

---

## 4. Dataset

| Property | Value |
|----------|-------|
| Source | **Synthea** (MITRE), Apache 2.0 — Walonoski *et al.*, *JAMIA* 25(3), 2018, doi: 10.1093/jamia/ocx079 |
| Record unit | One clinical encounter |
| Keyword sources | SNOMED conditions/procedures, RxNorm medications, LOINC observations (quantile-binned), CVX immunizations, allergies, devices, care plans, imaging body sites |
| Domains | 10, derived from `encounters.ORGANIZATION` (raised from 4 on 2026-08-28 so Exp. 3 can sweep its published `d=2..10`) |
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

### Frozen corpus (v4) — re-frozen 2026-08-28

Synthea `7e08387`, 38,000 patients, seed 20260804.

| | |
|---|---|
| Records | 1,143,792 |
| Keyword universe | 2,023 distinct |
| Keyword/document pairs | 36,263,865 |
| `|W_i|` min / median / mean | **5** / 29 / 31.70 |
| Zipf exponent | 2.741 |
| Domains | **10**, 114,379–114,380 each (0.001% imbalance) |
| SHA-256 | `e56ca2d14b3b6438a231fa9d00c5970a91cd0085879fa214092efbb7f707d6a0` |

**Why 10 domains.** v3 carried 4, but §V sweeps Exp. 3 over `d = 2..10`, so
three of five sweep points could not run at all. Rebuilt with `--domains 10`.
This required no Synthea regeneration — only the extraction step re-ran over
the preserved CSVs, which is deterministic — so records, keyword universe,
`|W_i|` distribution and Zipf exponent are **identical** to v3; only the
domain partition changed. The 1,195 distinct organizations pack into 10
near-exact buckets (largest single org is 74,718 encounters, well under the
259,338 per-domain ideal), so domains remain real institutional boundaries
rather than an arbitrary split.

Note `global.yaml defaults.domains` stays at **4** — that is §V's published
default for Exp. 1/2/4/5/6 and is a different quantity from how many domains
the corpus can *supply*. The config validator checks coverage
(`corpus.domains >= max(exp3 sweep)`), not equality.

**Why v3 and not v2.** v2 (`fd4b7654…`, 1,141,072 records, frozen 2026-08-04)
lived only on an instance that was terminated, and the corpus is git-ignored,
so it is gone. Regenerating with the documented recipe — same Synthea commit,
seeds, patient count and export flags — produced this corpus instead, because
Synthea generates patients across threads: a fixed seed pins the random
*stream* but not which patient consumes which draw. The recipe is reproducible
in shape, not in bytes, so regenerating again would yield a *fourth* digest
rather than recovering v2. **No results existed against v2** (checked on both
instances before it was lost), so nothing is invalidated. v3 satisfies every
property v2 was selected for: `synthea`, min `|W_i|` = 5 against the published
`q=5`, and exactly balanced domains.

**v3 *is* re-derivable**, unlike v2: the raw Synthea CSVs are preserved at
`~/synthea/output_full/csv` in AMI `ami-0feb3b14b4ea27844`, and re-running
`prepare_dataset.py` over those fixed CSVs is deterministic — the
non-determinism is in Synthea's *generation*, not in extraction. Keep that AMI.

**Domain count is a hard limit on Exp. 3.** The corpus carries exactly 4
domains (real organization boundaries), but §V sweeps `d = 2..10`.
`CorpusRecordSource` refuses `d > 4` rather than re-bucketing records into a
synthetic split while still reporting `corpus_type: synthea`. This needs an
author decision — see §14.

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
| 5 | Dynamic Keyword Update | (keyword, doc) pairs `k` | 10² → 10⁵ | latency (ms) | Merkle nodes recomputed, entries rewritten | Ours, Ref[35] |
| 6 | Authorization Sync | updates `δ` | 10² → 10⁵ | latency (ms) | IAS message size (KB), FSNs touched | Ours |
| 7 | Search Throughput | concurrency | 100 → 5000 | throughput (q/s) | p50/p95 latency, rejected | Ours — ablation |
| 8 | Load Balancing | concurrency | 100 → 5000 | std dev of FSN utilization | max-node util, peak queue depth | Ours — ablation |

### Scheduler ablation (Exp. 7–8)

Internal ablation, not a cross-scheme comparison. Four variants over one workload trace:

| Variant | Node selection |
|---------|---------------|
| `no_lb` | fixed FSN |
| `round_robin` | cyclic, authorization-oblivious |
| `least_loaded` | min queue length, authorization-oblivious |
| `aass` | `arg min SC_j`, `SC_j = λ₁C^auth + λ₂C^index + λ₃C^verify + λ₄C^sync + λ₅C^queue` |

Exp. 7 and 8 report different metrics over **the same recorded arrival trace**, replayed once per experiment per variant. The trace is built deterministically in setup, so both experiments see an identical workload — verified by digesting it: `exp7` and `exp8` produce the same trace hash, stable across repeated calls. The digest covers the workload itself — keyword tokens, authorization root, user id, and the AIM decision — and excludes each `SearchToken`'s fresh random nonce, which necessarily varies per token. The trace is identical in *content*; it is deliberately not byte-identical. They are not the same *replays*: each experiment runs its own, so the two differ by timing noise and Exp. 8's σ cannot be paired run-for-run with a specific Exp. 7 throughput. Aggregate per-point comparison across variants, which is what the figures show, is unaffected. Throughput alone can hide congestion: a scheduler can post good aggregate numbers while pinning one node at saturation, which is what Exp. 8 exists to expose.

### Measurement boundaries

These decide what the numbers mean.

- **Exp. 1** — online trapdoor generation only. ML-KEM encapsulation happens once at session establishment; report it separately as a setup cost, not in the per-query curve.
- **Exp. 2** — full online path: AIM check → AASS selection → shard search → response assembly. Index construction is offline. Report `n_eff` alongside latency; that secondary metric is the only thing that can demonstrate the paper's claim.
- **Exp. 3** — baselines issue `d` trapdoors and `d` searches; ours issues one reused across domains. Count trapdoors issued so the mechanism is visible.
- **Exp. 4** — client-side verification only: Merkle proof, `Commit_i*` recomputation, chain consistency. IPFS fetch and decryption excluded.
- **Exp. 5** — incremental update only. A global rebuild means Phase VII is implemented wrong. `k` counts (keyword, document) pairs — the corpus has 18.8M of them, so 10⁵ is available; read as distinct keywords it would be impossible against a 2,102 vocabulary.
- **Exp. 6** — IAS end-to-end: commitment recomputation → Merkle path update → IAS message → selective FSN propagation until all affected FSNs report the new `VID`. Report FSNs touched; selective propagation is the claim.
- **Exp. 7–8** — closed-loop generator, fixed concurrency per point, recorded arrival trace so all variants see identical workloads. Utilization sampled every 100 ms. Index size is the §6 default 10⁵, sized as Exp. 2 sizes it (`index_size // keywords_per_record`) so `N` means the same thing in both. The 30 s ramp runs once per sweep point inside setup, not once per run — "warm after a ramp" means the 10 retained runs all see a warm system, and ramping per run would time a warm-up 10 times over.
  - **Query domain span is a benchmark choice, not published.** §V fixes `d = 4` but never says how many domains one query touches. The Data User population is uniform over spans 1…`d` with the starting domain rotated, so every domain appears equally often and no FSN is structurally favoured. A single user authorized across all domains — which is what this was — makes `C^auth` constant on every node and leaves the scheduler nothing to discriminate on.
  - **Cross-node forwards is not reported, and cannot be.** At `d = m = 4` each FSN holds exactly one domain, and the scheduler only ever considers nodes serving an authorized domain, so the chosen node serves exactly one of a request's `k` domains *whichever node it is* — the forward count is `k−1` under all four variants, measured identically at 600 over 400 requests. Peak queue depth replaces it: it measures node congestion, which is what the claim is actually about, and it is only measurable now that the FSN queue is fed by the dispatch path.

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

- **Repetitions.** 10 runs per point after 5 discarded warm-ups. Report mean ± 95% CI.
  Reduced from 30 on 2026-09-03. Note the 95% t multiplier is 2.26 at n=10 against
  2.05 at n=30, so every interval is ~10% wider than a banked one before any change
  in variance — widths are not comparable across the two campaigns.
- **Clock.** `time.perf_counter_ns()` for latency; wall-clock for throughput.
- **Isolation.** One experiment at a time per instance, no concurrent plotting or preprocessing.
- **Cold vs warm.** State which. Defaults: Exp. 1–6 warm, Exp. 7–8 warm after a 30 s ramp.
- **Outliers.** Keep them. If a run fails, record `status=failed` in `raw_runs.csv` and re-run to restore n=10 rather than dropping it.
- **Provenance.** Each `results.csv` gets a `run_meta.json`: git commit, instance type, Python and library versions, dataset SHA-256, corpus type, config hashes, UTC start time.

BLAS threads must be pinned (`OMP_NUM_THREADS` etc.) — numpy claims all cores by default, which would make a lattice-heavy scheme's latency depend on core count (was Ref[52]'s concern; applies equally to Ref[54]'s lattice CP-ABE once implemented). `provision.sh` sets this; `environment_report()` records what was in force.

---

## 8. Repository Structure

```
├── README.md
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

**`Common/` scope.** Primitives a paper *cites* (SHA-256, HMAC, AES-GCM, Merkle, Bloom, Gaussians, pairings, ML-KEM) live here so every scheme measures the same cost. Anything a paper *contributes* (Guo's forward index, Perera & Fugkeaw's hybrid index, Thingom's LSSS encoding, our PDSI/AASS/IAS) stays in its own `src/`. If two schemes seem to need the same construction, one of them is probably being implemented unfaithfully.

Per-scheme experiment coverage: ours 1–8 · Guo 1,2,3,4,5 · Ge (Ref[55]) 1,2,3,4,5 · Thingom 1,2,3 · Perera & Fugkeaw (Ref[54]) 1,2,3 — all implemented, see their `SCHEME.md` files. Ref[54] does not cover Exp. 5/6 (no incremental-update primitive; self-disclosed no fine-grained revocation, only coarse epoch-based key evolution) — narrower than Zhuang's old slot, deliberately, not copied over. Ref[57] (Feng *et al.*, MDPI) was added on 2026-08-28 and **removed the same day**: the co-author does not accept MDPI as a venue, so only IEEE references may be cited — see `.claude/skills/reference-vetting`. Exp. 6 has no baseline as a result. XB-Muse (Ref[36]) was **dropped on 2026-08-23** — see §14 item 8. Zhuang (Ref[52]) was **dropped and replaced by Ref[54] on 2026-08-27** — see §16.

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
python3 -m Schemes.ma_lb_pq_vdse.src.main    --experiment all       --runs 30 \
    --config "Experiment Configuration/global.yaml" --dataset Dataset/derived
python3 -m Schemes.guo_vdsse.src.main        --experiment 1,2,3,4,5 --runs 30
python3 -m Schemes.thingom_pq_abse.src.main  --experiment 1,2,3     --runs 30 \
    --dataset Dataset/derived
python3 -m Schemes.perera_lv_pqabse.src.main --experiment all       --runs 30
python3 -m Schemes.yue_ge.src.main           --experiment 1,2,3,4,5 --runs 30

# Figures
python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

**Flags are not uniform** — they were written at different times. Only `ma_lb_pq_vdse` and `thingom_pq_abse` accept `--dataset`; the others read the corpus from its configured location. `guo_vdsse` and `yue_ge` use `--output-dir` where the rest use `--output`, and `--warmup` where `ma_lb_pq_vdse` and `thingom_pq_abse` use `--warmups`. See [SystemConfiguration.md §7](SystemConfiguration.md) for the full table.

### Splitting one experiment across instances

Campaign wall-clock is bounded by the largest **indivisible** unit of work, so extra instances only help if the work is split more finely. `--points` selects which sweep values one process runs:

```bash
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 2-5
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 6-10
python3 infra/merge_points.py Schemes/thingom_pq_abse/exp3_crossdomain_scalability
```

Each shard writes to its own `…__points-…` directory so instances cannot overwrite each other; `merge_points.py` re-aggregates from `raw_runs.csv` and refuses shards that disagree on git commit, corpus hash or config hashes, or that repeat a sweep value. A `--points` value the experiment does not sweep is an error, not a silent no-op. This takes the campaign from **25 h to ~11 h** at the same total compute. Exp. 2 for `guo_vdsse` and `perera_lv_pqabse` grows one index across nested prefixes and is inherently sequential — sharding it is allowed but buys nothing.

`generate_plots.py` walks `Schemes/*/exp<N>_*/results.csv` and skips schemes with no results, so partial runs still plot. Windows works for development — substitute `python` and backtick line continuations — but reportable Ref[41] runs need Linux.

---

## 12. Collaboration

Each collaborator owns one or more scheme folders. `git pull` before starting. Work inside your `Schemes/<scheme>/`; leave `Dataset/`, `Plots/`, and `Experiment Configuration/` alone unless the team agrees — they affect everyone's numbers.

Commit format: `<type>(<scope>): <summary>` with types `feat` `fix` `data` `exp` `config` `docs` `refactor` `plot` `chore` and scope naming the scheme or area. Keep the first line under 72 chars, one logical change per commit, and separate results commits from code commits so provenance stays clear. Add `Results-Affecting: yes` in the footer when a change means earlier results are no longer comparable, and `Experiment: exp2` when committing results.

```
exp(guo_vdsse): run exp1 trapdoor generation (n=10, Synthea)

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

**For AI agents.** Ask rather than guess on scheme constructions, parameter values, or anything affecting reported numbers. Edit this README only when asked to.

---

## 14. Open Issues

Decisions still needed, roughly in order of impact.

| # | Issue | Options |
|---|-------|---------|
| 1 | ~~**`\|W_i\|` median 4 vs `q=5`.**~~ **RESOLVED 2026-08-04** — `min_keywords_per_record: 5` set from the published `q`; every frozen corpus since has min `\|W_i\|` = 5. | — |
| 2 | ~~**Domains aren't uniform** (34/21/23/22%).~~ **RESOLVED 2026-08-28** — `balance_domains()` packs whole organizations largest-first; corpus v4 is 10 domains at 114,379–114,380 each (**0.001%** imbalance). | — |
| 3 | **§V still says MIMIC-IV** ([`:1902`](Overleaf/PQ-AVDSE-OJCOMS#L1902), already flagged in red) and `c6i.xlarge` ([`:1899`](Overleaf/PQ-AVDSE-OJCOMS#L1899)). | Update to Synthea + `m6i.xlarge`; fixes the duplicate `\bibitem{ref55}` at the same time |
| 4 | **Observations are 72% of the index**, conditions 4%. | Per-source cap, or disclose |
| 5 | ~~**λ₁…λ₅ undetermined.** Blocks Exp. 7–8.~~ **RESOLVED 2026-08-28** — the documented 1001-vector held-out sweep ran against independent-process FSNs: **λ = (0.2, 0.4, 0.1, 0.2, 0.1)**, `status: fixed`. An earlier run under one interpreter was discarded: it marked all 1001 vectors feasible and zeroed `C_auth`. | — |
| 6 | ~~**`charm-crypto` not installed.** Blocks Ref[41].~~ **RESOLVED 2026-08-27** — built on `44.222.205.213`/`98.91.21.219` (PBC 0.5.14 from source + `python3-config` symlink fix, now scripted into `infra/provision.sh`). | — |
| 7 | ~~**Primitive tests never run.** The crypto layer is unverified.~~ **RESOLVED 2026-08-27** — `Common/crypto/tests/test_primitives.py`: 64 passed, 1 skipped, 0 failed. | — |
| 8 | **Ref[36] requires Intel SGX** — key provisioning and part of the algorithm run in an enclave with SGX attestation. `m6i.xlarge` does not expose SGX (AWS provides Nitro Enclaves, a different trust and attestation model). | (a) Simulate the enclave as a process boundary and disclose — the cryptographic work is identical, only hardware isolation is absent, and omitting SGX's enclave-transition and EPC-paging overhead makes the baseline look *faster* than reality, which is the conservative direction; (b) run Ref[36] on an SGX-capable instance, breaking §1 parity; (c) drop it and say so in §V **RESOLVED 2026-08-23: option (c).** Ref[36] is dropped from all experiments; §V must state the omission and that the reason is hardware parity, not an unfavourable result. |
| 9 | ~~`load_verified_corpus()` materialises 1.2M records (~1–2 GB per process).~~ **PARTLY RESOLVED 2026-08-28** — `CorpusRecordSource` streams and stops at the records it needs. `load_verified_corpus()` itself is unchanged and still materialises; other schemes still use it. | Stream there too, if a baseline ever needs the full corpus |
| 10 | ~~**Exp. 6 is O(δ²) and cannot complete.**~~ **RESOLVED 2026-08-29** — root cause was `RevocationList`'s sorted-array Merkle tree: inserting one identifier shifts every later leaf, so a single revocation cost a full O(n) rebuild and Phase VII reads the root once per update. Reproduced at **O(n^2.02)** (0.8 s at δ=1,000; 53 s at 8,000; ~8,673 s/run extrapolated to δ=10⁵). Replaced with `Common/crypto/merkle.SetMerkleTrie`, a canonical binary radix Merkle trie keyed by the leaf digest — the shape depends on the key set alone, so the root stays order-independent and `restore` still returns to the exact previous root, while insert and delete rewrite only one O(log n) path. Now **O(n^1.08), ~2 s/run**; the full sweep to δ=10⁵ completes in 32 s at 3 runs/point and is linear in δ. | — |

---

## 15. Pre-Submission Checklist

- [ ] All 8 experiments produce `results.csv` with `n_runs = 10` for every participating scheme
- [ ] Every `results.csv` has a matching `run_meta.json` with a real commit and dataset SHA-256
- [ ] All reportable runs used `corpus_type: synthea`
- [x] λ₁…λ₅ fixed by the documented held-out sweep and committed — **(0.2, 0.4, 0.1, 0.2, 0.1)**, 2026-08-28. Index parameters and the statement in the manuscript are still outstanding
- [x] **Exp. 6's O(δ²) revocation-root recomputation fixed** (§14 item 10) — 2026-08-29, now O(n^1.08); the full δ=10⁵ sweep completes
- [ ] **Fabric ledger adapter written** — Exp. 4 and Exp. 6 are blocked on `ledger_faithful`; `infra/fabric/` brings the network up but no adapter reads it
- [ ] **FSN independent-process topology confirmed in the reported runs** — implemented 2026-08-28 (`fsn/pool.py`), recorded in `run_meta.json` as `fsn_processes`
- [ ] All 8 figures regenerate from one `generate_plots.py` invocation
- [ ] Every numeric claim in §V traces to a `results.csv` cell
- [ ] §V updated: Synthea (not MIMIC-IV), `m6i.xlarge`, domain distribution as measured
- [ ] Duplicate `\bibitem{ref55}` resolved
- [x] Ref[36] obtained (2026-08-05); **scheme dropped 2026-08-23** — no SGX on the benchmark host (§14 item 8, option (c))
- [x] §V states the Ref[36] omission and its reason (2026-08-28)
- [ ] §V states that Ref[41]'s Exp. 2 is capped at N=10⁴ and its search ran across 2 processes
- [ ] §V states the solo-orderer Fabric topology is a **lower bound** on Raft anchoring latency (`infra/fabric/README.md`)

---

## 16. Change Log

Newest last. Mark entries that invalidate existing results **[results-affecting]**.

| Date | Change |
|------|--------|
| 2026-08-02 | Initial specification: environment, phases, 4 baselines, 8 experiments, defaults, methodology, structure, output format, figures. |
| 2026-08-03 | Split per-scheme detail into `SCHEME.md`; added cross-platform run instructions. |
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
| 2026-08-23 | **Ref[36] (XB-Muse) dropped.** §14 item 8 resolved as option (c): the construction runs inside an Intel SGX enclave and `m6i.xlarge` exposes none, so it could only run simulated (omitting enclave-transition and EPC-paging cost, flattering the baseline) or on non-parity hardware. Removed from the Exp. 1/2/3/5 sweeps in `global.yaml`; `crypto.yaml` status is now `dropped_no_sgx_on_benchmark_host`. No results existed for it, so no `results.csv` is invalidated. §V must state the omission. |
| 2026-08-05 | **Ref[36] recovered.** Clean copy from IEEE Xplore extracted cleanly (108,474 bytes, 1,030 lines) where the corrupted original yielded 0; originals archived under `References/corrupted_archive/`. Construction identified: SRE from a multi-puncturable PRF + Bloom filter of revoked tags — both already covered by `Common/crypto/prf.py` and `bloom.py`. **New finding: the scheme requires Intel SGX** (`Ref[36].txt:341,359`), which `m6i.xlarge` does not expose. Options recorded in §14. |
| 2026-08-04 | **Environment complete and crypto layer verified.** liboqs 0.16.0 supplies ML-KEM-768 (`cryptography` 50.0.0 does not expose it, contrary to the requirements.txt comment). `charm-crypto` built after fixing `configure.sh`'s `which python3-config` probe — only `python3.11-config` exists under deadsnakes — with PBC 0.5.14 built from source first; SS512 bilinearity verified. **65 primitive tests: 64 passed, 1 skipped, 0 failed** on first execution. Noted that SS512 provides ~80-bit security (charm DeprecationWarning); Ref[41] specifies Type-I but no curve, so this is a decision to make before reportable runs. |
| 2026-08-27 | **Old experiment host terminated; new one provisioned with two provision.sh bugs fixed; frozen corpus lost and regenerated non-identically.** See §17 for full state and open questions — this entry is the pointer. **[results-affecting: corpus]** |
| 2026-08-28 | **First full campaign attempted and KILLED: Exp. 6 is O(δ²).** Exp. 1–5 completed at n=30; the run was stopped after 72 minutes with zero Exp. 6 points, and Exp. 7–8, Guo and Thingom never started. `authority/revocation.py::_compute_root` rebuilds the entire revocation Merkle tree on every `synchronize`, so per-update cost grows with the update count. Measured on the pinned host: δ=2,000 → 5.6 s, 4,000 → 21.1 s, 8,000 → 81.3 s — **O(n^1.93)** — extrapolating to **≈103 hours** at the published δ=10⁵. Found by taking a live stack trace of the stalled process (`revocation_leaf ← _compute_root ← revocation_root ← commitment ← evolve_authorization_state ← synchronize`) after an initial fit over δ≤2,000 wrongly read as O(n^1.00) and predicted 23 minutes; the defect is invisible below δ≈2,000. This is a **Phase VII implementation defect, not a slow benchmark** — README §5 requires Exp. 6 to measure *incremental* propagation, and recomputing the whole root per update is the opposite of incremental. Recorded as §14 item 10. **[results-affecting: no Exp. 6 result exists]** |
| 2026-08-28 | **Exp. 7–8 unblocked: FSNs now run as independent OS processes, and the λ weights are fixed.** `fsn/pool.py` forks one worker per node (README §1 requires it; the harness previously ran all nodes in one interpreter, so under the GIL per-node utilization could not differ and Exp. 8's metric measured bookkeeping rather than contention). With real concurrency the metrics respond to the variant — `aass` util σ 0.0601 vs `round_robin` 0.0053, where both were previously a constant 0.5. The documented 1001-vector held-out sweep was then re-run and its result adopted: **λ = (0.2, 0.4, 0.1, 0.2, 0.1)**, closing §14 item 5. The pre-fix sweep is deliberately discarded and must not be revived — it marked all 1001 vectors feasible (the constraint never bound) and picked a vector that **zeroed `C_auth`**, the authorization-awareness that is the scheme's own contribution. Also this session: the Type-III pairing backend (`CharmType3Backend`, BN254) makes the proposed scheme reportable for the first time; `--dataset` was wired to the real corpus (it had been accepted and silently ignored); the freeze pin is now actually enforced (it was claimed but never checked); `Plots/generate_plots.py` was written (it never existed); and `infra/fabric/` was added so README §11's compose command exists. |
| 2026-08-28 | **Ref[57] (Feng *et al.*, BL-ABSE) REMOVED — venue rejected by the co-author.** MDPI is not accepted, so only IEEE-published references may be cited from now on. This is an editorial decision, not a quality judgement: Ref[57] passed every content check in this repo more cleanly than either Ref[41] or Ref[54] — genuinely lattice-based, internally coherent, quantifying its own leakage and self-disclosing its limitations — and was rejected purely on publisher. Removed from `tab:comparison`, `tab:cost`, both lattice/PQ citation groups, the bibliography, `global.yaml`'s sweeps, and `Schemes/feng_bl_abse/`; `crypto.yaml` keeps a `status: dropped_non_ieee_venue` marker, and `References/Ref[57]/` is retained as evidence of the assessment. `$T_{\mathrm{NTT}}$` was removed from the cost notation, having been added solely for that row. Exp. 6 therefore has no baseline again and is a proposed-scheme-only ablation. The rule is recorded in `.claude/skills/reference-vetting` so it is applied to every future search rather than remembered. |
| 2026-08-28 | **Ref[57] (Feng *et al.*, "BL-ABSE") added as a fifth scheme; Ref[41]'s search parallelized and its sweep caps raised.** Ref[57] is **additive** — nothing was dropped for it. It fills the Exp. 6 gap no other baseline could: instant on-chain revocation is its headline contribution, proven O(1) in system size and measured flat ~2s from N=100 to 50,000. Genuinely lattice-based (RLWE commitment + lattice CP-ABE + NTT, zero pairings), and it passed this repo's legitimacy checks more cleanly than Ref[41] or Ref[54] — it quantifies its own search-pattern leakage, labels its simulated baseline numbers as simulated, and self-identifies five limitations. Only non-IEEE venue among the baselines (MDPI *Electronics*, Scopus/WoS-indexed); included on content quality, venue to be cited plainly. Unusually, it publishes **every** cryptographic parameter numerically, so `crypto.yaml`'s `feng_bl_abse` block has no undetermined values — only scoping decisions remain (Exp. 3 deferred, Fabric dependency for Exp. 6, native-mode multi-keyword), all recorded in its `SCHEME.md`. `Schemes/feng_bl_abse/src/` **not yet implemented**. Separately, Ref[41]'s per-entry search was parallelized across 2 forked processes — a **hardware-utilization change, not an algorithmic one** (same pairings computed; verified identical pairing counts and match sets against a single-threaded reference on both Exp. 2's and Exp. 3's real call shapes). Measured 1.94–1.95× in isolation, 0.371–0.389 ms/pairing end-to-end. Using the worst observed rate, the freed budget raised Exp. 2 `N` `10⁴ → 2×10⁴` and Exp. 3's held total `2,000 → 3,500`, landing at ~20.45h with ~3.55h margin (`4,000` was considered and rejected at ~22.2h/1.8h margin). §V must state that Ref[41]'s search ran across 2 processes, so its latency is not read as a single-core figure — disclosed in `SCHEME.md`. **[results-affecting: thingom_pq_abse exp2/exp3 sweep range and execution model; baseline scheme roster]** |
| 2026-08-27 | **Ref[52] (Zhuang) dropped and replaced by Ref[54] (Perera and Fugkeaw, "LV-PQ-ABSE").** Team decision: Zhuang's Exp. 2 runner never built a real N-record index (approximated the scan by replaying one real entry N times), which doesn't match the "build once, measure the real thing" methodology every other scheme here uses — rather than disclose the approximation, the scheme was replaced. Ref[54] is already cited in the manuscript's related work; it is genuinely lattice-based (LWE CP-ABE + Kyber768 + Dilithium3, no pairings anywhere) and self-discloses its own limitations rather than self-contradicting, unlike Ref[41]. `Schemes/zhuang_lattice_mabse/` removed entirely; `Schemes/perera_lv_pqabse/` **not yet implemented** — only `crypto.yaml`'s config block and `Ref[54].md`'s extraction exist so far. Two parameters the paper never publishes (lattice `(n,q,σ)`, attribute universe size) are flagged there as benchmark decisions still needed, same treatment as `thingom_pq_abse.attributes.u`. `References/Ref[52].pdf/.md` removed; `References/Ref[35]/` reorganized into the same subfolder convention as Ref[36]/Ref[41]/Ref[54]. **[results-affecting: baseline scheme roster]** |
| 2026-08-27 | **charm-crypto built on the new host; Ref[41] sweep capped to a 24h-per-track budget; a real methodology bug fixed in Exp. 3.** Built PBC 0.5.14 + charm-crypto on `98.91.21.219` (same fix as 2026-08-04, now scripted into `provision.sh`) — **64 passed, 1 skipped, 0 failed** on `test_primitives.py`, resolving §14 items 6–7. Measured Ref[41]'s real pairing cost at **0.703 ms/pairing** (vs. an earlier 1.5 ms/pairing guess) — 2.1× better, but the published `N=10⁴–10⁶` / `d=2–10` sweep still costs ~178h even at the real rate, so Exp. 2 is capped to `N=10⁴` only and Exp. 3's held-constant total index is capped `1e5 → 2,000` (`Schemes/thingom_pq_abse/src/main.py`; ~20.1h combined, disclosed in `SCHEME.md`). While sizing that cap, found and fixed a real bug in `experiment_3`: `shard_size` was a fixed constant (`DEFAULT_INDEX_SIZE // DEFAULT_DOMAINS`) instead of dividing the swept `d` into the held-constant total, so total work scaled linearly with `d` instead of staying flat as the measurement boundary requires — verified fixed (latency flat within noise across `d=2/5/10`). Audited all four schemes' Exp. 2 methodology against the "build once, then measure" standard `ma_lb_pq_vdse`'s own harness uses: `guo_vdsse` and `thingom_pq_abse` already matched it; `zhuang_lattice_mabse` does not (approximates an N-record scan by replaying one real entry N times rather than building a real N-record index) — still open, decision pending. Confirmed `ma_lb_pq_vdse`'s own full campaign (previously unmeasured) is dominated by Exp. 7–8's ramp+steady windows at ~17.6h, plausibly fitting the 24h budget without cuts. **[results-affecting: thingom_pq_abse exp2/exp3 sweep range]** |

---
| 2026-08-29 | **`Common/crypto/kem.py`'s primary backend never worked on any host** — written against `mlkem.MLKEMParameterSet`, an API no `cryptography` release shipped. Rewritten against the shipped `MLKEM768PrivateKey`/`MLKEM768PublicKey`. This alone was **132 of 132** suite failures. dk is the 64-byte FIPS 203 seed on that backend, so backends now declare `decapsulation_key_bytes` and the size assertion checks the live backend. |
| 2026-08-29 | **`Common/crypto/signature.py` added** — ML-DSA-65 (Ref[54]'s Dilithium3), probed backends, same shape as `kem.py`. |
| 2026-08-29 | **Exp. 6's O(δ²) fixed** — `RevocationList` moved from a sorted-array Merkle tree to `merkle.SetMerkleTrie`, a canonical binary radix Merkle trie. O(n^2.02) → O(n^1.08); ~8,673 s/run → ~2 s/run at δ=10⁵. §14 item 10 resolved. **[results-affecting]** — RevRoot values change; no Exp. 6 results existed. |
| 2026-08-29 | **`yue_ge` Exp. 2 memory 34 GB → 10.5 GB.** `A_c` was a dict keyed by a random 64-bit address (557 B/node measured); ListGen line 10's "non-repeating `addr_j` ≤ \|A_c\|" is a *permutation*, so `A_c` is dense. Now one flat `bytearray` of fixed-width slots (330 B/node) — closer to the paper *and* it fits the host. Runners also build one sweep point at a time. |
| 2026-08-29 | **`yue_ge` Exp. 3 held the total index constant.** It built one deployment per real corpus domain over that domain's whole record set, so `d=10` indexed 5× the data of `d=2` — the same defect fixed in `thingom_pq_abse` on 2026-08-27. Now shards a fixed N=10⁵ subset. **[results-affecting]** |
| 2026-08-29 | **`perera_lv_pqabse` (Ref[54]) implemented** — all five phases, 18 tests. Undetermined parameters decided and recorded in `crypto.yaml`: `n=768`, `q=2²²`, `σ=4.0`, `\|U\|=10`, trigram fuzzy θ=0.6, native-mode Exp. 3, and `abe_on_measured_path: false`. |
| 2026-08-29 | **Exp. 2 builds made incremental** for `guo_vdsse` and `perera_lv_pqabse`. The sweep points are nested prefixes, so rebuilding per point cost 1,880,000 inserts to produce a largest index of 1,000,000 — a 1.88× waste. guo 34.9 h → 25.0 h, perera 8.0 h → 5.5 h. Guarded by equivalence tests on index structure and search results. |
| 2026-08-29 | **`--points` sweep splitting** (`infra/sweep.py`) on every scheme, plus `infra/merge_points.py` to reassemble shards by re-aggregating from `raw_runs.csv`. Campaign wall-clock 25 h → ~11 h at unchanged total compute. |
| 2026-08-29 | **`synthetic_generator.py` no longer overwrites the frozen corpus manifest.** `--manifest` defaults to the committed `Dataset/dataset_manifest.json`, so making a dev corpus silently replaced the campaign's provenance pin. Now refused unless `--force`. |
| 2026-08-29 | **`SystemConfiguration.md` added** — operator's guide for anyone new to the project. |
| 2026-09-03 | **Two measurement defects found and fixed; the 30 → 10 change finished; full first-to-last audit.** Exp. 2 had been querying `keywords[0]` of the first record — one arbitrary keyword, unchanged across every run of every point — while `guo` and `yue_ge` each draw a NEW keyword per run. Peony++ is output-sensitive (`O(n_w^l)` is literally the matching-file count), so its ten runs at N=10⁶ spanned **0.33–1408.65 ms** and its mean sits **16.9× its median**; our flat ±2% curve was an artefact of never varying the query, and whichever keyword `keywords[0]` happened to be silently set the published figure. Now draws `warmup_runs + repetitions` keywords at the baselines' own selectivity bounds (copied verbatim from `yue_ge/src/workload.py`) and rotates one per call; warm-ups consume the first entries so retained runs align with the baselines'. Separately, Exp. 4 was recomputing Phase VIII Steps 2–3 once per index ENTRY when both depend only on the RECORD — 1000 bundles cover 167 records at `keywords_per_record = 6`, making 67% of runtime redundant; amortised for **2.08× at r=1000**, Step 1 deliberately left per-bundle. The 30 → 10 repetition change was completed across 18 stale claims in 13 files (worst: `global.yaml`'s own comment on the `repetitions: 10` line reading "§V still says 30") and is now pinned by `test_repetition_count_agreement.py`. Audit of all eight experiments against `tab:cost`: Exp. 4, 5, 6 match; Exp. 7–8 have no table row; Exp. 1's `O(1)`/`O(q)` baseline claims and Exp. 3's assumed linearity do not hold. **[results-affecting: ma_lb_pq_vdse Exp. 2 and Exp. 4 both need rerunning — see §17]** |

## 17. Session Handoff — 2026-09-03

**Read this before touching the fleet or quoting any number.** Written for
someone picking this up cold.

### 17.1 What was wrong, in one paragraph

Two measurement defects were found in the proposed scheme, both of which had
been silently shaping published numbers. Exp. 2 queried ONE arbitrary keyword
(`keywords[0]` of the first record) for every run of every point, while every
baseline draws a new keyword per run — so our flat ±2% curve measured the
repeatability of one query rather than search latency, and whichever keyword
that happened to be set the whole figure. Exp. 4 recomputed Phase VIII Steps 2–3
once per index ENTRY when both depend only on the RECORD; at
`keywords_per_record = 6` that made 67% of its runtime redundant. Both are fixed
and both reruns are in flight. Separately, the 30 → 10 repetition change had been
applied to values but not to prose — 18 stale claims across 13 files, including
`global.yaml`'s own comment on the `repetitions: 10` line.

### 17.2 DATA LOSS — disclose, do not quietly re-run

**perera's finished 10-repetition run was destroyed on 2026-09-03 by the
assistant.** It had completed Exp. 1–3 at 18:42:40 on 2026-09-02 on node
`i-0d9b2c6e1776c6f84`. While preparing that node for another job, `git checkout
-- .` was run to clear the working tree; the perera result files were tracked and
modified, so they reverted to the committed 2026-08-29 30-repetition versions.
No untracked survivors; every `results-safe-*` backup on that box is from
2026-08-29. **The data is unrecoverable and was re-run instead.**

Two consequences worth carrying forward:

* **Never `git checkout -- .` on a fleet node.** Results are tracked files. Look
  at `git status` output and understand each modified path first.
* **The watchdogs now commit results locally** before stopping, precisely so a
  finished run cannot be destroyed this way again.

### 17.3 Fleet state — all campaigns finished

| Node | Scheme | Outcome |
|------|--------|---------|
| `i-0d9b2c6e1776c6f84` | **proposed** | complete 06:33:00Z, `rc(7-8)=0`, all 8 experiments — harvested, stopped |
| `i-0c376b61dae6fed24` | **perera** | complete 06:38:33Z, `rc=0`, Exp. 1–3 — harvested, stopped |
| `i-0e5ae20e113bae9f7` | **guo** | Exp. 1–5 finished ~08:4x; **HARVEST PENDING — see below** |
| `i-025c809974bbf7511` | yue_ge | complete, harvested, stopped |
| `i-0b3030b5bd768536e` | thingom | complete, harvested, stopped |

**OPEN: guo's results are still only on its node.** Its watchdog fired and
stopped the instance correctly, but on restart the box came back `running` with
`ok/ok` status checks and **sshd never answered** (same security group as nodes
that connect fine, so it is the host, not access). Its Exp. 1–4 numbers in
§17.4 were read before it stopped; **Exp. 5 has been neither read nor
harvested.** Recover with:

```bash
aws ec2 stop-instances  --instance-ids i-0e5ae20e113bae9f7   # clean stop
aws ec2 start-instances --instance-ids i-0e5ae20e113bae9f7   # then retry ssh
# if sshd still refuses, take the console output before doing anything drastic:
aws ec2 get-console-output --instance-id i-0e5ae20e113bae9f7 --output text | tail -50
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-guo-*.bundle" /tmp/
```

**Do NOT terminate it.** `DeleteOnTermination: true` on these volumes — a stop
preserves every result, a terminate destroys them, and guo's are unbacked.

**Watchdog design, for whoever writes the next one.** Each waits for the
DRIVER to exit, not a single python process: the proposed scheme's run is two
invocations (Exp. 1–6, then 7–8), so watching "is the python alive" fires in the
gap between them and stops the box with the ablation unrun. On exit it commits
results locally, writes `~/results-<scheme>-<ts>.bundle`, attempts a push, then
stops.

**The nodes cannot push.** Remote is `git@github.com:Jaoguya/ABCD` over SSH and
no node holds a private key; copying a personal key onto a cloud instance was
deliberately not done. **For real auto-push, add a GitHub deploy key with write
access per node.** Until then, fetch the bundle and push from a machine that
holds a credential:

```bash
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-<scheme>-*.bundle" /tmp/
git fetch /tmp/results-<scheme>-*.bundle HEAD:refs/node/<scheme>
git checkout refs/node/<scheme> -- Schemes/<that-scheme-only>/
```

**That last line matters.** Each watchdog runs `git add -A Schemes/`, which is
too broad: perera's node commit also carried 39 stale 2026-08-29
`ma_lb_pq_vdse` files that were dirty in its working tree. **Merging its bundle
would have overwritten the fresh proposed-scheme results with month-old data.**
Always check `git diff --name-only <ref>~1 <ref>` and extract per-scheme paths
rather than merging. Narrowing that `git add` to the scheme the node actually
ran is a one-line fix worth making.

### 17.4 Results after the fixes — measured, 10 repetitions

**Everything below is fresh 10-repetition data.** Every scheme was re-run; the
proposed scheme had never been measured at 10 repetitions at all before this
(its previous results were all `n_runs=30` from commits `d65df6b`/`55aa3c8`,
predating both the repetition change and both fixes).

**The two fixes, before and after:**

| Exp | Before (30 rep, pre-fix) | After (10 rep, fixed) | Note |
|-----|--------------------------|-----------------------|------|
| 2 @ N=10⁶ | 24.995 **± 39.34** | **6.040 ± 0.386** | old CI was 157% of its own mean |
| 4 @ r=1000 | 28.027 | **15.411 ± 0.072** | **1.82×** faster |

Exp. 2's "8.8× blow-up at the top of the sweep" was one 582.81 ms run against a
5.698 ms median; 29 of 30 runs had been 5.63–7.31 ms. The new curve is monotonic:
0.486, 0.611, 0.853, 2.539, 6.040.

**Exp. 4 head-to-head, all three schemes at 10 repetitions:**

| r | Proposed | Scheme [30] | Scheme [35] | our rank |
|---:|---:|---:|---:|---|
| 10 | 0.172 ±0.011 | 0.135 ±0.005 | **0.062 ±0.002** | 3 of 3 |
| 100 | 1.505 ±0.005 | 0.963 ±0.027 | **0.524 ±0.006** | 3 of 3 |
| 1000 | 15.411 ±0.072 | 9.139 ±0.047 | **5.195 ±0.015** | 3 of 3 |

**We are 3rd of 3 at every point, and it is not close.** Every interval is under
3% of its mean. The amortisation narrowed the gap to Scheme [30] from 3.09× to
1.69× and was never expected to close it — **only the aggregate proof (§17.5
item 1) reaches 2nd.** The baselines barely moved between 30 and 10 repetitions
(guo 5.171 → 5.195, yue_ge 9.058 → 9.139), which is a useful check that the
repetition change disturbed nothing.

**Proposed-scheme data quality: clean.** All 27 result directories, zero
outlier-distorted points, mean/median 1.00–1.05 throughout.

### 17.4.1 guo Exp. 3 is NOT publishable as it stands

This is fresh 10-repetition data, not the stale campaign — **the defect
survived the re-run.**

| d | median | published mean | ±CI | max |
|---:|---:|---:|---:|---:|
| 2 | 36.555 | **53.786** | ±46.238 | 194.118 |
| 6 | 21.302 | **53.394** | ±46.814 | 193.964 |
| 10 | 18.538 | **42.816** | ±43.343 | 193.356 |

* **9 of 9 points distorted; the CI is ~86% of the mean.**
* **The max is ~194 ms at every single `d`** — a hard ceiling, which is guo's
  `EDBcache` miss cost (its own Alg. 3 lines 25/28). The other runs hit the cache
  at 18–36 ms.
* **The mean destroys the actual finding.** Medians fall cleanly with `d` —
  36.6 → 21.3 → 18.5, which is the scaling Exp. 3 exists to show. The mean is
  flat near 50 ms and hides it completely.

This is the sharpest instance of the open decision in §17.6: reporting
mean ± 95% CI here publishes a number whose interval is 86% of itself and whose
trend is invisible.

**perera Exp. 1 also still has 5 of 20 points distorted** (worst 4.2×,
mean/median 1.20) after its re-run — improved from 12 of 20, but this was never
purely an artefact of the 30-repetition campaign. Its Exp. 2 and 3 are clean.

### 17.5 What remains — code

1. **Exp. 4 Tier 2, the aggregate proof.** The only change that reaches 2nd:
   measured prototype **3.43× → ~8.2 ms**, proof size **86 KB → 0.34 KB**. Both
   baselines already verify this way (constant 32 B / 64 B proofs at every `r`);
   our per-bundle design is the outlier. It changes Phase VIII, so the security
   argument moves with it. Keep per-result granularity by falling back to
   per-bundle verification only when the aggregate check fails.
2. **`O(d)T_Ver` in `tab:cost` has no counterpart in the code.** There is no
   signature verification anywhere in `verify/`. Either the implementation is
   missing a domain-signature check — making our Exp. 4 number *understated* on
   top of the ledger caveat — or the table term is wrong.
3. **Fabric ledger adapter.** Until it exists, **Exp. 4 and Exp. 6 stay
   `reportable: false`** however fast they get. This is not fixable by rerunning.

### 17.6 What remains — DECISION, not work

**Scheme [54] in Exp. 4.** Exp. 4 has **3 of 5 schemes**. `global.yaml:79` pins
the roster to `[ma_lb_pq_vdse, guo_vdsse, yue_ge]`, and **zero source files** in
thingom or perera mention `exp4`.

* **[41] is correctly excluded** — Ref[41] has no verification algorithm.
* **[54] was never decided.** `perera_lv_pqabse/SCHEME.md:24` calls its
  verification "comparable in spirit — partitioned Merkle proofs" and says
  inclusion "needs a decision before inclusion, not defaulted to yes". Its paper
  is *LV-PQ-ABSE: A Lightweight **Verifiable** PQ-ABSE*, with Merkle inclusion
  proofs, a threshold-Dilithium-signed root, and a freshness check.
* **The manuscript already assumes it belongs**: `tab:cost` gives [54] a full
  verification row, `O(x log N)T_H + O(x)(T_Ver+T_MAC)`, while `global.yaml:78`
  claims [41] and [54] "have no result-verification primitive at all". **These
  contradict each other and the table is what a reviewer reads.**
* **This is the likeliest source of the "we rank 2nd in Exp. 4" estimate.** If
  [54] were implemented and lands slower than 15.4 ms, the proposed scheme is
  2nd of 4. Either implement `perera_lv_pqabse/exp4`, or drop [54] from the
  verification column so the paper stops claiming a measurement that does not
  exist.

**How the baselines' spread should be reported.** `guo` caches by version key
(its own Alg. 3 lines 25/28): identical secondary counters, latency 0.015 ms to
195 ms. `yue_ge` is output-sensitive — `O(n_w^l)` is literally the matching-file
count — so at N=10⁶ its ten runs spanned **0.33 → 1408.65 ms** and its mean is
**16.9× its median**. Neither is a bug; rerunning reproduces both exactly. But §7
mandates "mean ± 95% CI" with outliers kept, and a mean 17× its median is hard to
defend in a figure. Note this interacts badly with 30 → 10: fewer samples from a
heavy-tailed distribution make the *mean* less stable, not more.

### 17.7 What remains — manuscript

Reported as file + line; not edited by the assistant.

| Where | Says | Measurement |
|-------|------|-------------|
| `tab:cost`, [35] trapdoor | `O(1)T_PRF` | rises 61% across q=1..20 (R² 0.879) |
| `tab:cost`, [30] trapdoor | `O(q)T_CPRF` | step function, jumps at q=5→6 and 13→14; linear fit needs an impossible −3.99 ms intercept |
| `tab:cost`, Search row (our Exp. 3) | implies linear in `d` | sublinear, 0.076 → 0.154 ms across d=2→10 (R² 0.983) |
| `tab:cost`, [54] verification | full formula | never measured — see 17.6 |

### 17.8 Audit result, Exp. 1 → 8

| Exp | Cost table holds? | Data quality |
|-----|-------------------|--------------|
| 1 Trapdoor | ours ✅ · [35] ❌ · [30] ❌ | clean (guo 1/20 minor, yue_ge 0/20, thingom 0/20) |
| 2 Search | ❌ | **defect fixed; rerun in flight** |
| 3 Cross-domain | ❌ sublinear | thingom 0/9 clean; guo still running |
| 4 Verify | ⚠️ phantom `T_Ver` | clean; `reportable: false` |
| 5 Update | ✅ all three | clean |
| 6 Sync | ✅ | clean; `reportable: false` |
| 7 / 8 | **no table row exists** | clean |

**Exp. 5 is the strongest unqualified result in the campaign and nothing in the
paper leans on it.** Same complexity class as both baselines, our constant
**15× better than [35] and 32× better than [30]** per updated pair (18.9 µs vs
607 and 289 µs), clean data, no caveats.

### 17.9 Commits from this session

`9c6615f` repetition prose + drift guard · `f413e62` Exp. 4 amortisation (2.08×
on dev, 1.82× on host) · `a1c3a83` Section V at 10 · `bce2e46` Exp. 2 per-run
query draw · `79a5739` earlier version of this handoff. Suite **567 passed,
1 skipped**.

---

## 18. Session Handoff — 2026-08-27 (superseded)

> **SUPERSEDED 2026-08-28.** Kept as a dated record; do not read its "still
> open" list as current. Several items below were resolved the next day — the
> corpus was re-frozen twice (v3, then v4 at 10 domains), `charm-crypto` builds,
> the Type-III backend exists, the λ weights are fixed, and Zhuang was dropped
> entirely. For current state see the **Status** line at the top of this file,
> §14 Open Issues, and §16's 2026-08-28 entries.

Left mid-provisioning. Read this before doing anything else with AWS; it replaces
guessing with what's actually true right now.

### Instances

- **Old host `3.236.231.174`** (key `~/.ssh/ABCDE_key.pem`): **terminated by the
  user.** It also turned out to be a bad AMI pick — it was running an unrelated
  `sqlservr` process, almost certainly from selecting "Ubuntu Server 22.04 LTS
  **with SQL Server** 2022 Standard" instead of a plain Ubuntu image. When
  launching AWS consoles again: plain Ubuntu 22.04 no longer appears in Quick
  Start's abbreviated list (only the SQL Server bundle does) — use "Browse more
  AMIs" for a real search, or fall back to plain **Ubuntu 24.04 LTS** as this
  session did. Also confirm instance type is `m6i.xlarge` (never `t3`/`t4g` —
  CPU credits make latency non-reproducible) and launch **one** instance first,
  never all 9 — `provision.sh` is a build-once-then-snapshot workflow, not
  nine independent provisions.
- **Experiment host** (instance `i-007e491c10f5e7d62`, name `OJCOMS`, key
  `~/.ssh/ojcoms.pem`, Ubuntu 24.04.4 LTS, `m6i.xlarge`, 30 GiB gp3): `~/abcd`
  is a real git clone, `pytest` installed, `charm-crypto` **now builds** (see
  the 2026-08-28 change-log entry) — **612 passed, 1 skipped, 0 failed**.
  **No Elastic IP**: the public IP changes on every stop/start and has already
  moved four times (`44.222.205.213` → `98.91.21.219` → `34.228.7.222` →
  `54.172.21.174`). Never hardcode it; get the current one from the console.
  Each restart also wipes `/tmp`, so long-running output belongs elsewhere.

- **AMI `ami-0b2da6ed17be6c7a1`** (`abcd-benchmark-2026-08-28b`) — **current**,
  created 2026-08-28 after the corpus rebuild. Carries corpus v4
  (`e56ca2d1`, 10 domains), the Type-III pairing backend, multi-process FSNs
  and the swept AASS weights. **Launch the fleet from THIS one**: the earlier
  AMI below holds the superseded 4-domain corpus and would fail the freeze
  check at startup.

- **AMI `ami-0feb3b14b4ea27844`** (`abcd-benchmark-2026-08-28`), superseded,
  created 2026-08-28 from the above instance. **This is the single point of recovery
  for two things that exist nowhere else**: the frozen corpus
  `Dataset/derived/corpus.jsonl` (686 MB, git-ignored via `.gitignore:12`) and
  the from-source crypto build (PBC 0.5.14 + charm-crypto + liboqs). It also
  carries the ~11 GB of raw Synthea CSVs at `~/synthea/output_full/csv` —
  keep them: the corpus non-determinism came from Synthea *generating*
  patients across threads, not from `prepare_dataset.py` extracting a corpus
  out of fixed CSVs, so those CSVs are what make the current corpus
  re-derivable. Launch the fleet **from this AMI**, not from a stock Ubuntu
  image: `provision.sh` is a build-once-then-clone workflow, and cloning one
  image is what makes §1's "identical hardware" parity claim exact rather
  than "we installed the same packages nine times".

- **Fleet: not yet launched.** The other 8 instances (4 FSN, 1
  cloud+Fabric+IPFS, 1 client, 3 baseline runners — §1) do not exist. Note
  that several of those roles have nothing to run yet: Exp. 7–8 still execute
  all FSNs in one interpreter (a recorded reportability blocker), so the 4 FSN
  nodes are idle until that is fixed; `infra/fabric/` does not exist, so the
  Fabric/IPFS node has nothing to deploy; and two of the five schemes
  (`perera_lv_pqabse`) is documentation-only.

### Local fixes — now committed (were scp'd to `44.222.205.213` but had no git
history anywhere until this session; still need pulling onto that host)

Committed as six separate commits (one logical change each, per §12), not
squashed:

- `fix(infra)`: `requirements.txt` `petrelic>=0.1.5` doesn't resolve on PyPI at
  all and was aborting `provision.sh` before it reached anything else —
  commented out (it's already a best-effort install inside `provision.sh`'s
  "Pairing backends" step, which has its own failure guard). Also adds `cmake`
  to the apt package list — `liboqs-python`'s auto-build needs it and nothing
  installed it, so every run died at the "Environment report" step with
  `RuntimeError: No oqs shared libraries found`.
- `feat(crypto)`: `Common/crypto/config.py`, `Common/crypto/__init__.py` — new
  `verify_experiment_host()` — queries the live EC2 metadata service and
  compares it against `global.yaml`'s pinned instance type, so
  `run_meta.json`'s `environment.experiment_host` records what host actually
  produced a number instead of echoing the declared config value unverified.
- `feat(ma_lb_pq_vdse)` / `feat(thingom_pq_abse)`: wired that check into each
  scheme's `reportable` gate — a run off the pinned AWS host now fails
  reportability with a stated reason.
- `feat(zhuang_lattice_mabse)`: added the `environment_report()` call it was
  missing, so it carries the same field (not yet wired into a `reportable`
  gate for this scheme — it doesn't have one to wire into yet).
- `docs(macos)`: `MacOS/SETUP.md` documents the above.
- `chore(xb_muse)`: `Schemes/xb_muse/SCHEME.md` deleted — Ref[36] is fully
  dropped (§14 item 8, option (c)); the file was a "retained for the record"
  stub with nothing else linking to it.

Still `git pull` these onto `44.222.205.213` before trusting `git log` there —
the host has the file contents (scp'd) but not this commit history.

### Corpus — needs a decision before anything is reportable again

The frozen corpus (`fd4b7654e4c20186163f0b8c390c2c50b4bc4f908bdfbca585779b8d0792dc47`,
§4) lived **only** on the terminated old instance and is gone. It was
regenerated on the new instance using the exact documented recipe — Synthea
commit `7e08387`, `-p 38000 -s 20260804 -cs 20260804`, same export flags — but
**did not come out byte-identical**:

|                    | Old (lost)      | Regenerated      |
|--------------------|-----------------|------------------|
| SHA-256            | `fd4b7654…`     | `7a4e6835…`      |
| Records            | 1,141,072       | 1,143,792        |
| Keywords           | 2,006           | 2,023            |
| Per-domain split   | 285,268 × 4     | 285,948 × 4      |
| Zipf exponent      | 2.7078          | 2.741            |

Likely cause: Synthea parallelizes patient generation across threads, so a
fixed seed pins the random *stream* but not which patient consumes which draw
from it — thread-interleaving order isn't guaranteed deterministic run to run.

No `results.csv`/`run_meta.json` exists anywhere for the old corpus (checked
both instances) — nothing is invalidated by accepting a new one. The raw
Synthea CSVs are at `~/synthea/output_full/csv` and the extracted (not yet
frozen) corpus at `~/abcd/Dataset/derived/corpus.jsonl` on `44.222.205.213`.

**Ask the user**: accept the regenerated corpus as the new freeze (update
`dataset.yaml`'s `freeze.expected_corpus_sha256` to `7a4e6835…` and today's
date, and update the record/keyword/SHA numbers cited in §4 to match), or
attempt a single-threaded regeneration first for an exact-match retry against
`fd4b7654…` (another ~49-minute run, `-p 38000` alone took 44m35s here, with
no guarantee it resolves the non-determinism)?

### Still open, not yet started

- **`charm-crypto` build failure on `44.222.205.213`.** Failed both via pip
  and from-source. 2026-08-04's changelog entry above describes fixing this
  exact class of problem before (`configure.sh`'s `python3-config` probe only
  finds `python3.11-config` under deadsnakes) — that fix was never folded back
  into `provision.sh`, so it had to be rediscovered. Worth scripting this time
  so it survives the next AMI rebuild.
- **`zhuang_lattice_mabse`'s Exp. 2 corpus-build cost.**
  `Experiment Configuration/planning/runtime_estimates.csv` estimates ~55 days
  for one `build_exp2` step. Root cause found:
  `Schemes/zhuang_lattice_mabse/src/construction/p6_encrypt.py:130-186` runs
  ~1,000 unbatched Python-loop iterations per `encrypt()` call (one matvec +
  one Gaussian-noise sample per (user, attribute) pair, up to `l·u = 500`
  pairs, twice). Fix not implemented — an early attempt to fully stack all 500
  lattice matrices into one array to benchmark a fix OOM-crashed the *old*
  instance (~15.7 GB array on a 16 GiB box), which is part of why that
  instance ended up terminated. Any retry must chunk the batch (a few dozen
  pairs at a time, not all 500) and must not cast the int64 matvec to float64
  — the accumulated sum can exceed float64's 2^53 exact-integer range at
  published parameters (`n=284`, `q=2^24`), which would silently corrupt
  results rather than just being slow.
- Full `pytest -q` has not been run on `44.222.205.213` yet — only the
  primitive-test gate inside `provision.sh` has (61/4/0). Run it before
  trusting this box for anything beyond the gate.
- AMI snapshot and the remaining 8-instance fleet launch have not happened.
