# MA-LB-PQ-VDSE

Reference implementation and benchmark harness for **MA-LB-PQ-VDSE** —
*Multi-Authority Load-Balanced Post-Quantum Verifiable Dynamic Searchable
Encryption for IoMT Data Sharing* — together with four published baseline
schemes it is evaluated against.

This repository is the experimental half of the paper in
[`Overleaf/MA-LB-PQ-VDSE.tex`](Overleaf/MA-LB-PQ-VDSE.tex). Every figure in
that paper's Evaluation section is produced by the code here.

---

## The problem

Internet of Medical Things (IoMT) deployments generate encrypted health records
that must be searched across several administrative domains — hospital,
laboratory, emergency care — each governed by its own attribute authority.
Existing searchable-encryption schemes assume a centralised search server and a
static authorization model. That combination breaks down in three places:

- **Authorization and index state evolve at different scopes.** An unrelated
  authority advancing its revocation state should not invalidate index entries
  it does not govern.
- **Resource-only load balancing misprices encrypted search.** The least-loaded
  node may not hold the required shard, may hold stale authority state, or may
  face expensive proof generation.
- **A returned content identifier proves nothing on its own.** It cannot show
  that its index entry belongs to the current authenticated index and policy
  state.

## What OJCOMS is

**OJCOMS** is this project's name for the proposed scheme — MA-LB-PQ-VDSE. In
the code it is the `ma_lb_pq_vdse` package; in the figures it is labelled
*Proposed*. It is a cloud–fog framework that unifies:

| Component | What it does |
|---|---|
| **VAP** — Version-Bound Authorization Profile | binds a user's attributes to the current states of the authorities that issued them |
| **Policy-state-aware index** | binds each token to only the authorities governing its policy, so unrelated updates do not invalidate it |
| **AASS** — Adaptive Authorization-Aware Search Scheduler | assigns each shard to an eligible Fog Search Node by predicted index, verification, synchronization and queue cost |
| **DIAS** — Dependency-Aware Incremental Authorization Synchronization | propagates an authority update only along its dependency closure |
| **Verifiable retrieval** | Merkle proofs plus blockchain-anchored commitments bind each returned entry to its ciphertext and policy state |
| **ML-KEM-768** | post-quantum protection for attribute-key delivery |

Full detail: **[OJCOMS.md](OJCOMS.md)**.

## The schemes

Five schemes are implemented. Baselines are referred to by their citation
number in the manuscript — never by author name — and each has one document:

| Doc | Scheme | Paper | Code |
|---|---|---|---|
| [OJCOMS.md](OJCOMS.md) | Proposed (MA-LB-PQ-VDSE) | this repository's manuscript | `Schemes/ma_lb_pq_vdse/` |
| [30.md](30.md) | Scheme 30 | Ge *et al.*, Peony / Peony++ | `Schemes/yue_ge/` |
| [35.md](35.md) | Scheme 35 | Guo *et al.*, forward-private VDSSE | `Schemes/guo_vdsse/` |
| [41.md](41.md) | Scheme 41 | Thingom *et al.*, PQ-ABSE | `Schemes/thingom_pq_abse/` |
| [54.md](54.md) | Scheme 54 | Perera and Fugkeaw, LV-PQ-ABSE | `Schemes/perera_lv_pqabse/` |

> **Scheme 41 is measured differently from the other four.** Its search is
> `O(N)` pairings with no early termination, so the published `10⁴–10⁶` sweep
> cannot be executed within the compute budget. Its large-`N` points are
> **derived from a fitted linear model**, not measured, and are drawn with
> hollow markers. See [41.md](41.md) — this distinction is load-bearing and
> must never be flattened.

## The experiments

Nine experiment numbers exist in the code; the manuscript reports eight.

| # | Measures |
|---|---|
| 1 | Policy-state-aware token generation vs `q` |
| 2 | Search latency vs index size `N` |
| 3 | Cross-domain search latency vs domains `d` |
| 4 | Verification overhead vs returned results `r` |
| 5 | Dynamic index update vs modified pairs `k` |
| 6 | DIAS synchronization ablation |
| 7 | AASS search throughput vs concurrency |
| 8 | Load-balancing effectiveness vs concurrency |
| 9 | Verification granularity vs tampered records `t` |

Experiment 9 has no standalone figure — it is drawn as panel (b) of the
Experiment 4 figure, which is how the manuscript presents the pair.
Experiments 6, 7 and 8 are proposed-scheme ablations with no baseline.

Which scheme runs which experiment, and what each one measures, is the
participation matrix in [skill.md](skill.md) §3.

## Repository layout

```
Overleaf/              the manuscript (.tex) — the specification
Schemes/               one directory per scheme: src/ plus expN_*/ result folders
  ma_lb_pq_vdse/src/     aim/ authority/ chain/ fsn/ index/ psa/
                         scheduler/ shard/ sync/ user/ verify/ harness/
Common/                shared crypto primitives and timing
Dataset/               corpus preparation, loading, verification
Experiment Configuration/  global.yaml, crypto.yaml, dataset.yaml,
                           index.yaml, scheduler.yaml, workload/
Plots/                 generate_plots.py and the rendered figures
infra/                 provisioning, fleet control, sweep sharding, Fabric
References/            transcripts of the baseline papers
```

Results live beside the code that produced them: each run writes
`raw_runs.csv`, `results.csv` and `run_meta.json` into
`Schemes/<scheme>/exp<N>_*/`.

## Requirements

- Python 3.11
- `pip install -r requirements.txt`
- **Linux** for Scheme 41 — it needs `charm-crypto` for its published Type-I
  SS512 curve, which has no macOS or Windows wheel. The other four schemes run
  anywhere.
- `liboqs` or the `cryptography` package for ML-KEM-768.

## Running it

```bash
python3 -m Schemes.ma_lb_pq_vdse.src.main    --experiment all       --runs 10
python3 -m Schemes.yue_ge.src.main           --experiment 1,2,3,4,5 --runs 10
python3 -m Schemes.guo_vdsse.src.main        --experiment 1,2,3,4,5 --runs 10
python3 -m Schemes.thingom_pq_abse.src.main  --experiment 1,2,3     --runs 10
python3 -m Schemes.perera_lv_pqabse.src.main --experiment all       --runs 10

python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

The flags are **not uniform across schemes** — they were written at different
times. **[skill.md](skill.md)** is the operational guide: experiment framework,
configuration, execution, output validation and result collection. Figures are
**[plotgen.md](plotgen.md)**. Read both before running a campaign.

## Reportability

A run always completes and always writes results. Whether those results may be
**quoted in the paper** is a separate, machine-checked question recorded in
`run_meta.json` as `reportable` plus a `not_reportable_because` list. Only runs
against the frozen Synthea corpus, on the campaign host, at the configured
replication count, qualify. Never put a number in the manuscript without
reading that field — see [skill.md](skill.md).

## Relationship to the paper

The manuscript is the specification; the code is the source of truth for what
was actually measured. Where they disagree, the scheme document records the
disagreement rather than resolving it silently — see *Where it still departs
from the paper* in [OJCOMS.md](OJCOMS.md), and the equivalent sections in the
baseline documents.
