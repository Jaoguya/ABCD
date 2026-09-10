# System Configuration — how to run this, and what is actually true

**Rewritten from scratch 2026-09-08.** The previous version had drifted badly:
seventeen of its factual claims were false against the repo, including three
separate sections asserting an instance-type pin that was removed on 2026-08-30,
and a claim that no result in the repo was reportable when 103 were. It was
rewritten rather than patched, because a stale rule is worse than no rule — it
gets followed.

**Everything below is either re-derived from a machine-written file, checked
against code that runs, or carried over verbatim and marked as unverifiable
experience.** Nothing is copied from prose on trust.

## How to tell what is true here

**There are two different questions, and they rank sources differently.** Using
the wrong ranking is how the previous version of this file came to tell readers
to resolve construction disputes against the code.

### Question A — "is this claim about the repo's current state true?"

*Is BLAS pinned? How many domains does the corpus have? What does the config say?*

| Rank | Source | Why |
|---|---|---|
| 1 | `Dataset/dataset_manifest.json`, `run_meta.json`, `results.csv` | Machine-written, committed, never hand-edited |
| 2 | `Experiment Configuration/*.yaml` and the code | Executable — what actually runs |
| 3 | This file | Commentary. Useful, never evidence |

The papers are irrelevant here; they do not know what we ran.

### Question B — "is the implementation correct?"

*Does our token match the spec? Does Scheme [35]'s search match its paper? Is
Exp. 3's workload the published one?* **This is the question the publication
rests on**, because the entire repo exists to derive from published schemes.

| Rank | Source | Why |
|---|---|---|
| 1 | `References/Ref[NN]/Ref[NN].pdf` | The baselines' papers. If our Scheme [35] differs from its paper, **ours** is wrong. Immovable — we cannot edit someone else's paper |
| 2 | `Overleaf/MA-LB-PQ-VDSE.tex` | The spec for the proposed scheme. Authority, but **movable by decision**: code and spec must agree, and which one moves is a choice |
| 3 | Code and `*.yaml` | *Implementations.* A config asserting `u: 10` does not make 10 what the paper published. Here they are the thing under test, not the evidence |
| 4 | `results.csv` | **The output.** It cannot validate its own generator — if the code measures the wrong thing, the data measures it faithfully and looks perfect |

**Test for any claim: can you execute it, or read it out of committed data?** If
not, it is a lead, not a fact.

Two inversions worth knowing. On `keyword_document_pairs` the old prose said
36,263,865 and `index.yaml` said 36,172,487 — the manifest agrees with the
prose, so it is not "code beats docs", it is "the manifest beats everything".
And under Question B the code never wins on its own: it is a claim about the
paper, not proof of it.

**Note on the reference extractions.** `Ref[NN].md` is lossy OCR of the PDF —
`λ` renders as `?`, `10⁻⁴` as `10? 4`. Fine for locating a passage, not for
reading an equation. For anything load-bearing, open the PDF.

---

## 1. What this is

An evaluation of a proposed searchable-encryption scheme for IoMT electronic
health records against four published baselines, on shared hardware over a
frozen corpus.

The proposed scheme is `ma_lb_pq_vdse` — **M**ulti-**A**uthority,
**L**oad-**B**alanced, **P**ost-**Q**uantum, **V**erifiable **D**ynamic
**S**earchable **E**ncryption. Its claims: it verifies results per record, it
propagates authorization changes incrementally instead of rebuilding, and it
balances query load across fog nodes with an authorization-aware scheduler.

Refer to the baselines as **Scheme [30]** (`yue_ge`, Peony++), **[35]**
(`guo_vdsse`), **[41]** (`thingom_pq_abse`) and **[54]** (`perera_lv_pqabse`),
matching the manuscript's citation keys. Never by author name.

---

## 2. Environment — what is pinned, and what is not

Read this carefully; the previous version had it backwards.

| | Value | Enforced? |
|---|---|---|
| Corpus type | `synthea` | **Yes** — `reportability()` refuses anything else |
| Corpus SHA-256 | `e56ca2d1…f707d6a0`, pinned in `dataset.yaml` | **Yes** |
| Instance type | *(none)* | **No.** `environment.instance_type` was commented out of `global.yaml` on 2026-08-30 so `guo_vdsse` Exp. 2 could have the ~52 GB it needs. `verify_experiment_host()` reports `pin_configured=false` and passes vacuously; its `require=True` path has **zero call sites** |
| OS / Python | Ubuntu, Python 3.11 | **No** — recorded in `run_meta.json`, read by nothing |
| BLAS threads | 1, over the five names in `environment.thread_env_vars` | **Recorded, not blocking** — see below |

**The host is not part of the reportability check.** A run is stamped
`reportable: true` with no host guarantee, and the campaign deliberately rents
more than one instance size (`m6i.xlarge`, plus `r6i.8xlarge` / `r6i.32xlarge`
for the memory-hungry points). Cross-host latency comparisons are unsound until
the pin returns. The manuscript's §VI states a single `m6i.xlarge` — that
sentence and this table disagree, and the manuscript is the one that needs
changing.

**BLAS pinning is currently ineffective.** `provenance.py` calls
`verify_thread_pinning(require=True)`, but it *appends to the non-reportable
reasons* — it does not raise, and no `infra/` invocation passes
`--require-reportable`, so a run completes and writes output regardless. As of
2026-09-08: **114 banked `run_meta.json`, 0 with BLAS pinned, 103 stamped
`reportable: true`.** `infra/provision.sh` now derives the export list from
`global.yaml` rather than restating names — it previously exported four of the
five, so `VECLIB_MAXIMUM_THREADS` was never set and even a correctly provisioned
node failed the check. `/etc/profile.d/` is read by login shells only, and
`fleet.sh` drives nodes over non-login `ssh host '<cmd>'`.

**vCPU count is load-bearing for one baseline.** `thingom_pq_abse` runs its
search across **2** processes, tuned to `m6i.xlarge`'s 4 vCPU being 2 physical
cores plus hyperthreading — 4 processes measured slower. Changing instance type
means re-measuring that, and disclosing it.

---

## 3. Setting up

Python **3.11**, in a virtualenv. `infra/provision.sh` uses `~/.venv-malbpq`;
match it.

```bash
python3.11 -m venv ~/.venv-malbpq
source ~/.venv-malbpq/bin/activate
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
pip install pytest ruff        # NOT in requirements.txt
```

Three traps:

- **`pytest` is not in `requirements.txt`** and is not installed on the AWS
  host. Install it into the venv separately, never into a system Python.
- **ML-KEM is not in `cryptography` despite what `requirements.txt` implies.**
  `Common/crypto/kem.py` probes `cryptography` then `liboqs` then `kyber-py`.
  The AWS host runs **liboqs 0.16.0**; match it. `liboqs-python` builds its
  native library on first import and fails with `cmake: command not found`
  unless cmake is present — install the **cmake PyPI wheel into the venv**, not
  Homebrew, to keep the toolchain self-contained. Do **not** fall back to
  `kyber-py`: `crypto.yaml` marks it development-only and it is a different
  implementation from the server's, so timings would not correspond.
- **`charm-crypto` is Linux-only**, so Ref[41] cannot be developed on macOS and
  there is no macOS wheel for the `petrelic` fallback.

### Tests

```bash
python -m pytest -q      # inside the venv, from the repo root
```

**There is no agreed pass count.** Figures of 609, ~651 and 895 have all been
recorded at different times by different documents. Run it before changing
anything and use *that* as your floor; do not trust a number written down.
`pytest.ini` sets `--import-mode=importlib` — do not remove it, as all schemes
ship a package literally named `src` and the default mode makes them collide.

---

## 4. The dataset

**Synthea** — synthetic but clinically realistic patient records. Chosen over
MIMIC-IV: no size ceiling, no credentialing, citable, reproducible, and it
yields real keyword co-occurrence and real institutional domain boundaries.

Frozen corpus **v4**, re-derived here from `Dataset/dataset_manifest.json`
(rank 1) rather than restated:

| | |
|---|---|
| Records | 1,143,792 (unit: one Synthea *encounter*) |
| Keyword universe | 2,023 distinct |
| Keyword/document pairs | 36,263,865 |
| Keywords per record, min / median / mean | 5 / 29 / 31.70 |
| Zipf exponent | 2.741 |
| Domains | **10**, at 114,379–114,380 each (0.0009% imbalance) |
| SHA-256 | `e56ca2d1…f707d6a0` |
| Generated | 2026-08-28, Synthea `7e08387`, `balanced_organizations` |

**Note the domain count.** The corpus has **ten** domains. `global.yaml`'s
`defaults.domains` is **4**, and §VI says records are "uniformly distributed
across four administrative healthcare domains". Exp. 3 sweeps d = 2…10 and needs
all ten. Confirm what a four-domain default actually selects from a ten-domain
corpus before quoting §VI's sentence.

`Dataset/derived/corpus.jsonl` is git-ignored (686 MB) and exists **only** on
AMI `ami-0feb3b14b4ea27844` (§12). Regenerating it is not reproducible — Synthea
generates patients across threads, so a fixed seed pins the random stream but
not which patient consumes which draw. Re-deriving from the *fixed CSVs* on that
AMI is deterministic; regenerating from Synthea is not. **If the corpus changes,
every scheme must be re-run.**

`Dataset/dataset_manifest.json` is committed provenance. If you see it modified
in `git status` and did not mean it:
`git checkout -- Dataset/dataset_manifest.json`.

A second corpus type exists — `synthetic`, from `synthetic_generator.py`, a
fitted Zipf law with no clinical structure, **development only** and refused by
the reportability gate. Its shape differs sharply from v4 (~13,000 keywords over
~11 pairs/record versus 2,023 over 31.70), so anything scaling with keyword
count rather than pair count will be badly mis-estimated from it. That produced
a 6.5× memory over-estimate once already.

---

## 5. Defaults, and the eight experiments

Defaults from `global.yaml`, held constant unless the experiment sweeps them:
`keywords_per_query: 5`, `domains: 4`, `fog_search_nodes: 4`,
`index_size: 100,000`, `returned_results: 100`. Methodology: **10** measured runs
after 5 discarded warm-ups, `perf_counter_ns`, mean ± 95% CI from the
t-distribution, outliers kept.

Sweeps and participants, read from `global.yaml` rather than restated in prose:

| # | Measures | Variable | Sweep | Schemes |
|---|---|---|---|---|
| 1 | Token generation | `q` | 1, 5, 10, 15, 20 (with `P_U` in 1,2,4,8) | all 5 |
| 2 | Search latency | `N` | 10^4 … 10^6 | all 5 |
| 3 | Cross-domain scalability | `d` | 2, 4, 6, 8, 10 | all 5 |
| 4 | Verification overhead | `r` | 10, 50, 100, 500, 1000 | ours, [35], [30], [54] |
| 5 | Dynamic keyword update | `k` | 10^2 … 10^5 | ours, [35], [30] |
| 6 | Authorization sync | `delta` | 10^2 … 10^5 | ours only |
| 7 | Search throughput | concurrency | 100 … **10,000** | ours — ablation |
| 8 | Load balancing | concurrency | 100 … **10,000** | ours — ablation |

Baselines legitimately sweep **supersets** of these; `generate_plots.py`
restricts the x-axis. Extra points staying in `results.csv` is by design.

**Measurement boundaries** — these decide what the numbers mean:

- **Exp. 1** — online token generation only. ML-KEM encapsulation is per session,
  not per query, so it is excluded and reported separately.
- **Exp. 2** — the online search path. Index construction is offline setup.
- **Exp. 3** — baselines have no native cross-domain search, so they run `d`
  independent trapdoors aggregated client-side. **Per-domain index size is
  fixed**, at `global.yaml`'s `exp3 -> held_constant.per_domain_index_size`
  (10,000), so total data grows with `d`. That is §VI's stated convention;
  until 2026-09-09 the four baselines fixed *total* at 100,000 and sharded by
  `d` (per-domain shrinking 50,000 -> 10,000, which is why [35]'s latency
  *fell* as `d` grew) while the proposed scheme fixed per-domain at 4 records —
  a 2,500x data disparity at `d=10` on one axis.
- **Exp. 4** — client-side verification only; fetch and decrypt excluded.
- **Exp. 5** — incremental update only. A global rebuild is a bug, not a slow update.
- **Exp. 6** — incremental propagation until every affected node reports the new
  version. Chain anchoring excluded and reported separately. Three-way ablation:
  directory slugs are `ias` / `broadcast` / `full_rebuild`, labelled
  *DIAS (proposed)* / *Incremental-All* / *Full-State Synchronization*.
- **Exp. 7–8** — the *same runs* produce both. Throughput alone hides congestion.

**Index construction is untimed but is most of the wall-clock.** A runtime
estimate counting only measured operations will be wrong by an order of magnitude.

**Two constructions share these numbers.** `option_d` (`harness/experiments.py`)
and `psa` (`harness/psa_experiments.py`) time *different functions at the same
experiment number* — the first uses `T = H(w)`, the second the manuscript's
`T = H(w || PID || PV || Dom)`. Every reported number must say which produced it.
All `psa_*` runs are built on in-process synthetic data and are
`reportable: false` by construction.

---

## 6. What makes a number reportable

Every run writes `run_meta.json` with `reportable: true|false` and, when false,
`not_reportable_because`. A failing run still executes and still writes results —
that is deliberate. **Always read the field before quoting a number.**

Conditions actually checked, verified against `provenance.py:reportability()`:

- `corpus_type == "synthea"` and the SHA-256 matches `dataset.yaml`'s pin
- a faithful pairing backend (Type-III for ours), not a development stand-in
- `measurement.repetitions == 10`
- the ledger is real Fabric — **Exp. 4 only**; the adapter is not written, so
  Exp. 4 cannot pass this today
- for ours: scheduler weights `fixed`, tokens scheme-keyed, fog nodes in
  independent processes
- BLAS pinning — appended as a reason, **not blocking** (§2)

**Not checked:** the host, the OS, the Python version.

---

## 7. Running it

```bash
bash infra/provision.sh                       # provisions, gates on primitive tests

python3 Dataset/prepare_dataset.py --input <synthea>/output_full/csv \
    --output Dataset/derived --synthea-version 7e08387

docker compose -f infra/fabric/docker-compose.yaml up -d    # ours only
ipfs daemon &

python3 -u -m Schemes.ma_lb_pq_vdse.src.main    --experiment all       --runs 10
python3 -u -m Schemes.guo_vdsse.src.main        --experiment 1,2,3,4,5 --runs 10
python3 -u -m Schemes.thingom_pq_abse.src.main  --experiment 1,2,3     --runs 10
python3 -u -m Schemes.perera_lv_pqabse.src.main --experiment all       --runs 10
python3 -u -m Schemes.yue_ge.src.main           --experiment 1,2,3,4,5 --runs 10

python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

**Flags differ per scheme** — they were written at different times. Only
`ma_lb_pq_vdse` reads `global.yaml` for `--runs`/`--warmup`; the other four carry
argparse defaults that happen to match it. Changing `global.yaml` alone does
**not** change what a baseline runs.

**Never launch Ref[41] Exp. 2 above N=10^4.** 50k–1M are linear scalings from
that anchor (`n_runs=1`, blank `ci95`); one real run at 10^6 costs ~11.3 h.

### Parallelism

Split by sweep point with `--points`; each shard writes its own
`…__points-2_3_4_5` directory so instances cannot overwrite each other, then
reassemble with `infra/merge_points.py`. Shards are not results — the merge step
is required.

```bash
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 2-5
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 6-10
python3 infra/merge_points.py Schemes/thingom_pq_abse/exp3_crossdomain_scalability
```

---

## 8. Where things live

```
CLAUDE.md                     working rules, loaded every turn — kept short
SystemConfiguration.md        this file — operator's guide
Common/crypto/                primitives every scheme shares, so all pay the same cost
Dataset/                      corpus generation + the committed manifest (derived/ git-ignored)
Experiment Configuration/     global.yaml, crypto.yaml, dataset.yaml, index.yaml,
                              scheduler.yaml, workload/, planning/runtime_estimates.csv
Schemes/<scheme>/src/         implementation + one results folder per experiment
infra/                        provision.sh, fleet.sh, fabric/, sweep.py, merge_points.py
Plots/                        generate_plots.py -> Plots/output/
References/                   the papers, and extracted text per reference
Overleaf/                     the manuscript
.claude/                      skills and agent definitions
```

**`Common/` has a scope rule.** Primitives a paper *cites* (SHA-256, AES-GCM,
Merkle, Bloom, ML-KEM) live there so every scheme measures the same cost.
Anything a paper *contributes* stays in its own `src/`. If two schemes seem to
need the same construction, one is probably being implemented unfaithfully.

---

## 9. Before you change something

- **Adding a scheme?** Hold total indexed data constant across the swept
  variable — this has been violated and caught twice, and both times the top
  point indexed several times the data of the bottom one, so the "scalability
  curve" was mostly a growing corpus. Give it a `run_meta.json` with the same
  reportability conditions as everyone else, and record every unpublished
  parameter you had to choose (they go in `crypto.yaml`, with a date and a reason).
- **Optimising a baseline?** Fine and sometimes necessary, but disclose it, and
  if the proposed scheme gets an optimisation the baselines need it too. An
  optimisation on the *measured* path needs a manuscript note.
- **Found a defect?** Put it in the commit message with its evidence — file,
  line, measured numbers, why it matters. Say explicitly if it changes a number
  already in a `results.csv`, a figure, or the manuscript.
- **Ref[41] claims post-quantum security its own maths does not support** — it
  rests on DBDH, which Shor breaks, and the same paper says pairings are not
  post-quantum. It is implemented exactly as published and the contradiction is
  reported as a finding. Do not "fix" it.

---

## 10. Known gaps

Verified 2026-09-08 against the repo, not carried over from the previous version:

- **The Fabric ledger adapter is not written.** `infra/fabric/` brings the
  network up; nothing reads it, so Exp. 4 understates chain cost and cannot pass
  its own reportability condition. Exp. 6 does **not** depend on it — its timed
  path never anchors (`sync/dias.py::synchronize` takes `ledger` as optional and
  the runner passes none).
- **BLAS was never pinned in any banked run** — 114 files, 0 pinned, 103 stamped
  reportable (§2).
- **`secondary_metrics` is absent from all 114 banked `run_meta.json`**, so the
  panel-label check can verify no BANKED figure. *(2026-09-10: current code
  writes it, and `results.csv` now names its columns after the metric, so new
  runs are checkable by name. The gap is the banked data, closed by a re-run.)*
- **Four of five schemes never read `global.yaml`.** Their `--runs`, `q` and
  sweep lists are Python literals that happen to match, and `yue_ge` searches a
  single keyword where §VI states a five-keyword conjunctive query.
- **The λ weight vector was never swept in its current form.** The 2026-08-28
  hold-out sweep chose five weights over a cost function including `C^auth`;
  when that term was removed the surviving four were renormalised, not re-swept.
- **Parameter provenance for the shared primitives is unverifiable.** 64
  citations across 13 files point at `Ref[35].txt`, `Ref[41].txt` and
  `Ref[52].txt`. **No `.txt` extraction exists** — `References/Ref[NN]/` holds
  `.md` and `.pdf` — and the surviving `.md` files are far shorter than the
  cited lines (`Ref[35].md` is 830 lines against a cited `:1807`;
  `Ref[41].md` is 508 against `:919`), so the extension cannot simply be
  swapped. Worse, **`Ref[52]` is not in the repo at all** — it is the dropped
  Zhuang baseline — yet `Common/crypto/bloom.py` and `Common/crypto/lattice.py`
  cite it nine times as the source of their published parameters. `crypto.yaml`
  promises that "if a reviewer asks where n = 768 came from, the answer is in
  that file"; for these three references it is not.
- **§V's Exp. 4 "within measurement error" sentence rests on two datasets that
  disagree.** The Fabric run recorded on 2026-09-07 measured PSA against
  Option D at r = 10 / 100 / 1000 as 1.017× / 0.977× / 0.996× — within 2% at
  every point, which is what the sentence claims. A separate five-point
  comparison (r = 10 / 50 / 100 / 500 / 1000) gave +1.67 / −3.09 / −2.30 /
  −2.28 / −0.40%, exceeding 2% at three points with disjoint 95% CIs. Both
  cannot be the basis of one sentence. Re-derive from `raw_runs.csv` before
  defending it.
- **Table I contains verified errors, and ten rows cannot be checked here.**
  Audited against the PDFs (2026-09-10): the `ref54` row is wrong in two of
  seven columns — Blockchain Audit and Multi-Keyword Search are both `x` where
  that paper's own contribution claim is *"the first lattice-based ABSE
  framework that supports multikeyword, Boolean, fuzzy, and numeric range
  queries"* and its Merkle proofs are *"anchored on a blockchain"*. Both errors
  understate a baseline in the proposed scheme's own comparison table. The
  `ref35` and `ref41` rows are correct — including `ref41`'s Lattice/PQ `x`,
  which is right on the maths (its security rests on **DBDH**, which Shor
  breaks) despite the paper being titled "Post-Quantum". But the prose
  CONTRADICTS that at two places, listing `ref41` among lattice/PQ approaches.
  **[30] (Peony++) has no row at all** though it is a baseline in Exps. 1-5,
  while `ref52` has one and is not in the repo. The other ten rows have no PDF
  in `References/` and are unverifiable from here — two errors were found in
  the one row audited closely.

- **SVI's "q=5 conjunctive query used throughout this section" is
  unachievable.** Read from the PDFs: [30] is single-keyword by construction
  (*"query q = (w, alpha(u)) … single keyword queries"*, and it names
  conjunctive search as an open problem it has not solved), and [41] likewise
  (*"DU inputs … the keyword w_w they wish to search"*, one keyword per file
  index). [35] and [54] are genuinely conjunctive/multikeyword. **The harnesses
  are faithful in every case; the sentence is what must change** — SVI should
  state the query shape per scheme.

- **SVI Exp. 2's selectivity claim is unfalsifiable from banked data.** No
  baseline records a match count: `n_eff` means matched entries for the
  proposed scheme, `entries_traversed + forward_evals` for [35], tree nodes for
  [30], candidates examined for [54], and [41] records none. Dividing a
  traversal counter by N is not a selectivity. Add a `matched_records`
  secondary to all five, or drop the "selectivity is kept constant" sentence.

- **The PSA track omits the AIM authorization check that SVI puts inside the
  measured path.** `PsaExp2` and `PsaExp3` run token derivation plus
  `index.lookup`; Option D's Exp. 2/3 also run `verify_search_request`, and
  Exp. 7-8 run it in both tracks. SVI Exp. 3: *"The AIM first validates the
  current VAP and derives policy-state-aware tokens…"*. Wiring it in is Phase
  III work (`PsaDeployment` has no AIM, VAP or resolver) and moves `psa_exp2`,
  which is currently reportable.

- **SV Exp. 6 needs two corrections.** The DIAS-vs-Incremental-All advantage is
  in **delivered bytes, not latency** — measured 3.52 / 14.06 / 141.05 KB
  (deterministic) against a ~2% latency gap that is noise in both directions.
  And the narrowing toward a full affected-ratio is **not total**: evolution
  work converges exactly (10x -> 1x) while delivery does not (40x -> 4x), so
  the incremental advantage vanishes at 100% and the selective one survives.

- **Exp. 5's `entries_rewritten` is 0 in banked data and 6 per record today.**
  Three causes eliminated by direct execution: stale code (the banked commit
  returns 6 too), topology (4- and 10-domain builds both rewrite), and message
  construction. Isolated to the corpus path, which needs the AWS host —
  `Dataset/derived/corpus.jsonl` is gitignored and exists only on the AMI.

- **97 citations point at five deleted documents**: `SCHEME.md` (39),
  `README.md` (21), `MANUSCRIPT_DIVERGENCE.md` (15), `PHASE_IV_PLAN.md` (13),
  `PHASE_III_PLAN.md` (9). Section 8's "two prose files" rule exists because of
  exactly this, and cites 338 from the `README.md` deletion as history — it is
  not history. Every one of these sends a reader to a file that does not exist.

- **The cross-node-forward metric is 0 for AASS by construction.**
  `scheduler/aass.py` increments `forwards` only in the non-AASS branch, and
  the three oblivious arms are handed a pool "deliberately not filtered by
  `S_j`". So Fig. 8(c) measures the arm definitions rather than scheduler
  quality. Either give all four arms the same eligibility filter and report the
  honest difference, or drop the metric and SV's sentence reading it as
  evidence. **Open decision, parked by the user 2026-09-10.**

- **The construction question is DECIDED (2026-09-10): PSA.** The code
  implements `T = H(w)`; the manuscript specifies
  `T = H(w || PID || PV || Dom)`. These are two different schemes, and Fig. 1
  was drawn from the PSA track while Figs. 2-8 came from Option D. Resolved in
  the manuscript's favour: **PSA is canonical, `option_d` stops feeding any
  figure, and every banked Option-D number behind Figs. 2-8 is superseded.**
  `run_meta.json` now records `construction`, and `generate_plots.py` refuses a
  figure that mixes two. Remaining work is tracked outside this file.

---

## 11. Operational traps

Rescued 2026-09-07 from `infra/SESSION_HANDOFF.md` and `infra/CAMPAIGN_RESUME.md`
before both were deleted as stale. Everything else in those two files was a
snapshot of a campaign that has since been harvested, committed and superseded;
these six are not snapshots. Each one cost real time or real data once.

- **Never blanket-unpack a harvest tarball.** Each node's tarball carries stale
  copies of every *other* scheme's results. Unpacking several in alphabetical
  order silently overwrites fresh results with stale ones — and the overwrite
  leaves no trace, because the stale files are valid. Extract scoped, one scheme
  at a time, from the one node that produced it.
- **`run_meta.json` existing does NOT mean the point finished.** Restoring tracked
  files before a run recreates old `run_meta.json` files. Distinguish by
  `git_commit`, never by presence or mtime.
- **`python -u`, or the log is useless.** Without it a healthy run block-buffers
  stdout to a file and is indistinguishable from a hang. A 900 s "timeout" was
  once diagnosed off an empty log from a run that was fine.
- **Long runs go in `tmux` on the node.** Three separate incidents had the WORK
  survive an SSH drop while the RECORD of it died.
- **`pkill -f smoke.sh` does not kill `timeout`-wrapped children.** Orphans kept
  writing into a deleted output directory.
- **The egress IP rotates.** Every host times out at once and the fleet looks
  dead; it is the security group. Re-authorise and retry before diagnosing
  anything else.

One more, kept because it is load-bearing for reading git history: **a `-dirty`
suffix on a pre-`dfa7e69` `run_meta.json` is not evidence that code was
modified.** `git_commit()` ran `git status --porcelain` over the whole repo
including tracked result directories, so a run's own output tripped its own
marker. At the same commit `55aa3c8`, `exp7` and its five shards are clean while
`exp8`, its five shards, and `exp6` are dirty — same commit, same sweep, opposite
verdicts. That is write-order contamination. It equally cannot *rule out* a
modified tree; it simply carries no information either way.

---

## 12. AWS estate — hosts, AMIs, keys, recovery

Rescued from `README.md` on 2026-09-07 before that file was deleted. Every
concrete identifier below existed **only** there; none of it was in this file.
Verify against the live console before acting on any of it — instance state
moves, and the IDs are a record, not a guarantee.

### Instance type

`m6i.xlarge` (4 vCPU, 16 GiB, Xeon 8375C), Ubuntu 24.04 LTS, 30 GiB gp3.

Chosen over the originally specified `c6i.xlarge`: same CPU, 8 -> 16 GiB.
Ref[52] allocates a 381 MB lattice trapdoor per attribute, and running near
memory saturation contaminates latency with GC and page-cache effects.

* **Never `t3`/`t4g`** — CPU credits make latency non-reproducible.
* **Never Spot** — an interruption kills a trace.
* When launching from the console, plain Ubuntu no longer appears in Quick
  Start's abbreviated list (only the SQL Server bundle does). Use "Browse more
  AMIs". A previous host was accidentally launched as "Ubuntu Server 22.04 LTS
  **with SQL Server** 2022 Standard" and ran an unrelated `sqlservr` process.
* Launch **one** instance first, never all nine — `provision.sh` is a
  build-once-then-snapshot workflow, not nine independent provisions.

### AMIs

| AMI | Name | Status |
|-----|------|--------|
| `ami-0b2da6ed17be6c7a1` | `abcd-benchmark-2026-08-28b` | **Current — launch the fleet from this one** |
| `ami-0feb3b14b4ea27844` | `abcd-benchmark-2026-08-28` | Superseded, but see below — do not delete |

`ami-0b2da6ed17be6c7a1` carries corpus v4 (`e56ca2d1`, 10 domains), the Type-III
pairing backend, multi-process FSNs and the swept AASS weights. The older AMI
holds the superseded 4-domain corpus and fails the freeze check at startup.

**`ami-0feb3b14b4ea27844` is the single point of recovery for two things that
exist nowhere else:**

1. The frozen corpus `Dataset/derived/corpus.jsonl` (686 MB, git-ignored).
2. The from-source crypto build (PBC 0.5.14 + charm-crypto + liboqs).

It also carries ~11 GB of raw Synthea CSVs at `~/synthea/output_full/csv`. Keep
them: the corpus non-determinism came from Synthea *generating* patients across
threads, not from `prepare_dataset.py` extracting from fixed CSVs — so those
CSVs are what make the current corpus re-derivable.

### Keys and access

* Current key: `~/.ssh/ojcoms.pem` (host name `OJCOMS`).
* Retired key: `~/.ssh/ABCDE_key.pem` — old host `3.236.231.174`, terminated.
* **No Elastic IP.** The public IP changes on every stop/start and has already
  moved four times (`44.222.205.213` -> `98.91.21.219` -> `34.228.7.222` ->
  `54.172.21.174`). Never hardcode it; read the current one from the console.
* Each restart wipes `/tmp`, so long-running output belongs elsewhere.

### Instance IDs seen in the 2026-09-03 campaign

| Instance | Scheme | Last known outcome |
|----------|--------|--------------------|
| `i-0d9b2c6e1776c6f84` | proposed | complete, harvested, stopped |
| `i-0c376b61dae6fed24` | perera | complete, harvested, stopped |
| `i-0e5ae20e113bae9f7` | guo | Exp. 1-5 finished; **harvest was pending** |
| `i-025c809974bbf7511` | yue_ge | complete, harvested, stopped |
| `i-0b3030b5bd768536e` | thingom | complete, harvested, stopped |
| `i-007e491c10f5e7d62` | (experiment host `OJCOMS`) | build host |

### Recovering a node whose sshd will not answer

Observed on `i-0e5ae20e113bae9f7`: the box came back `running` with `ok/ok`
status checks and sshd never answered, on the same security group as nodes that
connect fine — so it was the host, not access.

```bash
aws ec2 stop-instances  --instance-ids <id>   # clean stop
aws ec2 start-instances --instance-ids <id>   # then retry ssh
# if sshd still refuses, take the console output before anything drastic:
aws ec2 get-console-output --instance-id <id> --output text | tail -50
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-<scheme>-*.bundle" /tmp/
```

**Stop, never terminate, a node holding unharvested results.** These volumes
carry `DeleteOnTermination: true` — a stop preserves every result, a terminate
destroys them.

### Getting results off a node

The nodes **cannot push**. The remote is `git@github.com:Jaoguya/ABCD` over SSH
and no node holds a private key; putting a personal key on a cloud instance was
deliberately not done. For real auto-push, add a per-node GitHub deploy key with
write access. Until then:

```bash
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-<scheme>-*.bundle" /tmp/
git fetch /tmp/results-<scheme>-*.bundle HEAD:refs/node/<scheme>
git checkout refs/node/<scheme> -- Schemes/<that-scheme-only>/
```

**That last line matters.** Each watchdog runs `git add -A Schemes/`, which is
too broad: perera's node commit also carried 39 stale `ma_lb_pq_vdse` files that
were dirty in its working tree, and merging that bundle would have overwritten
fresh proposed-scheme results with month-old data. Always check
`git diff --name-only <ref>~1 <ref>` and extract per-scheme paths rather than
merging. Narrowing that `git add` to the scheme the node actually ran is a
one-line fix worth making.

### Watchdog design

Each watchdog waits for the **driver** to exit, not a single python process. The
proposed scheme's run is two invocations (Exp. 1-6, then 7-8), so watching "is
the python alive" fires in the gap between them and stops the box with the
ablation unrun. On exit it commits results locally, writes
`~/results-<scheme>-<ts>.bundle`, attempts a push, then stops.

---

## 13. Fabric + IPFS on the experiment host

Rescued from `infra/fabric/README.md` on 2026-09-07 before that file was
deleted. Brings up the ledger and off-chain store §5 specifies (Hyperledger
Fabric v2.5, IPFS). Before 2026-08-28 this directory did not exist, so the
documented `docker compose` instruction was broken and every run silently fell
back to `chain/ledger.py`'s `InProcessLedger`.

```bash
docker compose -f infra/fabric/docker-compose.yaml up -d
docker compose -f infra/fabric/docker-compose.yaml ps
docker compose -f infra/fabric/docker-compose.yaml down -v   # -v also drops ledger state
```

### What this is, and what it is not

**Single organisation, solo orderer.** Not a production topology. What Exp. 4
and Exp. 6 measure is the cost of *anchoring a commitment and reading it back*
— ordering latency, block cut, endorsement round-trip — and this reproduces
those on one `m6i.xlarge` reproducibly.

**A solo orderer has no consensus round, so anchoring latency here is a LOWER
BOUND on a Raft deployment.** State that in §V rather than describing this as a
production network. It is the conservative direction for the proposed scheme —
it does not flatter our anchoring cost relative to a baseline that anchors less
often — but it is still a difference from the stated stack.

**TLS is disabled**, because a handshake would be measured as if it were
anchoring cost on a single-host private-VPC network. Never carry that setting
anywhere the traffic leaves the host.

**LevelDB, not CouchDB**: the scheme stores opaque commitments and issues no
rich queries, so CouchDB would add indexing cost the construction does not
incur.

### Before this clears the reportability blocker

`provenance.reportability()` blocks on `ledger_faithful` because an in-process
hash chain understates Exp. 4's chain-consistency cost. Bringing these
containers up is **necessary but not sufficient** — a `FabricLedger` adapter
implementing `chain/ledger.py`'s `Ledger` interface against this network still
has to exist and be passed `ledger_faithful=True`. That adapter is **not yet
written**; see `chain/ledger.py`'s note that a Fabric adapter "reading an entry
it did not write will need a canonical decoder".

So this directory makes the compose command executable and unblocks that work.
It does not by itself make Exp. 4 reportable, and no run should claim it does.

### Channel setup

`ORDERER_CHANNELPARTICIPATION_ENABLED=true` means the channel is created via the
admin API (osnadmin) rather than a genesis block baked into the image. The
adapter above should create the channel on first use so the network is
reproducible from the compose file alone, with no manual crypto material to
check in — checked-in MSP keys would be both a security problem and an
unreviewable binary blob.
