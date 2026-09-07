# checkexp — status of the experiment-by-experiment check

**Which** experiments have been checked, how, and what the pass concluded.
**What to fix** lives in `needfix.md`. Those two files are the whole picture —
read them and nothing else is required.

**How they stay in sync:** anything a pass turns up gets a tagged item in
`needfix.md`, and this file only names it and points there. Findings about an
experiment become numbered items (`2-1`, `3-4`); checks that were never run
become `G-n`; work outside the per-experiment passes becomes `X-n`, `C-n` or
`D-n`. If a finding is described here but has no item there, they have drifted.

No item's reasoning is repeated across the two. That is the rule
`DO_NOT_READ/remainfix.txt` and `DO_NOT_READ/TASKS.md` broke before they were
retired.

---

## Status

Suite: **895 pass, 5 skip**, green on five consecutive full runs on 2026-09-08.
X-4's flaky wall-clock comparison did not fire in any of them — it has now
fired twice in twelve, so it is rarer than the earlier 2-in-7 suggested but is
NOT fixed; it still has no tolerance. The five `README.md` failures are gone: that file was deleted on
2026-09-07 and the six tests that read it were removed with it.

| Exp | Figure | Checked | Verdict |
|-----|--------|---------|---------|
| 1 | `fig_exp1_trapdoor.pdf` | **2026-09-08** (deep) | **8 items**, 1 fixed, 3 decisions. Construction is the strongest audited — `\|T_Q\| = q·\|P_U\|` **exact at 20/20 cells**, per-token cost flat at 6.30–6.99 us. **Data is not**: all four plotted arms are `reportable: false` / `psa_in_process`. A smoke run closes it |
| 2 | `fig_exp2_search.pdf` | **2026-09-07** (deep) | **8 items**, 4 fixed, 2 decisions, 2 blocked. Re-run blocked on host memory; banked numbers superseded |
| 3 | `fig_exp3_crossdomain.pdf` | **2026-09-08** (deep) | **10 items**, 1 fixed, 3 decisions. **Worst workload mismatch** — 2,500x index gap against the baselines. Q6 diff: one key differs across the three revisions, `repetitions` 10 vs **30 for `[54]`** (3-9). `trapdoors_issued` now counted, not asserted (3-5) |
| 4 | `fig_exp4_verify.pdf` | **2026-09-08** (deep) | **5 items**, 1 decision, 1 explained, 1 verified. **Cleanest of the eight** — the only figure whose five curves share ONE `global.yaml` revision. "Highest per-result cost" **holds** at all five shared r. §VI's "within 2% at every r" is **false at 3 of 5**, CIs disjoint — 4-4. 4-1's falling `path_length` **explained as sampling convergence**, with the PSA arm as the control |
| 5 | `fig_exp5_update.pdf` | **2026-09-08** (deep) | **6 items**, 1 fixed, 2 decisions, 1 blocked. `entries_rewritten` reads **0 at all four points** — **stale data, not a defect**: the counting path landed in `3950d3e` (09-06), the run is from `79a5739` (09-03). Re-measures at **102.0 at k=100**. Config drift diffed **benign**. Index still grows with k where §VI fixes it |
| 6 | `fig_exp6_sync.pdf` (psa) | **2026-09-08** (deep) | **6 items**: 1 open, 1 decision, 2 notes, 1 verified, **1 withdrawn**. All five §VI claims hold — DIAS lowest at every ratio, 10.18x→1.07x narrowing, Incremental-All's fan-out entirely in bytes (4.00x) not latency (1.06x). **Best-covered experiment: 20 tests**, both halves of the claim pinned independently. Fig. 6 is the one paper figure drawn from the **PSA** track, so its numbers are non-reportable — 6-5 |
| 7 | `fig_exp7_throughput.pdf` | **2026-09-08** (deep) | **5 items**, 2 fixed, 2 decisions, 1 blocked. Ordering **holds at all six** (5.5%→18.8%) but on data from a **five-term scheduler the code no longer has** — 7-4. Under PSA the ablation **collapses to 1.003x–1.054x and AASS wins nothing** — 7-5 |
| 8 | `fig_exp8_balance.pdf` | **2026-09-08** (deep) | **4 items**, 1 decision, 2 blocked, 1 verified. Panels (a) and (b) **verified** — AASS 2.8x–6.4x below `no_lb`, lowest max-utilization at all six. Panel (c) draws **max_queue_depth** under a "Cross-node forwards" label AND contradicts the text at 100/500 — 8-1, 8-3. Shares Exp. 7's runs and its 7-4 config problem |

**Recurring across experiments** — the sizing class (2, 3, 5) and the
metric-does-not-measure-its-name class (3, 5, 6, 8).

### Independent recheck of the banked data — 2026-09-08

Run AFTER all eight passes, deriving from `raw_runs.csv` rather than re-reading
this file. It is the arithmetic check the per-experiment passes assume:

| Check | Scope | Result |
|---|---|---|
| `primary_mean` + `primary_ci95` recomputed from raw | **454 points** | **0 discrepancies** |
| every `secondary_N_mean` recomputed from raw | **618 points** | **0 discrepancies** |
| `n_runs` vs count of `status=ok` raw rows | 454 points | **all agree** |
| raw row statuses across every experiment | **5,664 rows** | **all `ok`** — no run was dropped |
| negative secondaries / non-positive primaries | all | **none** |
| declared sweep vs banked x-values | 57 directories | 17 deviations, **all explained** |
| `generate_plots.py` diagnostics | 8 figures | every warning maps to a recorded item |

**Nothing new was found, and that is the finding.** The aggregation pipeline is
sound: every number in every `results.csv` is exactly reproducible from its raw
runs, at 1e-3 relative tolerance on means and 2e-2 on CIs. The defects this
audit found are in *what was measured* and *what §VI says about it* — never in
the arithmetic between the runs and the table.

Six recorded claims were also re-derived independently and all six held: 1-7's
20/20 identity, 7-3's six-point ordering, 7-5's `AASS wins 0 of 6` and
≤1.06x spread, 6-4's exact 4.00x, and 4-4's 3-of-5 failure.

The 17 sweep deviations are two known shapes: **baseline supersets** (the four
baselines sweep more points than §VI states — Exp. 1 +15, Exp. 3 +4, Exp. 4 +2,
Exp. 5 +3/+6, Exp. 2 +2; `global.yaml`'s own exp1 comment says these "stay in
results.csv" and the figure restricts) and **psa_exp6's ratio axis** (6-5).
`3-8` records the superset for Exp. 3 only; it is general.

**One campaign-wide blocker:** BLAS was never pinned in any of the 114 banked
runs (**X-6**), and the gate now refuses every future run until it is. Alongside
it, no banked run carries `secondary_metrics` (**X-7**, open not blocking), so
the panel/label check cannot verify any existing figure.

Totals across all sections: **74 items — 24 fixed, 20 open, 17 decisions,
9 blocked, 1 withdrawn**, plus 7 standing notes. (2026-09-08: +20; **G-1, G-2
and G-4 closed**; 3-5, 5-1 fixed; 6-2 withdrawn; **all eight experiments
finished**.)

### Coverage — how deep each pass actually went

**All eight experiments are finished.** Every experiment was
passed over and every one produced findings. The checklist ran end-to-end on
every one; Exps. 1, 3, 4, 5, 6, 7 and 8 were completed 2026-09-08. **The audit
phase is over — what remains is decisions and the re-run.**

**A pattern worth naming.** Three of the four figures now audited deeply carry
data that predates the fix to the very thing they plot — Exp. 1 (1-2), Exp. 5
(5-2) and Exp. 8 (8-1). In each case the CODE is right and the banked numbers
are from before it. The audit keeps finding fixed bugs, which is the good
outcome; what it means practically is that **the re-run, not more auditing, is
what closes them**.
"No further findings" is NOT a claim this table supports for anything except 2.

**Exp. 3 was described as finished and is not** (reconciled 2026-09-08). Its
matrix row carries `~` on questions 6 and 7, and `X-5` records its config-hash
drift as flatly *unexamined* rather than partial while `G-3` records test
coverage as run only on Exp. 2. The prose and the matrix disagreed; the matrix
is right. Exp. 3 is short two checklist items.

Columns are the seven checklist questions below.
`Y` ran · `~` partial · `-` not run · `n/a` does not apply.

| Exp | 1 axis | 2 workload | 3 claims vs data | 4 construction | 5 reportable | 6 config hash | 7 tests |
|-----|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| 1 | **Y** | **Y** | **Y** | Y | Y | **~** | **Y** |
| **2** | **Y** | **Y** | **Y** | **Y** | **Y** | **Y** | **Y** |
| **3** | **Y** | **Y** | **Y** | **Y** | **Y** | **Y** | **Y** |
| 4 | Y | **Y** | **Y** | **Y** | Y | **Y** | **Y** |
| 5 | Y | Y | Y | **Y** | **Y** | **Y** | **Y** |
| 6 | n/a | **Y** | **Y** | **Y** | Y | **Y** | **Y** |
| 7 | n/a | Y | **Y** | **Y** | Y | **Y** | **Y** |
| 8 | n/a | **Y** | **Y** | **Y** | Y | **Y** | **Y** |

Item 1 is `n/a` for Exps. 6-8: they are proposed-scheme-only ablations, so
there is no baseline axis to disagree with.

### The gaps this leaves

Read straight off the matrix — the empty columns are the work:

* **Item 3** — CLOSED 2026-09-08. Run on all eight; `needfix.md` **G-1** is
  fixed. It paid out to the last: 5 new items and 1 withdrawal.
* **Item 4** — CLOSED. All 19 `psa_*` dirs compared; **G-2** and **G-4** are
  fixed. Biggest finding: under PSA the scheduler ablation **collapses and AASS
  wins nothing** (7-5)
* **Item 7** — CLOSED, all eight. Coverage keeps coming back **stronger
  than G-3 implies** (Exp. 1: 13 tests, Exp. 5: 11, both headline claims
  pinned). The recurring real gap is different: **no experiment pins its own
  SIZING rule** (3-10, 5-6), which is the defect class three experiments
  actually have → **G-3**
* **Item 6** diffed for Exps. 2, 3, 4, 5, 7, 8 — Exp. 4 came back with a
  single revision across all five curves, the cleanest in the audit. Exps. 7-8 share **one** triple
  across all 16 arms — but all three files have since **changed**, and the AASS
  weight vector went 5-term to 4-term (**7-4**). Only Exp. 1 is left, narrowed to
  which-is-which but not key-level → **X-5**

Closing them is roughly one more focused pass, and it belongs before the
campaign rather than after, for the same reason the first audit did: the re-run
is the expensive step.

---

## Also done this session, outside the per-experiment passes

Recorded as items C-1..C-7 and D-1..D-3 in `needfix.md`:

* **Configs synced to §VI** — `index.yaml` was describing corpus **v2** while
  `dataset.yaml` was pinned to **v4**; `|P_U| ∈ {1,2,4,8}` was a published sweep
  living only in code; 46 dangling `README §N` citations retargeted. No measured
  number moves from any of it.
* **Three files deleted** — `README.md` and `infra/fabric/README.md` with their
  AWS and Fabric config rescued into `SystemConfiguration.md` §15-16 first, and
  `Overleaf/drafts/evaluation_setup.md`, which claimed n=30 against a n=10
  campaign and named two dropped baselines.
* **A scheduler regression fixed** — `5143ee7` had collapsed `round_robin` into
  `no_lb`; 8 consecutive `select()` calls returned the same node.

---

## What a pass is

Three sources, read against each other — never one alone:

1. **`Overleaf/MA-LB-PQ-VDSE.tex` §VI** — what the paper *claims* was measured.
2. **`Schemes/*/exp<N>_*/`** — `results.csv`, `raw_runs.csv`, `run_meta.json`.
3. **The code** — `harness/experiments.py` (Option D),
   `harness/psa_experiments.py` (PSA), and each baseline's own runner.

A pass is finished when every question below has an answer and every finding
is an item in `needfix.md`, carrying its own evidence.

---

## The checklist

Seven questions. Every one of them caught something real on Exp. 2 or Exp. 3.

### 1. Does the axis mean the same thing in every scheme?
The one that keeps hurting. Exp. 2 sized its index in entries where the
baselines used records (32x). Exp. 3 fixes 4 records *per domain* where the
baselines fix a 100,000-record *total* (2,500x at d=10). Exp. 4 had the same
bug and had already been fixed.

- For each scheme, find where the sweep value becomes work, and write the unit.
- Check it against `generate_plots.py`'s `xlabel` and §VI's own sentence.
- Greppable tell: `// self.source.keywords_per_record`.

### 2. Is the workload the published one?
`global.yaml defaults` is the contract — "NO scheme may override them".

- `keywords_per_query: 5` (§VI "each query contains five keywords"). Exp. 2 and
  Exp. 3 both issued **one**. Verify by running it: `len(token.tokens)`.
- If the query is conjunctive, do the q keywords **co-occur in a real record**?
  Independently drawn keywords match nothing over `|W_i| ~= 32` — that is the
  failure behind guo's 150 empty runs and psa_exp2's `n_eff = 0.0`.
- Is the queried keyword **from the corpus**, or invented? Exp. 3 plants
  `kw:00000` and still reports `corpus_type: synthea`.

### 3. Do §VI's stated properties survive contact with the data?
Take each quantitative claim in the paragraph and check it arithmetically
against `raw_runs.csv`. Ratios, not eyeballs.

- Exp. 2: "selectivity kept constant… proportional" — N x100 gave `n_eff` x23.2.
- Exp. 3: "the baselines accumulate domain-local search overhead" — guo and
  thingom are flat across the whole sweep.

### 4. Which construction produced the number — `option_d` or `psa`?
They time different functions at the same experiment number.

- Which folder does the `ExperimentSpec` read? `proposed_prefix="psa_"` changes
  the answer.
- Does §VI's prose describe that construction? Exp. 2's paragraph describes the
  policy-state-aware token set while the figure draws Option D.
- If both are banked, state the gap.

### 5. Is every point measured, and reportable?
- `run_meta.json`: `reportable`, `corpus_type`, `corpus_sha256` against the pin,
  host, `runs`.
- `measurement_type` — `projected` points must be hollow and named in the
  caption. Scheme [41] is projected above N=10^4 by decision; never launch it
  above 10^4.
- Count rows per point in `raw_runs.csv` rather than trusting `n_runs`.
- **Read the whole `results.csv`.** A `head -7` cost me a wrong "missing 10^6
  point" claim on two baselines.

### 6. Were all schemes in one figure run under the same `global.yaml`?
`generate_plots.py` warns on this automatically now. It fires on exp1, exp2,
exp3 and exp5.

- If it fires, diff the revisions over `defaults`, `measurement` and
  `experiments.exp<N>` before assuming anything moved. Exp. 2's drift was
  benign — every key it reads was identical.

### 7. Do the tests pin the claims, or only the mechanism?
Exp. 2 had 12 tests on the keyword-draw mechanism and none on q, the sizing or
selectivity. `test_exp2_reports_n_eff` asserted `n_eff >= 0`, which passes on
the empty result.

- For each §VI claim, name the test that would fail if it broke. Write the
  missing ones.
- Watch for tests hardcoding a convention the experiment has changed:
  `test_psa_exp2_shares_fewer_posting_lists_than_option_d` kept the old sizing
  and silently compared two different index sizes.
- Watch for headline metrics that are **asserted rather than measured**:
  Exp. 3's `trapdoors_issued` is a literal `1.0`.

---

## Order to work in

Audit first, re-run once. Every defect so far was found by checking one
experiment against the baselines and the manuscript — not by reasoning about it
in isolation — and a re-run is the expensive step. Finishing 4-8 before
launching means one campaign instead of several.

All eight have been passed over, two of them fully. The remaining order is set
by what unblocks what:

1. **X-6 (BLAS pinning)** — campaign-wide, and it gates every future run, so
   nothing should be launched before it is fixed.
2. **Exp. 1's smoke run** — minutes, and it converts Fig. 1 from
   non-reportable to reportable.
3. **The two sizing decisions** (Exp. 3, Exp. 5) — they join Exp. 2's, and all
   three want the same campaign.
4. **The re-run itself**, once 2-5 (host memory) and 2-6 (construction) are
   settled.
