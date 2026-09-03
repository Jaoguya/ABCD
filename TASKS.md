# Task board

One screen of "what is left". `remainfix.txt` carries the reasoning for every
item that has an ID here; README §17 carries the cold-start handoff. This file
is the index, not a third copy — when they disagree, `remainfix.txt` wins.

**State:** all five schemes complete, harvested and committed at 10 repetitions.
Nothing is running; all nine EC2 instances are stopped. Nothing below is blocked
on infrastructure.

Legend: `[DECIDE]` needs a human call · `[BUILD]` engineering with a known target
· `[FIX]` mechanical · `[OPS]` infrastructure · `[RUN]` needs machine time

---

## Blocking the paper

| ID | Task | State |
|----|------|-------|
| DECIDE-1 | Does Scheme [54] belong in Exp. 4? | **DECIDED 2026-09-03: no.** Excluded on time, not capability — `retrieve_verify` is implemented. Section V states its cost analytically and says it was not measured; `global.yaml` and `perera_lv_pqabse/SCHEME.md` now carry the reason, including the O(N) tree rebuild that must be fixed first if it is ever revisited |
| DECIDE-2 | What statistic do the baselines get reported with? | open |
| FIX-1 | `tab:cost` claims `O(d)T_Ver` but no such operation exists | **fixed 2026-09-03** — removed from the table cell, the paragraph under it, and the Fig. 5 discussion. `T_Ver` now appears only where Scheme [54] legitimately uses it |
| FIX-2 | Manuscript claims contradicted by measurement | open |
| BUILD-2 | Exp. 4 aggregate proof ("Tier 2") | open — the only change that moves us from 3rd to 2nd |

## Needs a machine (one trip)

| ID | Task | Cost |
|----|------|------|
| RUN-1 | Exp. 6 ablation — `--experiment 6 --variant all` | **~33 min.** Measured ratios at δ=1000: `ias` 1.00×, `broadcast` 1.01×, `full_rebuild` 1.37×, against `ias`'s AWS-measured 39.2 s per full-sweep run × 15 executions |
| RUN-2 | Exp. 9 tamper granularity — all three schemes | **~5 min of verification** (ours 828 ms/run at r=20,000, guo ~104 ms, ge ~182 ms) **plus index builds**, which are untimed and unmeasured — allow 10–40 min |
| RUN-3 | Ref[41] Exp. 2 at `N=10⁵` to validate the ×10 extrapolation | ~1.13 h |

`RUN-1` and `RUN-2` were deliberately held to go up in **one** trip, because
starting the fleet costs an SSH-rule round trip and `deploy` has a history of
overwriting results (OPS-2).

## Landed today, not yet run

| ID | Task | State |
|----|------|-------|
| BUILD-1b | Exp. 6's IAS ablation | code landed `fb4433a`; **20/20 tests now pass** (they had never been executed — pytest was missing). The two failure modes `remainfix.txt` predicted, `broadcast` needing Phase II Step 4 and `full_rebuild`'s touched-count, both hold. Owes RUN-1 |
| BUILD-9 | Exp. 9 — verification granularity under tampering | code landed for all three schemes; **13/13 tests pass for ours**. The two baseline arms are **untested** — they need the corpus, which is not on the dev host. First run is also their first execution |

## Open, not blocking

| ID | Task | State |
|----|------|-------|
| FIX-3 | perera Exp. 1 still has distorted points | open |
| FIX-4 | Two stale merged directories in the proposed scheme | open |
| OPS-1 | Nodes cannot push their own results | open |
| OPS-2 | Result handling destroyed data once, nearly twice | mitigated by `fleet.sh`, procedure still manual |

---

## Found 2026-09-03, not yet in `remainfix.txt`

### PARITY-1 — guo ran its whole final campaign on a 16-vCPU host `[FIX]`

Every other scheme reports `cpu_count: 4`. guo reports **16** for Exp. 1, 2, 3,
4 and 5 (only its older `exp3__points-*` shards are on 4). §V states
`m6i.xlarge` — 4 vCPU — for everything.

Most of these are single-threaded, so the numbers are probably not distorted:
a 16-vCPU m6i is the same Ice Lake core at the same clock, just more of them.
But "probably" is not what a parity claim rests on, and Exp. 4's three arms are
currently **guo on 16 vCPU vs yue_ge on 4 vs ours on an unrecorded host**.

Two honest ways out, and re-running is the cheap one:

1. Re-run guo Exp. 1, 3, 4, 5 on `m6i.xlarge` (all fast) and keep the large
   instance only for Exp. 2, where ~53.5 GB at `N=10⁶` forces it and where it
   is already disclosed.
2. Or state per-experiment hosts in §V and drop the blanket `m6i.xlarge` claim.

### PARITY-2 — provenance cannot prove parity either way `[FIX]`

The baselines record `cpu_count` but **no** `instance_type`; the proposed
scheme records `instance_type` but for the current campaign it is the literal
string `"unknown"` and there is no `cpu_count`. So no result file states which
box produced it. `verify_experiment_host()` exists for exactly this and is
returning nothing usable. Fix before the next campaign, not after.

### REPS-1 — manuscript vs config repetition count `[FIX]` **FIXED 2026-09-03**

Section V said "repeated 30 times" while `global.yaml` says 10 and every
committed result carries `n_runs = 10`. Decided 2026-09-03: **keep 10** —
re-running the whole campaign at 30 is not affordable. Section V is back to 10
and `test_manuscript_section_v_matches_the_config` passes.

### TEST-1 — four provenance tests crash on Windows `[FIX]` **FIXED 2026-09-03**

`test_repetition_count_agreement.py` read README and the manuscript with
`Path.read_text()` and no encoding, so it died on cp1252 before it could assert
anything — which is exactly how REPS-1 drifted unnoticed. All five reads now
pin `encoding="utf-8"`; 5/5 pass.

### FIG-1 — Fig. 7 is a placeholder `[FIX]`

The Exp. 6 figure in the PDF is a dummy: its "Proposed IAS" curve reads ~60 ms
at `δ=10⁵` where the measurement is 35,331 ms, and it grows sub-linearly where
both the measurement and `tab:cost`'s `O(δ)T_H + O(log d)T_MT` are linear.
Replace it from `Plots/output/` after RUN-1. Confirmed a placeholder, recorded
so nobody re-derives the discrepancy.

### FIG-2 — Fig. 7 cannot be a single latency panel `[DECIDE]`

Measured at delta=1000 before committing machine time:

| variant | latency | vs ias | fsns_touched |
|---------|---------|--------|--------------|
| `ias` | 107.6 ms | 1.00x | 1 |
| `broadcast` | 109.1 ms | **1.01x** | 4 |
| `full_rebuild` | 147.4 ms | 1.37x | 13 |

`broadcast` costs 1% more than `ias` in LATENCY. Plot latency against delta and
the selective-sync curve lands on top of the proposed one; only `full_rebuild`
separates, and only by 1.37x. That is not the three well-separated curves the
placeholder figure shows.

This is not the claim being wrong, it is the harness: all four FSNs run in one
interpreter, so delivering to four nodes instead of one costs almost nothing
because no network is crossed. Exp. 7-8 already declare this same limitation.

So the evidence splits, and `remainfix.txt` BUILD-1b item 3 already said so:
**`full_rebuild` vs `ias` on latency evidences INCREMENTAL; `broadcast` vs
`ias` on FSNs touched (4 vs 1) evidences SELECTIVE.** A single latency panel
proves half the claim. Fig. 7 should be two panels, or Section V should stop
claiming selective propagation as a latency result.

### CITE-1 — the repo and the manuscript disagree on reference numbers `[FIX]` **RECORDED 2026-09-03**

The manuscript cites Ge et al. as `ref30`; `ref55` is Cao et al. The repo
calls Ge **Ref[55]** across 29 files and 91 sites, all anchored to the
`References/Ref[55]/` folder. Renaming would break every link for no gain, so
the mapping is **recorded** at the top of `Schemes/yue_ge/SCHEME.md` instead of
applied — the repo's `Ref[NN]` are folder labels, not LaTeX keys.

**Still open, and an author call:** `\bibitem{ref55}` (Cao et al.) is in the
bibliography but cited **zero** times. IEEEtran will still print it. Cite it or
drop it.

---

## Should we upgrade the EC2 instances to go faster?

**No, not for speed.** Checked against what the experiments actually do:

- Nearly every measured path is **single-threaded Python**. A larger instance in
  the same family adds cores at the same clock, so the per-run latency is
  unchanged. Paying 4× for 0× is the usual outcome.
- The exceptions are real but narrow. **Memory** is one: guo Exp. 2 at `N=10⁶`
  needs ~53.5 GB and genuinely cannot run on a 16 GB box — that is why a large
  instance was used, and it is disclosed. **Parallelism** is the other:
  thingom's per-entry search runs across 2 processes for a measured 1.94×, and
  that is already capped at 2, not at the core count.
- The cost that matters is **wall-clock of the campaign**, and the campaign is
  finished. What remains is ~1.2 h of machine time (RUN-1 + RUN-2 + RUN-3), so
  even a large speedup would save minutes.

**And upgrading actively hurts.** Instance type is a parity property: every
scheme must be measured on the same box or the cross-scheme comparison is not a
comparison. PARITY-1 shows that has already slipped once and needs repairing —
changing instance types again would deepen the problem the paper has to explain.

**Where a bigger box IS the right answer:** a single scheme whose *build* is
memory-bound, run on the large instance deliberately, disclosed per-experiment
in §V, with the *measured* path still on the common instance wherever the
measurement is what is being compared.
