---
name: runtime-table
description: Show the full-campaign runtime table for every scheme - total hours per scheme against the 24h cap, per-experiment breakdown, and which totals are stale because the code changed. Use when asked how long a scheme or the campaign takes, whether a run fits in 24 hours, what a new scheme costs, or after implementing or debugging any scheme so the numbers get re-derived.
---

# Scheme runtime table

Answers "how long does each scheme take, and can I still run it in a day?"
from `Experiment Configuration/planning/runtime_estimates.csv`.

```bash
python3 .claude/skills/runtime-table/scripts/runtime_table.py            # the table
python3 .claude/skills/runtime-table/scripts/runtime_table.py --detail   # + per-experiment
python3 .claude/skills/runtime-table/scripts/runtime_table.py --bless <scheme>
```

Run it from the repo root. Pure stdlib, no venv needed — it works on a bare
EC2 host where `pyyaml` may not be in the active environment.

## When to run it

- The user asks how long anything takes, or whether it fits the 24h cap.
- **After implementing a new scheme or experiment** — a scheme with no rows
  shows a total of 0.00h, which reads as "free" and is not.
- **After debugging or optimising any measured code path** — a fix that changes
  runtime silently invalidates that scheme's row. This is the common case: the
  yue_ge Exp.1 scoping fix moved setup from ~3h to 16 min, and every number
  recorded before it was wrong.
- Before launching a campaign, to check nothing is over budget.

## Reading the output

`TOTAL` is the sum of leaf rows only. `MEASURED` vs `EST` splits on the
`basis` column — `MEASURED` came from a clock, anything else (`estimated`,
`config`) did not. Prefer moving rows into `MEASURED`; an all-`EST` scheme
total is a guess with a bar chart around it.

`SERIAL TOTAL` is what one host would take back to back. It is **not** the
campaign wall-clock: schemes run on separate instances, so wall-clock is the
largest single row.

`CODE STATUS` is the honest-numbers column:

| Value | Meaning |
|---|---|
| `current` | Totals were derived from exactly this code. |
| `STALE +n` | `n` commits touched `Schemes/<scheme>/` since the totals were validated. Treat the number as unverified. |
| `unvalidated` | Never validated against any commit. |
| `no sources` | No commits touch that scheme's directory. |

## Re-deriving after a change

When you change a measured code path:

1. Re-measure the affected part. A short run is usually enough — one
   `--runs 2` invocation, or a direct timing of the dominant loop — because
   the goal is a rate, not a result.
2. Update or add the rows in `runtime_estimates.csv`. Put the rate and the
   date in `notes`; that is what makes the row auditable later.
3. `--bless <scheme>` to record that the totals now match HEAD.

**Only bless what you actually measured.** Blessing is a claim that the
numbers came from this code. It is not a claim that coverage is complete —
missing experiments are reported separately, and a blessed scheme can still be
missing most of its rows.

## What the script deliberately handles

These are the traps in this particular CSV. Do not "simplify" them away:

- **Aggregate rows are excluded from sums.** `TOTAL` (in the experiment
  column) and `SUBTOTAL` (in sweep_value) restate other rows; counting them
  double-counts. Cross-check: thingom's leaf rows sum to 16.77h against its
  own `TOTAL` row of 16.73h, so the exclusion is working.
- **Seconds are summed, not hours.** `point_total_h` is rounded to 2dp and
  ma_lb_pq_vdse alone has 20 rows; the rounding error accumulates visibly.
- **`EXCLUDED` / `SUPERSEDED` / `DROPPED` rows are not costs.** They are
  deliberate scope cuts. They are counted and reported, never summed.
- **Ragged rows parse.** Some existing rows have unquoted commas in `notes`
  and come out at 13 or 15 fields against a 12-field header. Fields from
  column 11 on are rejoined, because that text holds the EXCLUDED rationale.
- **Experiment names are matched by number.** `exp2_search_latency` (global.yaml),
  `exp2` and `build_exp2` (CSV) are the same experiment; `exp7_8` is two, per
  README §5 which derives Exp. 7 and 8 from the same runs.

## Caveats the table surfaces, and why they matter

- **Rows measured off the pinned host.** Several guo_vdsse rows were taken on
  a macOS arm64 dev host, not the m6i.xlarge, and their notes say to derate
  ~1.5x. Those totals are not comparable to on-host numbers as written.
- **Missing experiments.** A scheme's total is a *floor* whenever global.yaml
  enrolls it in experiments the CSV has no rows for. Say "floor", not "total",
  when reporting one of these.
- **Untimed setup dominates.** Index builds are excluded from measured
  latency but still consume wall-clock. They belong in the table as
  `build_expN` rows, or the campaign will overrun its budget while every
  individual measurement looks cheap.

## Scope

This skill reads this project's own planning CSV and this repo's git history.
It does not touch AWS, other instances, or anything outside this repository —
see the aws-cost skill's scoping rule, which applies here too: **this project
only, never another instance that is not ours.**
