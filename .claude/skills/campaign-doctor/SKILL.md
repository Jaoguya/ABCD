---
name: campaign-doctor
description: Autonomously find, diagnose and fix defects in the benchmark campaign until every scheme runs clean. Use when a campaign fails, before launching one, when a scheme OOMs or errors, or when asked to debug/optimise the experiments. Decides and acts without asking; records results-affecting decisions loudly.
---

# Campaign doctor

Runs the loop: **gate → detect → diagnose → fix → verify → repeat**, until every
scheme completes every experiment with no failure, no fabricated number, and no
silently-wrong cost.

## Operating rule

**Decide and act. Do not ask.** When there is a recommended option, take it.
Record what was chosen and why in `debug_history.md`; that is the audit trail,
not a permission gate.

The single exception is not a question, it is a **label**: a change that alters
what a reported number means is `[results-affecting]` and must say so in
`debug_history.md` and the commit message, and name what §V has to disclose.
Make the change; make it loud. Never make one quietly.

Three things are never traded away, whatever the schedule:

1. **No fabricated data.** A number that was not measured is not written.
   No padding a sweep to fill an axis, no synthesised point, no estimate
   presented as a measurement.
2. **No baseline held to a weaker standard than the proposed scheme.** Same
   reportability gate, same corpus, same host, same methodology. An
   optimisation applied to one scheme must be considered for all of them.
   (AGENT_RULES "Bias Detection".)
3. **Never gate on speed.** Memory is a hardware limit; slowness is a finding.
   Refusing a scheme for being slow shapes which results exist.

## The loop

### 1. Gate before spending
`python3 .claude/skills/campaign-doctor/scripts/scale_gate.py --scheme <name>`

Runs each scheme's **largest sweep point** on the real corpus and records peak
RSS and elapsed time. Roughly an hour, on one instance. **Every defect in the
2026-08-29 campaign would have been caught here** instead of 8.7 fleet-hours in.

Never skip it because unit tests pass — they use toy data, and every failure so
far was invisible below real scale.

### 2. Triage what failed
`python3 .claude/skills/campaign-doctor/scripts/triage.py --hosts <ips>`

Classifies every node's outcome by signature. Do not read logs by hand first;
the classifier is faster and does not mis-remember.

### 3. Diagnose to root cause, not to symptom
Fix the cause. `rc=137` on four experiments of one scheme is one bug, not four.

### 4. Verify the fix does what you think
**Measure the mechanism, not just the outcome.** The `--points` fix looked
correct — the right sweep point was measured — while the setup silently ran 9x
the work, because only the measurement loop had been filtered. It was caught by
counting `update()` calls through a stub, not by reading results.

### 5. Re-run only what changed
Diff against the commit the standing results came from. If the change touches
one scheme, only that scheme re-runs. `Common/crypto/` or shared `global.yaml`
parameters touch everything.

## Failure signatures seen on this project

| Signature | Cause | Fix |
|---|---|---|
| `rc=137`, one scheme, several experiments | index too large for the host | scope the build to README §6 `index_size`, or cap the sweep and disclose |
| OOM in an experiment that does not sweep N | runner indexes the whole corpus | scope to `DEFAULT_N`; check keyword-frequency selection uses the same subset |
| OOM despite `--points` | selection applied at `run_experiment`, not where the range is computed | filter at the range definition so pre-build loops see it |
| Sweep is nested prefixes, rebuilt per point | `records[:n]` re-inserts everything already indexed | build once and grow; assert index structure and search results match a fresh build |
| Setup rebuilt per repetition | contradicts `prepare()` once / `measure()` x reps | build once; report index size per run so drift is visible |
| Cost grows with the swept variable when it should not | total indexed data not held constant | shard a fixed subset |
| A curve is superlinear in an "incremental" experiment | the operation is not incremental | fix the mechanism, not the sweep |

## Estimation traps that have already cost real hours

- **Measure the shape production has.** Adjacent puncture points share tree
  prefixes and gave 9.5 GB where pseudorandom ones give 141 GB. The dev corpus
  has 13,227 keywords at 11.2/record against corpus v4's 2,023 at 31.70;
  anything scaling with keyword density is ~6.5x wrong if extrapolated from it.
- **Never measure memory on a loaded machine.** RSS under pressure is
  compressed away and reads low. One scheme at a time, quiet host.
- **`basis=config` is a guess.** One such row booked Exp. 7-8 at 17.5h; it
  takes ~60s per config. Prefer `MEASURED`; re-derive after touching a measured
  path (`runtime-table` skill).
- **Time and memory are different questions.** The time model was accurate
  (40.5 predicted vs 42.3 measured ms/record) while memory was never modelled
  at all. `runtime_estimates.csv` still has no memory column.

## Cost discipline

Money is a constraint, and idle instances are the usual leak.

- Stop instances that finish. The watchdog (`~/watchdog.sh`) does this: it waits
  for the `.rc` file, confirms no scheme process is alive, then
  `shutdown -h` — and `InstanceInitiatedShutdownBehavior` is `stop`, so volumes
  and results survive.
- Check `aws-cost` skill (`--running` is free) before and after a campaign.
- Fleet wall-clock is bounded by the largest **indivisible** job. Adding
  instances past that only adds idle. Split with `--points` first.
- Never launch against code that has not passed the gate. That is what an
  8.7-hour campaign losing a whole scheme costs.

## Done means

- Every scheme completes every experiment it is enrolled in (`global.yaml`)
- Every `results.csv` has `n_runs = 30` and a `run_meta.json` with
  `reportable: true`, or a recorded reason it is not
- No `rc != 0` anywhere
- Every cap and every results-affecting decision is in `debug_history.md` with
  the measurement that forced it, and named for §V
- `runtime-table` re-derived and blessed
- Shards merged with `infra/merge_points.py`
