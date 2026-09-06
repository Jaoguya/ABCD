---
name: bug-sweep
description: One pass of find-fix-verify over this benchmark's code, built to run on a loop. Fixes defects that have exactly one right answer without asking; escalates anything that would change a reported number, and keeps working on the rest. Use with /loop, or on its own when asked to hunt for bugs, check for regressions, or audit recent changes.
---

# Bug sweep

One pass: **scope → detect → classify → act → verify → report**. Designed to be
run repeatedly (`/loop 45m /bug-sweep`), so every pass must leave the tree in a
state the next pass can start from — green suite, nothing half-applied.

`campaign-doctor` is the sibling for a *failing campaign*: it fixes what stops
the fleet running. This one hunts defects in code that already runs, where the
number comes out plausible and wrong.

## The one rule

**Fix what has one right answer. Ask about what has two.**

Not "fix what is easy". A large mechanical fix with one correct outcome is
yours. A one-line change that picks between two defensible estimands is not.

### Yours — fix it, then say so

- The axis lies: a sweep value that is not the work done. `k` retokenized
  `0.500 k`; `r` counted index entries where baselines counted records.
- A metric does not measure its own name. `fsns_touched` reporting 160 on a
  four-node deployment.
- A quantity is **derived where it should be measured** — `size x fan_out`
  instead of summing real deliveries.
- **Like-for-like breaks between two arms that share an axis.** One arm
  short-circuits where the other does the full work; one construction's Exp. 5
  does half the entries of the other's at the same `k`.
- A crash, an unreachable branch, a silent narrowing (`set(a) & set(b)` where a
  mismatch is a caller error).
- A test that asserts the opposite of its name, or passes for the wrong reason.
- Dead code and stale claims — a docstring describing a mechanism that no
  longer has a user. This repo has been bitten repeatedly; 18 stale claims
  across 13 files in one sitting.
- Anything with **no banked `results.csv` behind it**. If nothing measured
  depends on it, there is nothing to invalidate.

### Theirs — ask, and keep going

README §13: *ask rather than guess on scheme constructions, parameter values,
or anything affecting reported numbers.*

- Any change to a number already in a `results.csv`, a figure, or the
  manuscript.
- Choosing between two defensible constructions, estimands, or measurement
  boundaries.
- Scheme roster, sweep ranges, parameters the paper does not publish.
- Anything that would require §V to change to stay true.
- Superseding or deleting measured data.

**Escalating never stops the pass.** Park it and carry on with the rest; a
blocked decision is not a blocked sweep.

## How to escalate

1. Append to `.claude/skills/bug-sweep/DECISIONS.md` — one entry, newest last:

   ```
   ## <date> — <one-line title>
   **Found:** file:line, what is wrong, and the evidence that it is wrong.
   **Costs:** which number/figure/claim moves, and by how much if known.
   **Options:** A … / B … (name the one you would take, and why)
   **Blocked:** what cannot proceed until this is answered. "Nothing" is a
   valid answer and usually the true one.
   ```

2. If — and only if — the user is likely away and the pass is now blocked on
   it, send one `PushNotification` naming the decision. Never one per finding;
   batch to at most one per pass.

3. When the user is present, put the decision in the reply as a single
   question with every number-changing facet in it. Serial option cards read
   as stalling.

## The pass

### 1. Scope
Default to what changed: `git diff`, then `git log --oneline -5`. A full-tree
sweep only when asked, or when the last three passes found nothing.

### 2. Detect
In descending order of what has actually caught bugs here:

- **Cross-check the units of two things that share an axis.** Run both, compare
  the secondary that says what one point *is*. This found the Exp. 5 halving
  and defect `d1cdf9c`.
- **Run the sweep's real endpoints**, not a toy. Every defect below `N≈2000`
  was invisible in unit tests.
- **Read the metric name against the code that fills it.**
- **Diff a new arm against the arm it mirrors.** The PSA verifier's
  short-circuit only showed up beside Option D's.
- `~/.venv-malbpq/bin/python -m pytest -q` — a green suite is the floor, not
  the goal. Every bug in this file's list was found with the suite green.

### 3. Classify
Against the rule above. When genuinely unsure which side a fix falls on, it is
theirs.

### 4. Act
Fix, or write the DECISIONS entry. Never both half-way.

### 5. Verify the mechanism, not the outcome
A number that got better is not evidence. Show the mechanism changed: count the
calls, assert the invariant, compare against the arm it must match. Then pin it
with a test that fails on the old behaviour.

### 6. Report
Lead with what moved. One line per finding: file:line, what was wrong, what it
cost, fixed-or-parked.

## Standing invariants

Never traded away, whatever else the pass finds:

1. **No fabricated data.** A number not measured is not written.
2. **No baseline held to a weaker standard than the proposed scheme.**
3. **Never gate on speed.** Slowness is a finding, not a reason to skip.
4. **Two constructions that share a figure axis must do the same work per
   point.** Option D and PSA both.
5. **Do not edit `README.md` or the Overleaf `.tex`.** Report file, line and
   value; the user applies it.

## Ending the loop

Stop when a pass finds nothing new and DECISIONS.md has no unanswered entry.
Say so plainly rather than manufacturing a finding to justify the tick — under
`/loop` dynamic pacing that is a `noop: true`.
