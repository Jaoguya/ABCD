# AI Agent Rules

This document defines the behavior, constraints, and goal for any AI coding agent working in this repository.

---

## Goal Definition

The AI agent's goal is:

> **Execute all experiments for all schemes, validate the results as a journal reviewer would, and loop until every experiment passes both output validation and reviewer-level integrity checks. If anything is unclear or cannot be resolved, stop and ask the user.**

### Goal Execution Loop

```
LOOP:
  0. **git fetch origin && git pull** — ALWAYS, before any work begins. No exceptions.
  1. For each scheme (ours + 4 baselines):
     a. Read the scheme's SCHEME.md for experiment list and measurement rules
     b. Execute each applicable experiment
     c. Validate outputs (see Output Validation below)
     d. Perform reviewer-level integrity checks (see Reviewer Checks below)
  2. If ALL schemes pass ALL checks → run plotting script → DONE
  3. If any check fails:
     a. Log the failure in debug_history.md (see Debug Rules below)
     b. Attempt to fix the issue
     c. Re-run the affected experiment
     d. GOTO step 0 (fetch again, then recheck everything)
  4. If unable to fix, or unsure about anything → ASK THE USER
```

### Output Validation

For each experiment, verify:

- [ ] `raw_runs.csv` exists with correct columns and `n = 30` retained runs
- [ ] `results.csv` exists with correct aggregated format and `n_runs = 30`
- [ ] `run_meta.json` exists with real git commit, dataset SHA-256, Python version, UTC start time
- [ ] Units are correct (ms for latency, KB for sizes, queries/s for throughput)
- [ ] Secondary metrics are populated where applicable, blank where not
- [ ] No `status=failed` rows remain unresolved in `raw_runs.csv`

### Reviewer-Level Integrity Checks

Think like a **journal reviewer**. After experiments complete, verify these will NOT get flagged:

#### Statistical Integrity
- [ ] 95% CI is correctly computed from the 30 runs (not hardcoded or artificially narrow)
- [ ] Mean and CI values are plausible given the measurement (no suspiciously round numbers)
- [ ] Variance across runs is reasonable — zero variance or implausibly low variance indicates a bug or fabrication
- [ ] No outlier deletion — all 30 runs retained per the methodology

#### Bias Detection
- [ ] No artificial delays injected into any scheme
- [ ] No per-scheme parameter tuning — all schemes use identical `global.yaml` defaults
- [ ] No per-figure λ retuning — scheduler weights are fixed across Exp. 7–8
- [ ] The proposed scheme does not win on every metric with suspiciously uniform margins
- [ ] Baselines are not weakened below their published construction (no skipped steps, no reduced security parameters)
- [ ] Baselines are not strengthened beyond their published construction
- [ ] Measurement boundaries match the rules in each SCHEME.md (e.g., Exp. 1 excludes ML-KEM encapsulation)

#### Consistency Checks
- [ ] All `run_meta.json` files reference the same dataset SHA-256
- [ ] All schemes ran on the same Python version and instance type
- [ ] Config file hashes are consistent across all runs
- [ ] Corpus type is `mimic` for reportable data (not `synthetic`)
- [ ] Scaling behavior is physically plausible (e.g., O(N) search should not appear O(1))

#### Cross-Experiment Coherence
- [ ] Results across experiments for the same scheme are internally consistent
- [ ] Exp. 7 and Exp. 8 are derived from the same runs (same workload trace)
- [ ] Secondary metrics support the primary metric story (e.g., `n_eff` explains search latency in Exp. 2)

---

## Constraints

### 1. Do NOT Edit README.md

The main `README.md` is the **source of truth** for the benchmark specification. AI agents must **never** modify it. If `README.md` needs an update, ask the user to make the change.

Scheme-specific `SCHEME.md` files may be updated by the agent if needed (e.g., correcting a command, noting an issue).

### 2. Ask the User When Unsure

If the agent encounters any of the following, it must **stop and ask the user** before proceeding:

- A scheme's published construction is unclear or ambiguous
- A parameter value is not specified and no default exists
- An experiment produces unexpected results that could indicate a design issue (not just a bug)
- The agent is unsure whether a measurement boundary is correct
- The agent is unsure what a scheme's construction requires
- Any decision that would affect reported numbers

**Do not guess about scheme implementations.** If you don't know how a scheme works, ask.

### 3. Do NOT Fabricate or Bias Results

- Do NOT hardcode, precompute, or fabricate measurements
- Do NOT tune parameters per experiment to flatter one scheme
- Do NOT weaken or strengthen baselines beyond their published constructions
- If the proposed scheme loses on a metric, report it as measured

### 4. Cross-Platform Execution

- Use `python3` on Linux, `python` on Windows (PowerShell)
- Use `/` path separators on Linux, but quote paths with spaces on both platforms
- Use `\` for line continuation in bash, `` ` `` in PowerShell
- Test that timing functions (`time.perf_counter_ns()`) work correctly on both platforms
- The agent should auto-detect the platform and use appropriate commands

---

## Debug Rules

### When to Log

**Every time the agent debugs an issue**, it must append an entry to `debug_history.md`. This includes:

- Code fixes for failing experiments
- Parameter adjustments
- Environment issues
- Runtime errors and their resolutions
- Any change made during the experiment execution loop

### Format

Each entry in `debug_history.md` follows this format and is marked *not fixed* until resolved:

```markdown
### [Brief title of the issue]
- **Date:** YYYY-MM-DD
- **Status:** *not fixed*
- **Why it changed:** [Root cause or reason the change was needed]
- **How it will improve:** [Expected improvement or what this fix addresses]
- **What changed:** [Specific code, config, or environment changes made]
```

When the issue is resolved, update the status to *fixed* and append resolution details.

### Rules

- **Always append** — never delete or overwrite previous entries
- Log **before** attempting a fix so the history captures the intent
- Update the entry **after** the fix is verified
- If the same issue recurs, create a new entry referencing the previous one

---

## Execution Order

Recommended order for running experiments:

1. **Setup** — Dataset preparation, environment setup, infrastructure (Fabric, IPFS if needed)
2. **Proposed scheme first** (`ma_lb_pq_vdse`) — all 8 experiments
3. **Baselines** in order:
   - `guo_vdsse` — Exp. 1, 2, 3, 4, 5
   - `xb_muse` — Exp. 1, 2, 3, 5 (⚠️ requires clean Ref[36] PDF first)
   - `thingom_pq_abse` — Exp. 1, 2, 3
   - `zhuang_lattice_mabse` — Exp. 1, 2, 3, 5, 6
4. **Plotting** — `python Plots/generate_plots.py`
5. **Full validation loop** — recheck all outputs and reviewer checks
