#!/usr/bin/env python3
"""How much does the AASS λ vector actually matter?

    python3 -m Schemes.ma_lb_pq_vdse.src.harness.lambda_sensitivity

WHY THIS EXISTS, AND WHY IT IS NOT A SWEEP
------------------------------------------
The adopted weights (0.2, 0.4, 0.1, 0.2, 0.1) came from ``lambda_sweep.py``:
1001 grid vectors, ONE replay each, winner by max throughput. That selection is
unsafe, and the sweep's own output proves it. Grouping its vectors by scheduling
behaviour (λ1 is inert, and C^queue was constant pre-5cf65f9 so λ5 was inert
too) leaves only 206 distinct behaviours among 1001 rows; the worst class spans
50.3% in throughput, and the whole field spans 53.9%. The adopted vector is
rank 1/1001 and is the MAXIMUM of its own 4-member behavioural class, +7.7%
above classmates that must schedule identically to it. That is the max order
statistic of a noisy field — winner's curse — not evidence of a better vector.

So this tool deliberately does NOT rank and does NOT propose a winner. It
answers one question: **do well-separated λ directions differ by more than run
noise?** If they do not, the reported vector can honestly be described as fixed
a priori, and its exact value stops mattering. If they do, λ genuinely matters
and the weights need a real determination.

Nothing here may be promoted to a new adopted vector. Ranking twelve arms by
their sample mean would rebuild the same winner's curse at n=10.

DESIGN
------
λ1 is held at its adopted 0.2 throughout so every arm is comparable to the
reported vector, and (λ2..λ5) sum to 0.8.

Arm B is a FALSIFICATION arm. It carries λ1=0.0 with (λ2..λ5) scaled to keep the
same direction, so it must schedule identically to A if λ1 is truly inert
(``C^auth = |P_Q|`` has no node term, so ``normalize()`` maps that column to
0.0). If B separates from A beyond noise, the inertness claim is WRONG and the
disclosure built on it has to be withdrawn. One arm buys that check.

D-G are the simplex corners: if even the corners fall inside the band, the
insensitivity result is about as strong as this instrument can make it.

Both concurrencies are run because they ask different questions. 100 is where
AASS's throughput margin is thinnest; 5000 is where §VI's surviving claim —
bounded peak queue depth — lives. A band that holds across the reported range
is worth much more than one at a single corner.

The run is explicitly NON-REPORTABLE (``status="sweep"``), like the sweep it
replaces: it exists to characterise the weights, not to produce a figure.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import stats  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod  # noqa: E402

#: (label, note, λ1, λ2 index, λ3 verify, λ4 sync, λ5 queue)
ARMS: Tuple[Tuple[str, str, float, float, float, float, float], ...] = (
    ("A_adopted",     "the reported vector",           0.2, 0.40, 0.10, 0.20, 0.10),
    ("B_lambda1_ctrl","same direction, λ1=0",          0.0, 0.50, 0.125, 0.25, 0.125),
    ("C_uniform",     "neutral prior",                 0.2, 0.20, 0.20, 0.20, 0.20),
    ("D_index_heavy", "simplex corner",                0.2, 0.65, 0.05, 0.05, 0.05),
    ("E_verify_heavy","simplex corner",                0.2, 0.05, 0.65, 0.05, 0.05),
    ("F_sync_heavy",  "simplex corner",                0.2, 0.05, 0.05, 0.65, 0.05),
    ("G_queue_heavy", "simplex corner",                0.2, 0.05, 0.05, 0.05, 0.65),
    ("H_index_queue", "two-term mix",                  0.2, 0.35, 0.05, 0.05, 0.35),
    ("I_index_sync",  "two-term mix",                  0.2, 0.35, 0.05, 0.35, 0.05),
    ("J_verify_queue","two-term mix",                  0.2, 0.05, 0.35, 0.05, 0.35),
    ("K_anti_adopted","adopted ordering reversed",     0.2, 0.10, 0.20, 0.10, 0.40),
    ("L_near_adopted","small local perturbation",      0.2, 0.35, 0.15, 0.20, 0.10),
)

METRICS = ("throughput", "utilization_stddev", "max_queue_depth")

#: A verdict is only worth stating when the measurement could have detected a
#: difference. Post-fix Exp. 7 reports 3320 ± 37 at n=30 (±1.1%), so ±5% at
#: n=10 is a reachable bar; above it this tool says INCONCLUSIVE rather than
#: letting wide CIs masquerade as insensitivity.
PRECISION_TARGET = 0.05


def _tuned(config: scheme_config.Configuration,
           lam: Sequence[float]) -> scheme_config.Configuration:
    """The config with one λ vector installed, marked non-reportable.

    ``status="sweep"`` for the same reason lambda_sweep.py sets it: a run that
    CHARACTERISES the weights cannot be required to have them already fixed, and
    it must never be mistaken for a reportable result.
    """
    return replace(
        config,
        scheduler=replace(
            config.scheduler,
            weights=replace(
                config.scheduler.weights,
                auth=lam[0], index=lam[1], verify=lam[2],
                sync=lam[3], queue=lam[4],
                status="sweep", provisional=True,
            ),
        ),
    )


def run_point(config: scheme_config.Configuration, source: Any,
              concurrency: int, runs: int) -> List[Dict[str, Any]]:
    """Every arm at one concurrency, over ONE shared workload.

    prepare() is called once and its deployment and request trace are reused by
    every arm, so the arms differ only in λ. Rebuilding per arm would fold index
    construction and trace generation into the comparison.
    """
    base = exp_mod.SchedulerAblation(
        config=config, source=source, variant=aass_mod.VARIANT_AASS)
    print(f"  preparing concurrency={concurrency} "
          f"(index build + {exp_mod.RAMP_SECONDS:.0f}s ramp)...", flush=True)
    prepared = base.prepare(concurrency)
    deployment, requests = prepared["deployment"], prepared["requests"]

    rows: List[Dict[str, Any]] = []
    for label, note, *lam in ARMS:
        ablation = exp_mod.SchedulerAblation(
            config=_tuned(config, lam), source=source,
            variant=aass_mod.VARIANT_AASS)
        samples: Dict[str, List[float]] = {m: [] for m in METRICS}
        for _ in range(runs):
            out = ablation.replay(deployment, requests, concurrency)
            samples["throughput"].append(out.throughput)
            samples["utilization_stddev"].append(out.utilization_stddev)
            samples["max_queue_depth"].append(float(out.max_queue_depth))
        row: Dict[str, Any] = {
            "arm": label, "note": note, "concurrency": concurrency, "n": runs,
            "lambda_1_auth": lam[0], "lambda_2_index": lam[1],
            "lambda_3_verify": lam[2], "lambda_4_sync": lam[3],
            "lambda_5_queue": lam[4],
        }
        for m in METRICS:
            s = stats.summarise(samples[m])
            row[f"{m}_mean"] = round(s.mean, 6)
            row[f"{m}_ci95"] = round(s.ci95, 6)
        rows.append(row)
        print(f"    {label:<16} thr={row['throughput_mean']:9.2f}"
              f" ±{row['throughput_ci95']:<7.2f}"
              f" sigma={row['utilization_stddev_mean']:.5f}"
              f" qdepth={row['max_queue_depth_mean']:.1f}", flush=True)
    return rows


def report_band(rows: List[Dict[str, Any]]) -> None:
    """The band, per metric per concurrency. Explicitly not a ranking."""
    print("\n" + "=" * 74)
    print("SENSITIVITY BAND — not a ranking; no arm here may become the adopted vector")
    print("=" * 74)
    for conc in sorted({r["concurrency"] for r in rows}):
        at = [r for r in rows if r["concurrency"] == conc]
        print(f"\nconcurrency = {conc}")
        for m in METRICS:
            means = [r[f"{m}_mean"] for r in at]
            cis = [r[f"{m}_ci95"] for r in at]
            lo, hi = min(means), max(means)
            spread = (hi - lo) / lo * 100 if lo else float("nan")
            widest = max(cis)
            # Precision first. "spread fits inside the CI" is trivially true
            # when the CIs are wide, so a noisy run would otherwise report
            # INDISTINGUISHABLE and be read as "λ does not matter" -- the
            # comfortable answer, produced by a blunt instrument rather than by
            # evidence. Refuse to conclude anything until the measurement could
            # actually have detected a difference worth caring about.
            rel = widest / abs(max(means)) if max(means) else float("inf")
            if rel > PRECISION_TARGET:
                verdict = (f"INCONCLUSIVE — widest CI is ±{rel * 100:.1f}% of the "
                           f"mean, above the {PRECISION_TARGET * 100:.0f}% needed "
                           f"to detect a difference this size. Raise --runs.")
            elif (hi - lo) <= 2 * widest:
                verdict = ("INDISTINGUISHABLE — arms differ by less than run "
                           "noise, at adequate precision")
            else:
                verdict = "SEPARATED — arms differ by more than run noise"
            print(f"  {m:<20} {lo:.5g} .. {hi:.5g}  spread={spread:5.1f}%  "
                  f"widest CI=±{widest:.5g} ({rel * 100:.1f}%)")
            print(f"  {'':<20} -> {verdict}")

        a = next(r for r in at if r["arm"] == "A_adopted")
        b = next(r for r in at if r["arm"] == "B_lambda1_ctrl")
        gap = abs(a["throughput_mean"] - b["throughput_mean"])
        tol = a["throughput_ci95"] + b["throughput_ci95"]
        print(f"\n  FALSIFICATION ARM B (λ1 inertness): |A-B| = {gap:.2f} q/s, "
              f"CI sum = {tol:.2f}")
        rel_b = tol / a["throughput_mean"] if a["throughput_mean"] else float("inf")
        if gap > tol:
            print("  -> A and B SEPARATE: λ1 inertness is REFUTED — the §VI "
                  "disclosure built on it must be withdrawn")
        elif rel_b > PRECISION_TARGET:
            print(f"  -> INCONCLUSIVE: they agree, but the CI sum is "
                  f"±{rel_b * 100:.1f}% of A's mean, so agreement here is weak "
                  f"evidence. Inertness still holds ANALYTICALLY (C^auth has no "
                  f"node term); this arm simply failed to test it.")
        else:
            print("  -> A and B agree within noise at adequate precision: "
                  "λ1 inertness SURVIVES this test")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lambda_sensitivity")
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--concurrency", default="100,5000",
                    help="comma-separated (default: 100,5000)")
    ap.add_argument("--synthetic", action="store_true",
                    help="synthetic source; faster, and NEVER reportable")
    ap.add_argument("--output", default=None)
    args = ap.parse_args(argv)

    config = scheme_config.load()
    source: Any = (exp_mod.SyntheticRecordSource() if args.synthetic
                   else exp_mod.CorpusRecordSource())
    print(f"AASS λ sensitivity — {len(ARMS)} arms, n={args.runs}, "
          f"source={source.corpus_type}")
    print("NON-REPORTABLE by construction: this characterises the weights.\n")

    rows: List[Dict[str, Any]] = []
    for conc in [int(c) for c in args.concurrency.split(",") if c.strip()]:
        rows.extend(run_point(config, source, conc, args.runs))

    out = Path(args.output) if args.output else (
        REPO_ROOT / "Schemes/ma_lb_pq_vdse/exp7_search_throughput"
        / "lambda_sensitivity.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    report_band(rows)
    try:
        shown = out.relative_to(REPO_ROOT)
    except ValueError:
        shown = out          # --output outside the repo, e.g. a scratch dir
    print(f"\nwrote {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
