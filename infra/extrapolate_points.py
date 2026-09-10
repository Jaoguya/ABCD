#!/usr/bin/env python3
"""Fill a sweep's unmeasured points by scaling linearly from a measured anchor.

    python3 infra/extrapolate_points.py Schemes/thingom_pq_abse/exp2_search_latency \\
        --anchor 10000 --targets 50000,100000,500000,1000000 \\
        --scale-columns primary_mean,n_eff_mean,entries_traversed_mean

WHY THIS EXISTS
---------------
Ref[41]'s search is O(N) pairings with no early termination, as published. One
run at N=10^6 costs ~11.3 h and the full sweep ~18.7 h (see
``Experiment Configuration/planning/runtime_estimates.csv``), which does not fit
the 24 h-per-track budget. The alternative to an extrapolated curve is no curve
at all beyond N=10^4 -- a baseline that stops after one point tells a reader
less than an extrapolated one that is labelled as extrapolated.

WHAT IT WRITES, AND WHY IT LOOKS UNDER-CLAIMED
----------------------------------------------
Every generated row carries ``n_runs=0`` and a BLANK ci95. That is deliberate
and is the whole point of doing this with a script rather than by hand:

* ``n_runs=0`` is true -- the point was computed, not run. Writing ``30`` would
  put a fabricated sample size in a file whose reader assumes 30 measurements,
  and AGENT_RULES.md's Statistical Integrity check exists to catch exactly that.
* A blank ci95 is true -- a computed point has no variance, so it has no
  confidence interval. ``Plots/generate_plots.py`` renders a blank/single-run
  ci95 as NO error bar rather than a zero-length one, so an extrapolated point
  is visibly bare beside a measured one.

``run_meta.json`` gets an ``extrapolation`` block naming the anchor, the factor
applied to each target and the columns scaled, so any number in the figure can
be traced back to the measured cell it came from.

WHAT IT REFUSES
---------------
* An anchor value not present in results.csv, or present with n_runs < 2.
* A target that already has a row -- overwriting a measured point with a
  computed one is the one mistake this script must never make. Re-running is
  therefore safe: existing rows, measured or generated, are left alone unless
  --replace-generated is passed, which replaces only rows with n_runs=0.

LINEARITY IS AN ASSUMPTION, NOT A FINDING
-----------------------------------------
Scaling by target/anchor assumes cost is exactly proportional to the sweep
variable. That holds for a published O(N) scan; it does NOT hold for a scheme
with caching, batching or a non-linear index. Do not point this script at a
scheme whose complexity you have not checked, and prefer a measured point at
one intermediate value to confirm the slope before trusting the far end.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List


def _read_rows(path: Path) -> tuple[List[Dict[str, str]], List[str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader), list(reader.fieldnames or [])


def _num(value: str) -> float:
    return float((value or "").strip())


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("directory", type=Path,
                    help="experiment directory holding results.csv")
    ap.add_argument("--anchor", required=True,
                    help="measured variable_value to scale FROM")
    ap.add_argument("--targets", required=True,
                    help="comma-separated variable_values to generate")
    ap.add_argument("--scale-columns", default="primary_mean",
                    help="comma-separated *_mean columns that scale linearly "
                         "with the sweep variable. Columns not listed are left "
                         "BLANK rather than guessed at -- a ratio or a mean "
                         "count per record does not scale with N, and writing "
                         "a scaled value for one would be silently wrong.")
    ap.add_argument("--replace-generated", action="store_true",
                    help="regenerate rows that already exist with n_runs=0 "
                         "(never touches a row with n_runs>0)")
    args = ap.parse_args(argv)

    results = args.directory / "results.csv"
    if not results.exists():
        sys.exit(f"{results}: no such file")

    rows, fieldnames = _read_rows(results)
    if not rows:
        sys.exit(f"{results}: no rows")

    by_value = {r["variable_value"].strip(): r for r in rows}

    anchor = by_value.get(args.anchor.strip())
    if anchor is None:
        sys.exit(f"anchor {args.anchor} is not a row in {results}; "
                 f"have {sorted(by_value)}")
    anchor_n = int(_num(anchor.get("n_runs", "0")) or 0)
    if anchor_n < 2:
        sys.exit(f"anchor {args.anchor} has n_runs={anchor_n}; refusing to "
                 "extrapolate from a point that is not itself measured")

    scale_cols = [c.strip() for c in args.scale_columns.split(",") if c.strip()]
    unknown = [c for c in scale_cols if c not in fieldnames]
    if unknown:
        sys.exit(f"--scale-columns names {unknown}, not in {fieldnames}")

    anchor_x = _num(anchor["variable_value"])
    generated: Dict[str, float] = {}

    for target in [t.strip() for t in args.targets.split(",") if t.strip()]:
        existing = by_value.get(target)
        if existing is not None:
            existing_n = int(_num(existing.get("n_runs", "0")) or 0)
            if existing_n > 0:
                print(f"  {target}: already MEASURED (n_runs={existing_n}) — left alone")
                continue
            if not args.replace_generated:
                print(f"  {target}: already generated — pass --replace-generated to redo")
                continue

        factor = _num(target) / anchor_x
        row = {name: "" for name in fieldnames}
        row["variable_value"] = target
        for col in scale_cols:
            row[col] = f"{_num(anchor[col]) * factor:.6g}"
        row["n_runs"] = "0"
        by_value[target] = row
        generated[target] = factor
        print(f"  {target}: x{factor:g} from {args.anchor}  "
              f"({scale_cols[0]}={row[scale_cols[0]]})")

    if not generated:
        print("nothing to do")
        return 0

    ordered = sorted(by_value.values(), key=lambda r: _num(r["variable_value"]))
    with results.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ordered)

    meta_path = args.directory / "run_meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["extrapolation"] = {
            "anchor_variable_value": args.anchor,
            "anchor_n_runs": anchor_n,
            "scaled_columns": scale_cols,
            "factors": generated,
            "model": "linear in the sweep variable",
            "note": "Rows with n_runs=0 are COMPUTED from the anchor, not "
                    "measured. They carry no confidence interval because they "
                    "have no variance. Disclose in section V.",
        }
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        print(f"  -> provenance recorded in {meta_path}")

    print(f"  -> {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
