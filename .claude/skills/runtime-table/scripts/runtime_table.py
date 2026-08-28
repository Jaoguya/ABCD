#!/usr/bin/env python3
"""Roll up Experiment Configuration/planning/runtime_estimates.csv into a
per-scheme runtime table, and flag rows that code changes have invalidated.

Two jobs, deliberately in one place:

  1. TOTALS   -- what each scheme costs for a full campaign, against the 24h
                 per-track cap.
  2. STALENESS -- which totals no longer describe the code, because a scheme's
                 sources were committed after its numbers were last validated.

(2) is the whole reason this exists. A runtime table nobody re-derives after a
fix is worse than none: it reads as current and is not. The staleness baseline
lives in state.json next to this script, keyed by scheme -> commit SHA.

Usage:
    runtime_table.py                    # the table
    runtime_table.py --detail           # + per-experiment rows
    runtime_table.py --bless <scheme>   # record: totals now match HEAD
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Repo root: .claude/skills/runtime-table/scripts/ -> up 4.
ROOT = Path(__file__).resolve().parents[4]
CSV_PATH = ROOT / "Experiment Configuration" / "planning" / "runtime_estimates.csv"
GLOBAL_YAML = ROOT / "Experiment Configuration" / "global.yaml"
STATE_PATH = Path(__file__).resolve().parent.parent / "state.json"

BUDGET_H = 24.0  # README/user constraint: 24h maximum per scheme track.

# Rows that restate other rows. Summing these double-counts. `TOTAL` appears in
# the experiment column, `SUBTOTAL` in sweep_value -- both conventions are
# already in the file, so both are matched.
AGGREGATE_TOKENS = {"TOTAL", "SUBTOTAL"}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_rows() -> List[Dict[str, Any]]:
    """Parse the estimates CSV.

    Hand-tolerant on purpose: several existing rows carry unquoted commas
    inside `notes`, so they parse to 13 or 15 fields against a 12-field
    header. Everything from column 11 on is rejoined as the note rather than
    dropped -- a stricter reader would silently lose the EXCLUDED/SUPERSEDED
    rationale, which is the most decision-relevant text in the file.
    """
    if not CSV_PATH.exists():
        sys.exit(f"missing {CSV_PATH.relative_to(ROOT)}")

    with CSV_PATH.open(newline="", encoding="utf-8") as fh:
        raw = list(csv.reader(fh))
    if not raw:
        sys.exit("estimates CSV is empty")

    header = raw[0]
    ncol = len(header)
    rows: List[Dict[str, Any]] = []
    for line_no, r in enumerate(raw[1:], start=2):
        if not r or not r[0].strip():
            continue
        rec = {header[i]: (r[i] if i < len(r) else "") for i in range(ncol - 1)}
        rec["notes"] = ",".join(r[ncol - 1:]).strip() if len(r) >= ncol else ""
        rec["_line"] = line_no
        rows.append(rec)
    return rows


def _f(val: str) -> Optional[float]:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def is_aggregate(row: Dict[str, Any]) -> bool:
    return (
        row.get("experiment", "").strip().upper() in AGGREGATE_TOKENS
        or row.get("sweep_value", "").strip().upper() in AGGREGATE_TOKENS
    )


def is_dropped(row: Dict[str, Any]) -> bool:
    """A point deliberately cut from the campaign, not a cost to pay."""
    note = row.get("notes", "").upper()
    return note.startswith(("EXCLUDED", "SUPERSEDED", "DROPPED"))


def exp_keys(label: str) -> set[str]:
    """Canonical experiment numbers a label refers to.

    The CSV and global.yaml name experiments differently, and one CSV row can
    stand for two experiments. Reducing both sides to bare numbers is what
    makes coverage comparable:

        exp2_search_latency -> {2}      (global.yaml)
        build_exp2          -> {2}      (the untimed build carries exp2's cost)
        exp7_8              -> {7, 8}   (README §5: derived from the same runs)
    """
    return set(re.findall(r"\d+", label))


def scheme_experiments() -> Dict[str, List[str]]:
    """scheme -> experiments it participates in, per global.yaml.

    Parsed with a narrow reader rather than a YAML dependency: this skill has
    to run on a bare interpreter on an EC2 host where pyyaml may not be in the
    active venv. Only `experiments:` -> `<name>:` -> `schemes: [...]` is read.
    """
    if not GLOBAL_YAML.exists():
        return {}
    out: Dict[str, List[str]] = {}
    in_experiments = False
    current: Optional[str] = None
    for line in GLOBAL_YAML.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            in_experiments = stripped.startswith("experiments:")
            current = None
            continue
        if not in_experiments:
            continue
        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1]
        elif current and stripped.startswith("schemes:"):
            body = stripped.split(":", 1)[1].strip().strip("[]")
            for name in (s.strip() for s in body.split(",")):
                if name:
                    out.setdefault(name, []).append(current)
    return out


# ---------------------------------------------------------------------------
# Git / staleness
# ---------------------------------------------------------------------------


def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - staleness is advisory, never fatal
        return ""


def last_code_commit(scheme: str) -> tuple[str, str]:
    """(sha, iso-date) of the last commit touching this scheme's sources."""
    out = git("log", "-1", "--format=%H|%cs", "--", f"Schemes/{scheme}")
    if "|" not in out:
        return "", ""
    sha, _, date = out.partition("|")
    return sha, date


def load_state() -> Dict[str, Any]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def commits_between(old: str, new: str, scheme: str) -> int:
    if not old or not new or old == new:
        return 0
    out = git("rev-list", "--count", f"{old}..{new}", "--", f"Schemes/{scheme}")
    try:
        return int(out)
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------


def rollup(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    schemes: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        name = row["scheme"].strip()
        s = schemes.setdefault(
            name,
            {
                "seconds": 0.0,
                "measured_s": 0.0,
                "estimated_s": 0.0,
                "leaf_rows": [],
                "aggregate_rows": [],
                "dropped": 0,
                "not_started": 0,
                "bases": set(),
                "experiments": set(),
                "low_conf": 0,
                "host_caveat": 0,
            },
        )

        basis = row.get("basis", "").strip()
        if basis == "not_started" or (not basis and not row.get("point_total_s")):
            s["not_started"] += 1
            continue

        if is_aggregate(row):
            s["aggregate_rows"].append(row)
            continue
        if is_dropped(row):
            s["dropped"] += 1
            continue

        secs = _f(row.get("point_total_s", "")) or 0.0
        s["seconds"] += secs
        # Sum seconds, not the point_total_h column: that column is rounded to
        # 2dp, and 20+ rounded rows accumulate visible error.
        if basis.upper() == "MEASURED":
            s["measured_s"] += secs
        else:
            s["estimated_s"] += secs
        s["bases"].add(basis)
        s["experiments"].add(row["experiment"].strip())
        s["leaf_rows"].append(row)
        if row.get("confidence", "").strip() == "low":
            s["low_conf"] += 1
        if "macos" in row.get("notes", "").lower():
            s["host_caveat"] += 1
    return schemes


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def bar(hours: float, width: int = 16) -> str:
    if hours <= 0:
        return " " * width
    filled = min(width, max(1, round(width * hours / BUDGET_H)))
    return "█" * filled + "·" * (width - filled)


def render(schemes: Dict[str, Dict[str, Any]], detail: bool) -> None:
    coverage = scheme_experiments()
    state = load_state().get("validated", {})

    print()
    print(f"  RUNTIME BY SCHEME{'':21s}budget {BUDGET_H:.0f}h per scheme track")
    print("  " + "─" * 92)
    print(f"  {'SCHEME':<18}{'TOTAL':>9}  {'MEASURED':>9}  {'EST':>7}   "
          f"{'vs 24h':<18} {'CODE STATUS':<12}")
    print("  " + "─" * 92)

    grand = 0.0
    warnings: List[str] = []

    for name in sorted(schemes, key=lambda k: -schemes[k]["seconds"]):
        s = schemes[name]
        hours = s["seconds"] / 3600.0
        grand += hours

        sha, date = last_code_commit(name)
        blessed = state.get(name, {}).get("commit", "")
        if not sha:
            code = "no sources"
        elif not blessed:
            code = "unvalidated"
            warnings.append(
                f"{name}: totals were never validated against a commit. "
                f"Re-derive, then `--bless {name}`."
            )
        elif blessed == sha:
            code = "current"
        else:
            n = commits_between(blessed, sha, name)
            code = f"STALE +{n}" if n else "STALE"
            warnings.append(
                f"{name}: {n} commit(s) touched Schemes/{name}/ since these "
                f"numbers were validated (last {date}). Totals may be wrong."
            )

        over = " OVER" if hours > BUDGET_H else ""
        print(f"  {name:<18}{hours:>8.2f}h  {s['measured_s']/3600:>8.2f}h  "
              f"{s['estimated_s']/3600:>6.2f}h   {bar(hours)}{over:<5} {code:<12}")

        covered = set().union(*(exp_keys(e) for e in s["experiments"])) \
            if s["experiments"] else set()
        missing = [e for e in coverage.get(name, [])
                   if not (exp_keys(e) & covered)]
        if missing:
            warnings.append(
                f"{name}: no runtime rows for {', '.join(missing)} "
                f"-- the total above is a floor, not a campaign cost."
            )
        if s["dropped"]:
            warnings.append(
                f"{name}: {s['dropped']} sweep point(s) EXCLUDED/SUPERSEDED "
                f"and not counted (deliberate scope cuts -- see notes)."
            )
        if s["host_caveat"]:
            warnings.append(
                f"{name}: {s['host_caveat']} row(s) measured on a macOS arm64 "
                f"dev host, not the pinned m6i.xlarge. Notes say derate ~1.5x."
            )
        if s["low_conf"]:
            warnings.append(
                f"{name}: {s['low_conf']} row(s) at confidence=low.")
        if s["not_started"]:
            warnings.append(f"{name}: not implemented (basis=not_started).")

    print("  " + "─" * 92)
    print(f"  {'SERIAL TOTAL':<18}{grand:>8.2f}h"
          f"{'':>32}{grand/24:.1f} days on one host")
    print(f"  {'':18s}{'':>9}{'':>11}{'':>9}   "
          f"schemes run on separate instances, so wall-clock is the max row, "
          f"not this sum")
    print()

    if detail:
        print("  PER-EXPERIMENT")
        print("  " + "─" * 92)
        for name in sorted(schemes):
            per: Dict[str, float] = {}
            for row in schemes[name]["leaf_rows"]:
                per[row["experiment"]] = per.get(row["experiment"], 0.0) + (
                    _f(row.get("point_total_s", "")) or 0.0)
            if not per:
                continue
            print(f"  {name}")
            for exp in sorted(per, key=lambda e: -per[e]):
                n = sum(1 for r in schemes[name]["leaf_rows"]
                        if r["experiment"] == exp)
                print(f"      {exp:<16}{per[exp]/3600:>8.2f}h   ({n} point(s))")
            print()

    if warnings:
        print("  NEEDS ATTENTION")
        print("  " + "─" * 92)
        for w in warnings:
            print(f"    - {w}")
        print()


def bless(scheme: str) -> None:
    sha, date = last_code_commit(scheme)
    if not sha:
        sys.exit(f"no commits touch Schemes/{scheme}/ -- nothing to validate")
    state = load_state()
    state.setdefault("validated", {})[scheme] = {"commit": sha, "code_date": date}
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    print(f"validated {scheme} against {sha[:12]} ({date})")
    print(f"recorded in {STATE_PATH.relative_to(ROOT)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detail", action="store_true",
                    help="also print per-experiment breakdown")
    ap.add_argument("--bless", metavar="SCHEME",
                    help="record that this scheme's totals match HEAD")
    args = ap.parse_args()

    if args.bless:
        bless(args.bless)
        return
    render(rollup(load_rows()), args.detail)


if __name__ == "__main__":
    main()
