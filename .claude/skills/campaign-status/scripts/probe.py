#!/usr/bin/env python3
"""Collect campaign progress into a cache file the status line can read instantly.

WHY A CACHE
-----------
The status line is re-rendered constantly. It must return in milliseconds, and
querying nine EC2 instances over SSH takes tens of seconds. So this probe runs
separately -- on demand or from a loop -- and writes a small JSON snapshot; the
status line only ever reads that file. A stale or missing cache degrades to
showing nothing rather than blocking the prompt.

WHAT IT COUNTS
--------------
- fleet: how many project instances are running vs stopped, and the burn rate
- jobs:  per running node, whether a scheme process is alive
- done:  results.csv files present locally under Schemes/, and how many carry
         reportable=true -- the number that actually matters for the paper
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]  # .../<repo>/.claude/skills/<skill>/scripts/x.py
CACHE = Path.home() / ".cache" / "ojcoms-campaign.json"
COST_TTL = 6 * 3600   # Cost Explorer costs $0.01/call and lags ~24h
RATE = 0.19  # m6i.xlarge on-demand, us-east-1


def sh(cmd: list[str], timeout: int = 25) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""


def fleet() -> dict:
    out = sh(["aws", "ec2", "describe-instances",
              "--filters", "Name=tag:Project,Values=OJCOMS",
              "--query", "Reservations[].Instances[].[State.Name,PublicIpAddress]",
              "--output", "text"])
    running, stopped, ips = 0, 0, []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "running":
            running += 1
            if len(parts) > 1 and parts[1] != "None":
                ips.append(parts[1])
        elif parts[0] == "stopped":
            stopped += 1
    return {"running": running, "stopped": stopped, "ips": ips,
            "burn_hr": round(running * RATE, 2)}


def busy_nodes(ips: list[str]) -> int:
    """How many running nodes have a scheme process alive."""
    key = str(Path.home() / ".ssh" / "ojcoms.pem")
    busy = 0
    for ip in ips:
        # Match the module path, not a bare string: a probe's own shell would
        # otherwise match and every node would look busy forever -- the bug that
        # kept a finished instance billing.
        out = sh(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no",
                  "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                  f"ubuntu@{ip}", "pgrep -fa 'src\\.main' | grep -v pgrep | wc -l"],
                 timeout=15)
        try:
            busy += 1 if int(out.strip() or 0) > 0 else 0
        except ValueError:
            pass
    return busy


def project_spend(prev: dict, force: bool) -> dict:
    """Project-scoped spend to date, refreshed at most every COST_TTL seconds.

    Cost Explorer charges $0.01 per get-cost-and-usage call and lags up to 24h,
    so polling it often costs money and buys nothing. The previous value is
    carried forward between refreshes.

    Filtered on the Project tag -- the unfiltered query returns the whole
    account, which on this account is ~$14/day of unrelated work and would
    misreport this project's spend by roughly 4x.
    """
    age = time.time() - prev.get("spend_ts", 0)
    if not force and prev.get("spend") is not None and age < COST_TTL:
        return {"spend": prev["spend"], "spend_ts": prev["spend_ts"],
                "spend_from": prev.get("spend_from")}

    import datetime as dt
    end = dt.date.today() + dt.timedelta(days=1)
    start = end - dt.timedelta(days=30)
    out = sh(["aws", "ce", "get-cost-and-usage",
              "--time-period", f"Start={start},End={end}",
              "--granularity", "DAILY", "--metrics", "UnblendedCost",
              "--filter", json.dumps({"Tags": {"Key": "Project",
                                               "Values": ["OJCOMS"],
                                               "MatchOptions": ["EQUALS"]}}),
              "--query", "ResultsByTime[].[TimePeriod.Start,Total.UnblendedCost.Amount]",
              "--output", "text"], timeout=40)
    total, first = 0.0, None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                v = float(parts[1])
            except ValueError:
                continue
            total += v
            if v > 0 and first is None:
                first = parts[0]
    if not out:                       # call failed -- keep the old number
        return {"spend": prev.get("spend"), "spend_ts": prev.get("spend_ts", 0),
                "spend_from": prev.get("spend_from")}
    return {"spend": round(total, 2), "spend_ts": time.time(), "spend_from": first}


def local_results() -> dict:
    total = ok = 0
    for meta in (REPO / "Schemes").glob("*/*/run_meta.json"):
        if not (meta.parent / "results.csv").exists():
            continue
        total += 1
        try:
            if json.loads(meta.read_text()).get("reportable") is True:
                ok += 1
        except Exception:
            pass
    return {"results": total, "reportable": ok}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--cost", action="store_true",
                    help="force a Cost Explorer refresh ($0.01) instead of "
                         "reusing the cached figure")
    args = ap.parse_args()

    try:
        prev = json.loads(CACHE.read_text())
    except Exception:
        prev = {}

    f = fleet()
    snap = {"ts": time.time(), **f, "busy": busy_nodes(f["ips"]) if f["ips"] else 0,
            **local_results(), **project_spend(prev, args.cost)}
    snap.pop("ips", None)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(snap))
    print(json.dumps(snap, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
