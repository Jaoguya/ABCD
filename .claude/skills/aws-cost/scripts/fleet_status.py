#!/usr/bin/env python3
"""What is running on the benchmark fleet right now, and how far along.

    python3 .claude/skills/aws-cost/scripts/fleet_status.py
    python3 .claude/skills/aws-cost/scripts/fleet_status.py --watch

Answers "is anything actually running, and will it finish?" without having to
ask. For each reachable project instance it reports the experiment processes it
finds, how long they have been going, whether they are actually consuming CPU,
and — where the runner prints progress — how far through they are.

SCOPE: Project=OJCOMS only. Never touches instances belonging to other
projects (see SKILL.md). Read-only: it inspects and reports, and never starts,
stops or kills anything.
"""

from __future__ import annotations

import argparse
import json
import re
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

# expanduser: subprocess runs ssh WITHOUT a shell, so a literal "~"
# is never expanded and ssh silently falls back to other keys/agent.
KEY = os.path.expanduser("~/.ssh/ojcoms.pem")
PROJECT_TAG = "Project=OJCOMS"

# Log lines the runners actually emit, so progress is read rather than guessed.
PROGRESS_PATTERNS = [
    # lambda_sweep.py: "  400/1001"
    re.compile(r"^\s*(?P<done>\d+)/(?P<total>\d+)\s*$"),
    # main.py sweep points: "  domains=6: 1.05 ± ... (n=1)"
    re.compile(r"^\s*(?P<label>\w+)=(?P<value>[\w.]+):\s"),
]
LOG_CANDIDATES = [
    "/tmp/sweep.log", "/tmp/campaign.log", "/tmp/regen10.log",
    "/tmp/thingom_cli_test.log", "/tmp/guo_smoke.log",
]


def sh(cmd: List[str], timeout: int = 30) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def project_instances() -> List[Dict[str, str]]:
    code, out = sh([
        "aws", "ec2", "describe-instances",
        "--filters", f"Name=tag:{PROJECT_TAG.split('=')[0]},"
                     f"Values={PROJECT_TAG.split('=')[1]}",
        "--query", "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,"
                   "Ip:PublicIpAddress,State:State.Name}",
        "--output", "json",
    ], timeout=60)
    if code != 0:
        print(f"could not list instances: {out.strip()[:200]}", file=sys.stderr)
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    flat: List[Dict[str, str]] = []
    for group in data:
        flat.extend(group)
    return flat


def remote(ip: str, script: str, timeout: int = 30) -> Optional[str]:
    code, out = sh(
        ["ssh", "-i", KEY, "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=accept-new", f"ubuntu@{ip}", script],
        timeout=timeout,
    )
    return out if code == 0 else None


def inspect(ip: str) -> List[str]:
    """Processes + progress for one host, as display lines."""
    # etime and %cpu together distinguish "working" from "stuck": a process at
    # ~0% CPU that has been up for a while is not progressing, which is exactly
    # the state that has wasted time on this project before.
    out = remote(ip, (
        "ps -eo etime,pcpu,args --no-headers | "
        "grep -E 'src\\.main|lambda_sweep|prepare_dataset|generate_plots|pytest' | "
        "grep -v grep || true; "
        "echo '---LOGS---'; "
        + "; ".join(
            f"[ -f {p} ] && echo 'LOG {p}' && tail -n 3 {p}" for p in LOG_CANDIDATES
        ) + " || true"
    ))
    if out is None:
        return ["  unreachable (stopped, or SSH blocked by your current IP)"]

    procs_part, _, logs_part = out.partition("---LOGS---")
    lines: List[str] = []

    procs = [l for l in procs_part.splitlines() if l.strip()]
    if not procs:
        lines.append("  no experiment process running")
    for line in procs:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        etime, cpu, cmd = parts
        short = cmd[:66] + ("..." if len(cmd) > 66 else "")
        try:
            idle = float(cpu) < 5.0
        except ValueError:
            idle = False
        flag = "  <-- ~0% CPU, may be stalled" if idle else ""
        lines.append(f"  [{etime:>9}] {float(cpu):5.1f}% {short}{flag}")

    # Progress, read from whichever log the runner is writing.
    current_log = None
    for raw in logs_part.splitlines():
        if raw.startswith("LOG "):
            current_log = raw[4:].strip()
            continue
        text = raw.strip()
        if not text or current_log is None:
            continue
        m = PROGRESS_PATTERNS[0].match(raw)
        if m:
            done, total = int(m.group("done")), int(m.group("total"))
            pct = 100.0 * done / max(total, 1)
            lines.append(f"      progress {done}/{total} ({pct:.0f}%)  [{current_log}]")
    return lines


def snapshot() -> None:
    rows = project_instances()
    if not rows:
        print("no Project=OJCOMS instances found")
        return
    running = [r for r in rows if r.get("State") == "running"]
    stopped = [r for r in rows if r.get("State") != "running"]
    print(f"{len(running)} running, {len(stopped)} stopped "
          f"({time.strftime('%H:%M:%S')})\n")
    for inst in sorted(running, key=lambda r: r.get("Name") or ""):
        print(f"{inst.get('Name') or '?'}  {inst.get('Ip') or '-'}")
        for line in inspect(inst["Ip"]) if inst.get("Ip") else ["  no public IP"]:
            print(line)
        print()
    if stopped:
        names = ", ".join(sorted({r.get("Name") or "?" for r in stopped}))
        print(f"stopped: {names} (nothing can be running on these)")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="fleet_status.py",
        description="What is running on the Project=OJCOMS fleet, and how far along.",
    )
    ap.add_argument("--watch", action="store_true",
                    help="refresh every --interval seconds until Ctrl-C")
    ap.add_argument("--interval", type=int, default=60)
    args = ap.parse_args(argv)

    if args.watch:
        try:
            while True:
                print("\033[2J\033[H", end="")  # clear
                snapshot()
                print(f"(refreshing every {args.interval}s — Ctrl-C to stop)")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0
    snapshot()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
