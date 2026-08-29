#!/usr/bin/env python3
"""Status line: existing segments, plus campaign progress on the right.

Composes rather than replaces. It runs whatever status-line command was already
configured (default: the statusline-tokens one), then appends a campaign
segment, so context-window usage is not lost.

Speed is the whole design constraint. This never touches AWS or SSH -- it reads
the snapshot `probe.py` leaves in ~/.cache/ojcoms-campaign.json. A missing or
stale cache degrades to a dim hint instead of stalling the prompt.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

CACHE = Path.home() / ".cache" / "ojcoms-campaign.json"
INNER = os.environ.get(
    "CAMPAIGN_STATUS_INNER",
    str(Path.home() / ".claude/skills/statusline-tokens/statusline.py"),
)
STALE_S = 600  # older than this and the numbers are not worth trusting

R, DIM, GRN, YEL, RED, CYN = ("\033[0m", "\033[2m", "\033[32m",
                              "\033[33m", "\033[31m", "\033[36m")


def inner_line(payload: str) -> str:
    if not Path(INNER).exists():
        return ""
    try:
        out = subprocess.run([sys.executable, INNER], input=payload,
                             capture_output=True, text=True, timeout=3)
        return out.stdout.strip()
    except Exception:
        return ""


def campaign_segment() -> str:
    try:
        d = json.loads(CACHE.read_text())
    except Exception:
        return f"{DIM}campaign: run probe.py{R}"

    age = time.time() - d.get("ts", 0)
    stale = age > STALE_S

    running, busy = d.get("running", 0), d.get("busy", 0)
    total = running + d.get("stopped", 0)
    burn = d.get("burn_hr", 0.0)
    res, rep = d.get("results", 0), d.get("reportable", 0)

    if running == 0:
        fleet = f"{DIM}fleet idle{R}"
    elif busy:
        fleet = f"{GRN}▶ {busy}/{running} busy{R}"
    else:
        # Running but nothing working is the expensive state, so it is loud.
        fleet = f"{RED}⚠ {running} up, idle{R}"

    cost = (f"{RED if burn >= 1 else YEL}${burn:.2f}/hr{R}"
            if burn else f"{DIM}$0{R}")
    results = (f"{GRN}{rep}{R}{DIM}/{res} rep{R}" if res
               else f"{DIM}no results{R}")
    parts = [fleet, cost, results, f"{DIM}{total} inst{R}"]
    if stale:
        parts.append(f"{DIM}({int(age/60)}m old){R}")
    return f" {DIM}·{R} ".join(parts)


def main() -> int:
    payload = ""
    try:
        payload = sys.stdin.read()
    except Exception:
        pass

    left = inner_line(payload)
    right = campaign_segment()

    width = shutil.get_terminal_size((120, 24)).columns
    def visible(s: str) -> int:
        out, i = 0, 0
        while i < len(s):
            if s[i] == "\033":
                while i < len(s) and s[i] != "m":
                    i += 1
            else:
                out += 1
            i += 1
        return out

    pad = width - visible(left) - visible(right) - 1
    print(f"{left}{' ' * pad}{right}" if pad > 1 else f"{left} {DIM}|{R} {right}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
