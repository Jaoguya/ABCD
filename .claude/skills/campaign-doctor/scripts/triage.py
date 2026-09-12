#!/usr/bin/env python3
"""Classify what failed across the fleet, by signature rather than by reading logs.

Reading nine logs by hand is slow and mis-remembers. This pulls every node's
exit code and failure lines, groups them by SIGNATURE, and names the likely
cause -- so one bug affecting four experiments of one scheme is reported as one
bug, not four.

Read-only. Never starts, stops or modifies an instance.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import re
import subprocess

SSH = ["ssh", "-i", "~/.ssh/ojcoms.pem", "-o", "ConnectTimeout=20",
       "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]

# Signature -> (what it means, what to do). Learned on this project.
CAUSES = [
    (r"rc=137|Killed process|Out of memory",
     "OOM — the index exceeded host memory",
     "scope the build to skill.md index_size, or cap the sweep and disclose. "
     "Check --points reaches the PRE-BUILD loop, not just run_experiment."),
    (r"MemoryError",
     "allocation refused before the kernel intervened",
     "same as OOM; look for a structure held across sweep points"),
    (r"No module named|ImportError|ModuleNotFoundError",
     "missing dependency on this node",
     "re-provision, or the venv is not the one the runner uses"),
    (r"no pairing backend|charm|PairingUnavailable",
     "pairing backend absent",
     "charm-crypto is Linux-only; this scheme cannot run off the experiment host"),
    (r"KEMUnavailable|no ML-KEM|no ML-DSA",
     "post-quantum backend absent",
     "check Common/crypto/kem.py and signature.py backend probing"),
    (r"does not match dataset\.yaml|corpus SHA-256",
     "wrong corpus on this node",
     "regenerate v4 from the node's own Synthea CSVs (deterministic) rather "
     "than copying 687 MB"),
    (r"--points names .* which this experiment does not sweep",
     "a shard asked for a point the sweep does not contain",
     "a typo would silently run zero points; the selector refuses instead"),
    (r"rc=(?!0|137)\d+",
     "non-zero exit, cause not yet classified",
     "read that node's log tail"),
]


def run(host: str, cmd: str) -> str:
    try:
        out = subprocess.run(
            [a.replace("~", str(__import__("pathlib").Path.home())) for a in SSH]
            + [f"ubuntu@{host}", cmd],
            capture_output=True, text=True, timeout=60)
        return out.stdout
    except Exception as exc:  # noqa: BLE001 - unreachable is a finding
        return f"__UNREACHABLE__ {exc}"


def probe(host: str, pattern: str) -> dict:
    out = run(host, f'for L in ~/{pattern}; do [ -f "$L" ] || continue;'
                    f' echo "@@ $L"; grep -E "JOB FAILED|rc=" "$L" | tail -5;'
                    f' tail -3 "$L"; done')
    return {"host": host, "text": out}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hosts", required=True,
                    help="space- or comma-separated public IPs")
    ap.add_argument("--pattern", default="*.log",
                    help="log glob on each node (e.g. 'guo2-node*.log')")
    a = ap.parse_args()
    hosts = [h for h in re.split(r"[,\s]+", a.hosts.strip()) if h]

    with cf.ThreadPoolExecutor(max_workers=min(12, len(hosts))) as ex:
        found = list(ex.map(lambda h: probe(h, a.pattern), hosts))

    buckets: dict[str, list[str]] = collections.defaultdict(list)
    clean, unreachable = [], []
    for r in found:
        if "__UNREACHABLE__" in r["text"]:
            unreachable.append(r["host"]); continue
        hit = False
        for pat, meaning, action in CAUSES:
            for line in r["text"].splitlines():
                if re.search(pat, line):
                    buckets[f"{meaning}||{action}"].append(f"{r['host']}: {line.strip()[:78]}")
                    hit = True
                    break
            if hit:
                break
        if not hit:
            clean.append(r["host"])

    print(f"{len(hosts)} node(s): {len(clean)} clean, "
          f"{sum(len(v) for v in buckets.values())} failing, "
          f"{len(unreachable)} unreachable\n")
    if unreachable:
        print("UNREACHABLE (often a rotated egress IP, not a dead node):")
        for h in unreachable:
            print(f"  {h}")
        print("  fix: authorize-security-group-ingress for $(curl -s "
              "https://checkip.amazonaws.com)/32\n")
    for key, lines in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        meaning, action = key.split("||")
        print(f"[{len(lines)} node(s)] {meaning}")
        print(f"    -> {action}")
        for ln in lines[:4]:
            print(f"       {ln}")
        if len(lines) > 4:
            print(f"       ... +{len(lines)-4} more")
        print()
    if clean:
        print(f"clean: {', '.join(clean)}")
    return 1 if buckets else 0


if __name__ == "__main__":
    raise SystemExit(main())
