#!/usr/bin/env python3
"""Run a scheme at its largest sweep point and record PEAK MEMORY and time.

Why this exists
---------------
Every defect in the 2026-08-29 campaign was invisible below real scale. The
651-test suite passed throughout -- it uses toy data. The 20,000-record dev
corpus passed too, and is actively misleading: it carries 13,227 keywords at
11.2 per record against corpus v4's 2,023 at 31.70, so anything whose cost
scales with keyword density reads ~6.5x low. The failures cost 8.7 fleet-hours
and an entire scheme's results.

`runtime_estimates.csv` could not have caught them either: it has no memory
column at all. It models time, and time was never the problem.

So this gate asks the one question nothing else asks -- "does the largest point
this scheme will actually run fit in the host it will actually run on?" -- under
the conditions the campaign will use.

Method
------
The scheme runs in a child process; RSS is sampled from OUTSIDE it. Nothing is
instrumented inside the measured path, so the gate cannot perturb the latency
the campaign reports. Peak RSS is compared against the host's real memory.

Fairness
--------
This measures; it does not tune. It may justify a cap or a larger host. It may
NOT justify optimising one scheme and not the others -- that asymmetry is what
is a bias defect. And it gates on memory only: memory is a
hardware limit, slowness is a finding, and refusing a scheme for being slow
would shape which results exist.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]  # .../<repo>/.claude/skills/<skill>/scripts/x.py

# Largest point each scheme will actually run, and the experiment that runs it.
# Kept here rather than derived, so the gate states its own scope explicitly.
LARGEST = {
    "ma_lb_pq_vdse":    ("2", None),
    "guo_vdsse":        ("2", None),
    "thingom_pq_abse":  ("2", None),
    "perera_lv_pqabse": ("2", None),
    "yue_ge":           ("2", "1000000"),
}
WARMUP_FLAG = {"ma_lb_pq_vdse": "--warmups", "thingom_pq_abse": "--warmups"}
NEEDS_DATASET = {"ma_lb_pq_vdse", "thingom_pq_abse"}


def host_memory_gb() -> float:
    try:
        import psutil
        return psutil.virtual_memory().total / 1e9
    except Exception:
        return 0.0


def sample_peak_rss(proc: subprocess.Popen, interval: float = 2.0) -> float:
    """Peak RSS of the child and its descendants, in GB. Sampled externally."""
    try:
        import psutil
    except ImportError:
        return -1.0
    peak = 0.0
    try:
        p = psutil.Process(proc.pid)
    except Exception:
        return -1.0
    while proc.poll() is None:
        try:
            rss = p.memory_info().rss
            for c in p.children(recursive=True):
                try:
                    rss += c.memory_info().rss
                except Exception:
                    pass
            peak = max(peak, rss)
        except Exception:
            break
        time.sleep(interval)
    return peak / 1e9


def gate(scheme: str, runs: int, headroom: float) -> dict:
    exp, points = LARGEST[scheme]
    cmd = [sys.executable, "-m", f"Schemes.{scheme}.src.main",
           "--experiment", exp, "--runs", str(runs),
           WARMUP_FLAG.get(scheme, "--warmup"), "1"]
    if points:
        cmd += ["--points", points]
    if scheme in NEEDS_DATASET:
        cmd += ["--dataset", "Dataset/derived"]

    print(f"  {scheme}: exp{exp}" + (f" --points {points}" if points else ""))
    started = time.time()
    proc = subprocess.Popen(cmd, cwd=REPO, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    peak = sample_peak_rss(proc)
    rc = proc.wait()
    elapsed = time.time() - started

    total = host_memory_gb()
    # OOM shows as SIGKILL; the sampler also misses the final spike, so a kill
    # is reported as a failure regardless of the peak observed.
    oom = rc in (137, -9)
    fits = (not oom) and rc == 0 and (total == 0 or peak + headroom <= total)
    return {
        "scheme": scheme, "experiment": exp, "points": points,
        "rc": rc, "oom": oom,
        "peak_rss_gb": round(peak, 2), "host_mem_gb": round(total, 1),
        "headroom_gb": round(total - peak, 2) if total else None,
        "elapsed_s": round(elapsed, 1),
        "verdict": "PASS" if fits else ("OOM" if oom else "OVER-BUDGET"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scheme", action="append",
                    help="scheme to gate (repeatable); default: all")
    ap.add_argument("--runs", type=int, default=2,
                    help="measured runs; the gate sizes SETUP, which dominates")
    ap.add_argument("--headroom", type=float, default=2.0,
                    help="GB that must remain free; running near saturation "
                         "contaminates latency with GC and page-cache effects")
    ap.add_argument("--out", type=Path,
                    default=REPO / "Experiment Configuration/planning/scale_gate.json")
    a = ap.parse_args()

    schemes = a.scheme or list(LARGEST)
    print(f"scale gate — host has {host_memory_gb():.1f} GB, "
          f"requiring {a.headroom} GB headroom\n")
    print("  ONE SCHEME AT A TIME: RSS measured on a loaded machine is "
          "compressed away and reads low.\n")

    results = [gate(s, a.runs, a.headroom) for s in schemes]
    print(f"\n{'scheme':<20}{'peak':>9}{'host':>8}{'free':>8}{'time':>9}  verdict")
    for r in results:
        print(f"{r['scheme']:<20}{r['peak_rss_gb']:>8.2f}G{r['host_mem_gb']:>7.0f}G"
              f"{(r['headroom_gb'] or 0):>7.2f}G{r['elapsed_s']:>8.0f}s  {r['verdict']}")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {a.out.relative_to(REPO)}")

    bad = [r for r in results if r["verdict"] != "PASS"]
    if bad:
        print("\nDO NOT LAUNCH. Fix or cap these first:")
        for r in bad:
            print(f"  - {r['scheme']} exp{r['experiment']}: {r['verdict']} "
                  f"(peak {r['peak_rss_gb']} GB of {r['host_mem_gb']} GB)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
