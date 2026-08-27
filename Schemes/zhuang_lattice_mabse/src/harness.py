"""Experiment measurement harness for Ref[52].

Shared utilities for all five experiments (1, 2, 3, 5, 6):
    • Measurement loop with warm-up
    • CSV writers for raw_runs.csv and results.csv
    • run_meta.json generation
    • 95% CI computation via Student's t

Methodology follows README §7:
    • 30 measured runs after 5 discarded warm-ups
    • time.perf_counter_ns() for latency
    • All runs retained (no outlier deletion)
    • Provenance in run_meta.json
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np
from scipy import stats


SCHEME_NAME = "zhuang_lattice_mabse"
DEFAULT_WARMUP = 5
DEFAULT_RUNS = 30


@dataclass
class RunResult:
    """One row in raw_runs.csv."""

    variable_value: Any
    run_id: int
    primary_metric: float
    secondary_1: Optional[float] = None
    secondary_2: Optional[float] = None
    status: str = "ok"


def measure_latency_ns(
    func: Callable[[], Tuple[float, ...]],
    warmup: int = DEFAULT_WARMUP,
    runs: int = DEFAULT_RUNS,
    variable_value: Any = 0,
) -> List[RunResult]:
    """Run a measurement loop and return per-run results.

    ``func`` returns ``(primary, secondary_1, secondary_2, ...)`` where
    primary is the value to record (e.g. latency in ms) and secondaries
    are optional.

    The function itself should do its own timing with perf_counter_ns().
    """
    results: List[RunResult] = []

    # Warm-up (discarded)
    for _ in range(warmup):
        try:
            func()
        except Exception:
            pass

    # Measured runs
    for run_id in range(1, runs + 1):
        try:
            metrics = func()
            if not isinstance(metrics, (tuple, list)):
                metrics = (metrics,)
            result = RunResult(
                variable_value=variable_value,
                run_id=run_id,
                primary_metric=float(metrics[0]),
                secondary_1=float(metrics[1]) if len(metrics) > 1 else None,
                secondary_2=float(metrics[2]) if len(metrics) > 2 else None,
                status="ok",
            )
        except Exception as e:
            result = RunResult(
                variable_value=variable_value,
                run_id=run_id,
                primary_metric=0.0,
                status=f"failed: {e}",
            )
        results.append(result)

    return results


def aggregate_results(
    runs: List[RunResult],
) -> Dict[Any, Dict[str, float]]:
    """Group by variable_value, compute mean and 95% CI.

    Uses the t-distribution for the CI, which is correct for small n.
    """
    from collections import defaultdict

    groups: Dict[Any, List[RunResult]] = defaultdict(list)
    for r in runs:
        if r.status == "ok":
            groups[r.variable_value].append(r)

    aggregated: Dict[Any, Dict[str, float]] = {}

    for var_val, group_runs in sorted(groups.items(), key=lambda x: float(x[0])):
        primaries = [r.primary_metric for r in group_runs]
        n = len(primaries)

        if n == 0:
            continue

        mean = float(np.mean(primaries))
        if n > 1:
            ci = float(stats.t.interval(0.95, n - 1, loc=mean, scale=stats.sem(primaries))[1] - mean)
        else:
            ci = 0.0

        row: Dict[str, float] = {
            "primary_mean": mean,
            "primary_ci95": ci,
            "n_runs": n,
        }

        # Secondary metrics
        sec1 = [r.secondary_1 for r in group_runs if r.secondary_1 is not None]
        if sec1:
            row["secondary_1_mean"] = float(np.mean(sec1))
            row["secondary_1_ci95"] = (
                float(stats.t.interval(0.95, len(sec1) - 1, loc=np.mean(sec1), scale=stats.sem(sec1))[1] - np.mean(sec1))
                if len(sec1) > 1 else 0.0
            )

        sec2 = [r.secondary_2 for r in group_runs if r.secondary_2 is not None]
        if sec2:
            row["secondary_2_mean"] = float(np.mean(sec2))
            row["secondary_2_ci95"] = (
                float(stats.t.interval(0.95, len(sec2) - 1, loc=np.mean(sec2), scale=stats.sem(sec2))[1] - np.mean(sec2))
                if len(sec2) > 1 else 0.0
            )

        aggregated[var_val] = row

    return aggregated


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def write_raw_runs(path: Path, experiment: str, runs: List[RunResult]) -> None:
    """Write raw_runs.csv — one row per run, per README §9."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scheme", "experiment", "variable_value", "run_id",
            "primary_metric", "secondary_metric_1", "secondary_metric_2", "status",
        ])
        for r in runs:
            writer.writerow([
                SCHEME_NAME, experiment, r.variable_value, r.run_id,
                f"{r.primary_metric:.6f}",
                f"{r.secondary_1:.6f}" if r.secondary_1 is not None else "",
                f"{r.secondary_2:.6f}" if r.secondary_2 is not None else "",
                r.status,
            ])


def write_results(path: Path, aggregated: Dict[Any, Dict[str, float]]) -> None:
    """Write results.csv — aggregated means with 95% CI, per README §9."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "variable_value", "primary_mean", "primary_ci95",
            "secondary_1_mean", "secondary_1_ci95",
            "secondary_2_mean", "secondary_2_ci95",
            "n_runs",
        ])
        for var_val, row in aggregated.items():
            writer.writerow([
                var_val,
                f"{row['primary_mean']:.6f}",
                f"{row['primary_ci95']:.6f}",
                f"{row.get('secondary_1_mean', ''):.6f}" if "secondary_1_mean" in row else "",
                f"{row.get('secondary_1_ci95', ''):.6f}" if "secondary_1_ci95" in row else "",
                f"{row.get('secondary_2_mean', ''):.6f}" if "secondary_2_mean" in row else "",
                f"{row.get('secondary_2_ci95', ''):.6f}" if "secondary_2_ci95" in row else "",
                int(row["n_runs"]),
            ])


def write_run_meta(path: Path, experiment: str, extra: Optional[Dict] = None) -> None:
    """Write run_meta.json — provenance per README §7."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Git commit
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        git_commit = "unknown"

    # Dataset SHA-256
    from Common.crypto.config import load_dataset_config
    try:
        ds_cfg = load_dataset_config()
        dataset_sha = ds_cfg.get("freeze", {}).get("expected_corpus_sha256", "unknown")
    except Exception:
        dataset_sha = "unknown"

    # Config hashes
    from Common.crypto.config import config_hashes
    try:
        cfg_hashes = config_hashes()
    except Exception:
        cfg_hashes = {}

    # Environment, including experiment-host verification (README §1) —
    # best-effort like the fields above, since this must not block a dev run.
    from Common.crypto import environment_report
    try:
        environment = environment_report()
    except Exception:
        environment = {}

    meta = {
        "scheme": SCHEME_NAME,
        "experiment": experiment,
        "git_commit": git_commit,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "dataset_sha256": dataset_sha,
        "config_hashes": cfg_hashes,
        "environment": environment,
        "utc_start_time": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        meta.update(extra)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)
