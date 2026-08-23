"""Experiment execution framework for Guo VDSSE.

Handles the mechanical parts of running benchmark experiments per README §7:
  - Warm-up discarding (5 runs)
  - Per-run recording to raw_runs.csv
  - Aggregation to results.csv (mean ± 95% CI from 30 retained runs)
  - run_meta.json provenance

NO scheme logic lives here — the harness is agnostic to what is being
measured.  Each experiment module supplies a runner function; this module
calls it the right number of times and records the output.
"""

from __future__ import annotations

import csv
import json
import math
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from Common.crypto import config as crypto_config
from Common.crypto import environment_report
from Dataset import corpus


# =====================================================================
# Per-run result
# =====================================================================


@dataclass
class RunResult:
    """One measured run.  Created by the runner function."""

    variable_value: Any = None
    run_id: int = 0
    primary_metric: float = 0.0  # in ms
    secondary_metrics: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"


# =====================================================================
# Timing utility
# =====================================================================


def measure_ns(fn: Callable[[], Any]) -> tuple[float, Any]:
    """Time a zero-argument callable.

    Returns (elapsed_ms, fn_return_value).
    Uses ``time.perf_counter_ns()`` per README §7.
    """
    start = time.perf_counter_ns()
    result = fn()
    elapsed_ns = time.perf_counter_ns() - start
    return elapsed_ns / 1_000_000.0, result


# =====================================================================
# Experiment runner
# =====================================================================


def run_experiment(
    variable_values: List[Any],
    runner_fn: Callable[[Any], RunResult],
    *,
    runs: int = 30,
    warmup: int = 5,
) -> List[RunResult]:
    """Execute one experiment over a sweep of variable values.

    For each value in ``variable_values``:
      1. Execute ``warmup`` iterations (discarded).
      2. Execute ``runs`` iterations (retained).
      3. Record every retained run.

    ``runner_fn(value)`` is called each time and must return a RunResult
    with ``primary_metric`` and ``secondary_metrics`` populated.

    The warm-up / retained split follows README §7:
      "30 runs per point after 5 discarded warm-ups."
    """
    all_results: List[RunResult] = []
    for val in variable_values:
        for iteration in range(1, warmup + runs + 1):
            result = runner_fn(val)
            if iteration <= warmup:
                continue  # discard warm-up
            result.variable_value = val
            result.run_id = iteration - warmup
            all_results.append(result)
    return all_results


# =====================================================================
# CSV output — raw_runs.csv
# =====================================================================


def write_raw_runs(
    path: Path,
    experiment_name: str,
    results: List[RunResult],
    secondary_names: List[str],
) -> None:
    """Write raw_runs.csv — one row per run, never aggregated (README §9)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    sec_cols = [f"secondary_metric_{i + 1}" for i in range(len(secondary_names))]
    fieldnames = [
        "scheme",
        "experiment",
        "variable_value",
        "run_id",
        "primary_metric",
    ] + sec_cols + ["status"]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row: Dict[str, Any] = {
                "scheme": "guo_vdsse",
                "experiment": experiment_name,
                "variable_value": r.variable_value,
                "run_id": r.run_id,
                "primary_metric": f"{r.primary_metric:.6f}",
                "status": r.status,
            }
            for i, name in enumerate(sec_cols):
                val = r.secondary_metrics.get(secondary_names[i], "")
                row[name] = val if val != "" else ""
            writer.writerow(row)


# =====================================================================
# CSV output — results.csv
# =====================================================================


def aggregate_results(
    results: List[RunResult],
    secondary_names: List[str],
) -> List[Dict[str, Any]]:
    """Aggregate raw runs into mean ± 95% CI (README §7).

    Uses the t-distribution with df = n-1 for the confidence interval,
    computed via scipy.stats.t.  No hardcoded t-values.
    """
    from scipy import stats as scipy_stats

    # Group by variable_value
    groups: Dict[Any, List[RunResult]] = {}
    for r in results:
        groups.setdefault(r.variable_value, []).append(r)

    aggregated: List[Dict[str, Any]] = []
    for val in sorted(groups.keys(), key=lambda v: (isinstance(v, str), v)):
        runs = groups[val]
        n = len(runs)

        # Primary metric
        p_vals = [r.primary_metric for r in runs]
        mean_p = sum(p_vals) / n
        ci_p = _ci95(p_vals, n, scipy_stats)

        row: Dict[str, Any] = {
            "variable_value": val,
            "primary_mean": round(mean_p, 6),
            "primary_ci95": round(ci_p, 6),
        }

        # Secondary metrics
        for sname in secondary_names:
            s_vals = [
                r.secondary_metrics[sname]
                for r in runs
                if sname in r.secondary_metrics
                and r.secondary_metrics[sname] != ""
            ]
            if s_vals and all(isinstance(v, (int, float)) for v in s_vals):
                mean_s = sum(s_vals) / len(s_vals)
                ci_s = _ci95(s_vals, len(s_vals), scipy_stats)
                row[f"{sname}_mean"] = round(mean_s, 6)
                row[f"{sname}_ci95"] = round(ci_s, 6)
            else:
                row[f"{sname}_mean"] = ""
                row[f"{sname}_ci95"] = ""

        row["n_runs"] = n
        aggregated.append(row)

    return aggregated


def _ci95(values: List[float], n: int, scipy_stats: Any) -> float:
    """95% confidence interval half-width from n samples."""
    if n <= 1:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std = math.sqrt(variance)
    t_val = scipy_stats.t.ppf(0.975, df=n - 1)
    return t_val * std / math.sqrt(n)


def write_results(path: Path, aggregated: List[Dict[str, Any]]) -> None:
    """Write results.csv — aggregated format consumed by generate_plots.py."""
    if not aggregated:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(aggregated[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in aggregated:
            writer.writerow(row)


# =====================================================================
# run_meta.json
# =====================================================================


def write_run_meta(
    path: Path,
    manifest: Dict[str, Any],
    experiment_name: str,
) -> None:
    """Write run_meta.json — provenance per README §7."""
    meta = {
        "scheme": "guo_vdsse",
        "experiment": experiment_name,
        "git_commit": corpus.git_commit(),
        "python_version": sys.version.split()[0],
        "dataset_sha256": manifest.get("corpus_sha256", ""),
        "corpus_type": manifest.get("corpus_type", ""),
        "config_hashes": crypto_config.config_hashes(),
        "utc_start_time": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "environment": environment_report(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
