"""Experiment execution framework for Guo VDSSE.

Handles the mechanical parts of running benchmark experiments per README §7:
  - Warm-up discarding (5 runs)
  - Per-run recording to raw_runs.csv
  - Aggregation to results.csv (mean ± 95% CI from 10 retained runs)
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
    on_point_complete: Optional[Callable[[Any, List[RunResult]], None]] = None,
) -> List[RunResult]:
    """Execute one experiment over a sweep of variable values.

    For each value in ``variable_values``:
      1. Execute ``warmup`` iterations (discarded).
      2. Execute ``runs`` iterations (retained).
      3. Record every retained run.

    ``runner_fn(value)`` is called each time and must return a RunResult
    with ``primary_metric`` and ``secondary_metrics`` populated.

    The warm-up / retained split follows README §7:
      "10 runs per point after 5 discarded warm-ups."

    ``on_point_complete(value, results_so_far)`` fires after each sweep point
    finishes, so a caller can persist partial results instead of holding the
    whole sweep in memory until the end. Exp. 2's largest point is hours long
    and the process previously wrote NOTHING until every point had finished --
    an interruption at any time threw away everything before it too. That is
    not hypothetical: the 2026-08-29/30 campaign lost ~1 h/node to exactly this
    when guo and yue_ge were stopped mid-build, and a `git reset --hard` on a
    node destroyed guo's completed Exp. 1, 2 and 4 before that.

    It fires BETWEEN points, never inside the timed region -- ``runner_fn`` has
    already returned every run for this value by then -- so the flush I/O
    cannot land in a measurement. Same calls, same order, same retained runs:
    this changes when results reach disk, not what they are.
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
        if on_point_complete is not None:
            # A failed flush must not destroy a sweep that is otherwise fine --
            # the in-memory results are still good and the final write at the
            # end of run() is still coming. Report and carry on.
            try:
                on_point_complete(val, all_results)
            except Exception as exc:  # noqa: BLE001 - never fatal
                print(
                    f"  [warn] partial-result flush failed at {val}: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )
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


def _reportability_blockers(manifest: Dict[str, Any]) -> List[str]:
    """Every condition a quotable guo_vdsse number must satisfy.

    ADDED 2026-08-29. guo was the ONLY scheme whose run_meta.json carried no
    `reportable` field at all, so its numbers could not be audited the way the
    other four can — there was no recorded statement that a run used the pinned
    host and the frozen corpus. A baseline held to a weaker standard than the
    proposed scheme biases the comparison in the proposed scheme's favour,
    which is a bias defect; this mirrors
    ma_lb_pq_vdse's provenance.reportability() rather than inventing a looser
    rule.

    Ref[35] is symmetric-only (SHA-256, HMAC, AES, a GGM punctured PRF), so
    there is no pairing or post-quantum backend condition to check — that
    failure mode is structurally absent here, not merely unchecked.
    """
    reasons: List[str] = []

    corpus_type = manifest.get("corpus_type", "")
    if corpus_type != "synthea":
        reasons.append(
            f"corpus_type={corpus_type!r} is not reportable; README §4 admits "
            f"only 'synthea'"
        )

    actual = manifest.get("corpus_sha256")
    if not actual:
        reasons.append(
            "no corpus SHA-256: the corpus was not loaded and verified against "
            "the frozen pin"
        )
    else:
        try:
            from Common.crypto.config import load_dataset_config

            pinned = (load_dataset_config().get("freeze") or {}).get(
                "expected_corpus_sha256"
            )
        except Exception:  # noqa: BLE001 - an unreadable pin must not crash a run
            pinned = None
        if pinned and pinned != actual:
            reasons.append(
                f"corpus SHA-256 {actual[:12]}... does not match dataset.yaml's "
                f"frozen pin {pinned[:12]}...; results from a different corpus "
                f"are not comparable to the campaign (README §13)"
            )

    try:
        from Common.crypto.config import verify_experiment_host

        host = verify_experiment_host()
        if not host["host_check_satisfied"]:
            reasons.append(
                f"not running on the pinned AWS experiment host: expected "
                f"{host['expected_instance_type']!r}, detected "
                f"{host['detected_instance_type'] or 'not EC2'!r} (README §1)"
            )
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        reasons.append(f"could not verify the experiment host: {exc}")

    return reasons


def write_run_meta(
    path: Path,
    manifest: Dict[str, Any],
    experiment_name: str,
) -> None:
    """Write run_meta.json — provenance per README §7."""
    reasons = _reportability_blockers(manifest)
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
        "reportable": not reasons,
        "not_reportable_because": reasons,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
