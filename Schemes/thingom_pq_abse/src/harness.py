"""Measurement, aggregation and output, per global.yaml and §9.

Timing uses ``time.perf_counter_ns()``. Warm-ups are discarded
before the retained runs begin. Failed runs are recorded with
``status=failed`` and are NOT dropped — global.yaml is explicit that a failure
is re-run to restore n=10 rather than deleted, so the row has to survive to
be visible.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

# Two-sided 95% Student-t quantiles by degrees of freedom. Tabulated rather
# than pulled from scipy because scipy is optional in requirements.txt and a
# missing dependency must not silently switch the CI to a normal
# approximation — that would narrow every interval in the paper.
_T_95: Dict[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
    31: 2.040, 32: 2.037, 33: 2.035, 34: 2.032, 35: 2.030,
    36: 2.028, 37: 2.026, 38: 2.024, 39: 2.023, 40: 2.021,
    60: 2.000, 120: 1.980,
}


def t_quantile_95(degrees_of_freedom: int) -> float:
    """Two-sided 95% t quantile, rounded conservatively between anchors.

    t decreases as df grows, so the conservative (wider-interval) choice
    between two tabulated anchors is the one for the LOWER df. Taking the
    higher anchor would report an interval narrower than the data supports,
    which is the direction a reviewer checks first.
    """
    if degrees_of_freedom <= 0:
        raise ValueError("need at least 2 runs to form a confidence interval")
    if degrees_of_freedom in _T_95:
        return _T_95[degrees_of_freedom]
    if degrees_of_freedom > 120:
        return 1.960
    below = [anchor for anchor in _T_95 if anchor < degrees_of_freedom]
    return _T_95[max(below)] if below else 12.706


def mean_ci95(values: Sequence[float]) -> tuple[float, float]:
    """Return ``(mean, half-width of the 95% CI)``.

    Half-width is ``t * s / sqrt(n)`` with the SAMPLE standard deviation
    (n-1 denominator). A single value has no interval; that returns 0.0 and
    the caller is responsible for not reporting it as if it were measured
    spread.
    """
    count = len(values)
    if count == 0:
        raise ValueError("no values to aggregate")
    average = statistics.fmean(values)
    if count == 1:
        return average, 0.0
    deviation = statistics.stdev(values)
    return average, t_quantile_95(count - 1) * deviation / (count**0.5)


@dataclass
class Run:
    """One retained repetition."""

    variable_value: Any
    run_id: int
    primary: float
    secondary_1: Optional[float] = None
    secondary_2: Optional[float] = None
    secondary_3: Optional[float] = None
    #: Added 2026-09-10 so Exp. 2 can report `matched_records`. SVI Exp. 2
    #: claims "query selectivity is kept constant" and no scheme recorded
    #: the quantity that claim is about; `n_eff` denotes something different
    #: in each scheme, so it could not be used to check it.
    secondary_3: Optional[float] = None
    status: str = "ok"
    # "measured" = this run was executed. "projected" = this value was derived
    # from a measured unit cost (Ref[41]'s search is q*N*(2u+1) pairings with no
    # index and no early termination, so cost is linear in N and one measured
    # record extrapolates). A projected row must never be readable as measured:
    # it carries NO confidence interval, because there is no sample to interval
    # over, and multiplying one run by 30 would state a replication that did
    # not happen.
    measurement_type: str = "measured"


@dataclass
class Measurement:
    """What a single timed repetition produced."""

    primary: float
    secondary_1: Optional[float] = None
    secondary_2: Optional[float] = None


@dataclass
class ExperimentResult:
    scheme: str
    experiment: str
    runs: List[Run] = field(default_factory=list)
    columns: Dict[str, str] = field(default_factory=dict)


def measure_point(
    operation: Callable[[], Measurement],
    *,
    variable_value: Any,
    repetitions: int,
    warmups: int,
) -> List[Run]:
    """Run ``operation`` ``warmups + repetitions`` times, keeping the latter.

    ``operation`` returns its own primary metric because only it knows which
    span to time — Exp. 1 times trapdoor generation alone, Exp. 2 the full
    online search path. Timing here instead would sweep setup into the number.
    """
    for _ in range(warmups):
        try:
            operation()
        except Exception:
            # A failing warm-up is not recorded; the retained runs below will
            # capture the failure with a status the reviewer can see.
            pass

    runs: List[Run] = []
    for run_id in range(1, repetitions + 1):
        try:
            measurement = operation()
            runs.append(
                Run(
                    variable_value=variable_value,
                    run_id=run_id,
                    primary=measurement.primary,
                    secondary_1=measurement.secondary_1,
                    secondary_2=measurement.secondary_2,
                    secondary_3=measurement.secondary_3,
                    status="ok",
                )
            )
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            runs.append(
                Run(
                    variable_value=variable_value,
                    run_id=run_id,
                    primary=float("nan"),
                    status=f"failed:{type(exc).__name__}",
                )
            )
    return runs


class Timer:
    """``perf_counter_ns`` span, reported in milliseconds (global.yaml units)."""

    __slots__ = ("_start", "elapsed_ms")

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter_ns()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.elapsed_ms = (time.perf_counter_ns() - self._start) / 1e6


class CpuTimer:
    """Aggregate CPU time across this process AND its reaped children, in ms.

    Exp. 2 parallelises the candidate scan across a fork pool, so a wall-clock
    span reports aggregate work DIVIDED BY the worker count -- making the
    published latency a function of how many cores the run happened to rent
    rather than a property of the scheme. At P=64 the same point would read ~32x
    faster than at P=2, and since this scheme is a BASELINE that would report it
    as faster than it is, which is strengthening a baseline.

    Aggregate CPU time removes P from the result: cores buy wall-clock, and the
    number reported is the single-core-equivalent cost of the scan. Identical
    pairings, identical match set -- only the clock changes.

    ``RUSAGE_CHILDREN`` counts only children that have been REAPED, so the pool
    must be closed inside the measured span; ``multiprocessing.Pool`` as a
    context manager terminates and joins its workers on exit, which satisfies
    that. The parent's own share is ``process_time`` (user+system, excluding
    sleep), covering trapdoor generation, query planning and result assembly.
    """

    __slots__ = ("_start_self", "_start_children", "elapsed_ms", "wall_ms", "_wall")

    @staticmethod
    def _children_seconds() -> float:
        try:
            import resource
            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
            return ru.ru_utime + ru.ru_stime
        except Exception:  # noqa: BLE001 - not available on every platform
            return 0.0

    def __enter__(self) -> "CpuTimer":
        self._start_self = time.process_time()
        self._start_children = self._children_seconds()
        self._wall = time.perf_counter_ns()
        return self

    def __exit__(self, *exc_info: object) -> None:
        cpu = ((time.process_time() - self._start_self)
               + (self._children_seconds() - self._start_children))
        self.elapsed_ms = cpu * 1e3
        self.wall_ms = (time.perf_counter_ns() - self._wall) / 1e6


# ---------------------------------------------------------------------------
# Output — global.yaml
# ---------------------------------------------------------------------------
def _format(value: Optional[float]) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:  # NaN
        return ""
    return f"{value:.6g}"


def write_raw_runs(path: Path, result: ExperimentResult) -> None:
    """``raw_runs.csv`` — one row per run, never aggregated."""
    lines = [
        "scheme,experiment,variable_value,run_id,primary_metric,"
        "secondary_metric_1,secondary_metric_2,status"
    ]
    for run in result.runs:
        lines.append(
            ",".join(
                [
                    result.scheme,
                    result.experiment,
                    str(run.variable_value),
                    str(run.run_id),
                    _format(run.primary),
                    _format(run.secondary_1),
                    _format(run.secondary_2),
                    run.status,
                ]
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_results(path: Path, result: ExperimentResult) -> None:
    """``results.csv`` — aggregated means with 95% CI.

    Only ``status=ok`` runs are aggregated. ``n_runs`` reports how many that
    was, so a point that lost runs to failures is visible as n < 30 rather
    than silently averaged over fewer samples.
    """
    header = (
        "variable_value,primary_mean,primary_ci95,"
        "secondary_1_mean,secondary_1_ci95,"
        "secondary_2_mean,secondary_2_ci95,"
        "secondary_3_mean,secondary_3_ci95,n_runs,measurement_type"
    )
    lines = [header]

    ordered: List[Any] = []
    grouped: Dict[Any, List[Run]] = {}
    for run in result.runs:
        if run.variable_value not in grouped:
            grouped[run.variable_value] = []
            ordered.append(run.variable_value)
        grouped[run.variable_value].append(run)

    for variable_value in ordered:
        ok = [run for run in grouped[variable_value] if run.status == "ok"]
        if not ok:
            lines.append(f"{variable_value},,,,,,,0,measured")
            continue

        projected = any(run.measurement_type == "projected" for run in ok)
        # A projected point gets its mean and the string "nan" for every CI.
        #
        # "nan" rather than an empty cell, deliberately. generate_plots.py:200
        # reads `_to_float(cell) or 0.0`, so an EMPTY cell becomes 0.0 and
        # matplotlib draws a zero-length error bar -- a 2pt cap that reads as a
        # vanishingly TIGHT interval, the single most flattering misreading of
        # a number that has no interval at all. nan is truthy so it survives
        # the `or`, and matplotlib draws nothing for it. Verified by pixel
        # count: the empty/0.0 path renders 13 extra pixels at the point, nan
        # renders none, and the axis limits are identical either way. This is
        # why the plotting code needs no change to represent it honestly.
        ci_cell = (lambda _v: "nan") if projected else _format

        primary_mean, primary_ci = mean_ci95([run.primary for run in ok])
        cells = [str(variable_value), _format(primary_mean), ci_cell(primary_ci)]

        for attribute in ("secondary_1", "secondary_2", "secondary_3"):
            values = [
                getattr(run, attribute)
                for run in ok
                if getattr(run, attribute) is not None
            ]
            if values:
                mean, ci = mean_ci95(values)
                cells.extend([_format(mean), ci_cell(ci)])
            else:
                cells.extend(["", ""])

        # len(ok) is what was EXECUTED. A projected point is derived from one
        # measured unit cost, so this reads 1 -- never the count of points it
        # was multiplied out to, and never a replication that did not happen.
        cells.append(str(len(ok)))
        cells.append("projected" if projected else "measured")
        lines.append(",".join(cells))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_run_meta(
    path: Path,
    *,
    scheme: str,
    experiment: str,
    started_utc: str,
    dataset_manifest: Optional[Dict[str, Any]],
    parameters: Dict[str, Any],
    reportable: bool,
    reportable_blockers: Sequence[str],
) -> None:
    """``run_meta.json`` — provenance.

    ``reportable`` and ``reportable_blockers`` are the important fields. A run
    produced with a development-only pairing backend, or against a sample
    corpus, must never be mistaken for one that can go in the paper, so the
    reason it cannot is recorded in the artefact itself rather than only in a
    console message that scrolls away.
    """
    from Common.crypto import environment_report
    from Common.crypto.config import config_hashes
    from Dataset.corpus import git_commit

    meta: Dict[str, Any] = {
        "scheme": scheme,
        "experiment": experiment,
        "started_utc": started_utc,
        "git_commit": git_commit(),
        "reportable": reportable,
        "reportable_blockers": list(reportable_blockers),
        "parameters": parameters,
        "config_hashes": config_hashes(),
        "environment": environment_report(),
    }

    if dataset_manifest:
        meta["dataset"] = {
            "corpus_type": dataset_manifest.get("corpus_type"),
            "corpus_sha256": dataset_manifest.get("corpus_sha256"),
            "records": dataset_manifest.get("records"),
            "keyword_universe_size": dataset_manifest.get("keyword_universe_size"),
            "domains": dataset_manifest.get("domains"),
        }
    else:
        meta["dataset"] = None

    path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def write_all(
    output_dir: Path,
    result: ExperimentResult,
    *,
    started_utc: str,
    dataset_manifest: Optional[Dict[str, Any]],
    parameters: Dict[str, Any],
    reportable: bool,
    reportable_blockers: Sequence[str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_raw_runs(output_dir / "raw_runs.csv", result)
    write_results(output_dir / "results.csv", result)
    write_run_meta(
        output_dir / "run_meta.json",
        scheme=result.scheme,
        experiment=result.experiment,
        started_utc=started_utc,
        dataset_manifest=dataset_manifest,
        parameters=parameters,
        reportable=reportable,
        reportable_blockers=reportable_blockers,
    )
