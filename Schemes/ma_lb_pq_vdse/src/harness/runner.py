"""The measurement loop and output writer — global.yaml and §9.

One place that decides how a point is measured, so no experiment can quietly use
a different repetition count, discard a run, or invent an interval.

What global.yaml requires, and where it is enforced:

* **10 runs after 5 discarded warm-ups.** :func:`run_point`. Warm-ups are executed
  and thrown away, never recorded — a warm-up in ``raw_runs.csv`` would be a run
  that never happened at the stated cache state.
* **Keep outliers.** Nothing here trims. A run that raises is recorded with
  ``status=failed`` and **re-run** to restore n = 10, which is global.yaml's rule
  rather than dropping it and reporting n = 9.
* **Mean ± 95% CI from the sample.** ``stats.summarise``; the runner passes only
  the retained values.
* **``perf_counter_ns`` for latency, wall clock for throughput.** Each experiment
  reports its own primary value, because Exp. 7's primary is a rate — a runner
  that timed every call would silently convert it into a latency.

Output is exactly global.yaml: ``raw_runs.csv`` (one row per run, never aggregated),
``results.csv`` (the aggregate the plotting script reads), and ``run_meta.json``.
"""

from __future__ import annotations

import csv
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from .. import config as scheme_config  # noqa: E402
from . import stats  # noqa: E402
from .provenance import RunMetadata  # noqa: E402

#: The row order global.yaml fixes for ``raw_runs.csv``.
RAW_COLUMNS = (
    "scheme",
    "experiment",
    "variable_value",
    "run_id",
    "primary_metric",
    "secondary_metric_1",
    "secondary_metric_2",
    "status",
)

#: global.yaml illustrates both CSVs with exactly two secondaries, and the writers
#: below took that as a CAP: ``[:2]`` on the metric names, ``range(1, 3)`` on the
#: columns. An experiment declaring a third recorded it in memory and then had it
#: dropped on the way to disk, with no warning — the same silent-loss class of
#: defect as a deploy that reports a commit it did not install. Exp. 6's
#: ``delivered_kb`` is the first metric to hit it.
#:
#: The column count now follows the experiment, floored here so that every
#: experiment declaring two or fewer keeps the exact shape §9 prints. §9's header
#: line is therefore still literally correct for all of them, and a run with more
#: writes a superset. global.yaml should say so; that edit is the user's.
MIN_SECONDARY_COLUMNS = 2


def _secondary_count(secondaries: Sequence[Any]) -> int:
    return max(MIN_SECONDARY_COLUMNS, len(secondaries))


def raw_columns(secondaries: Sequence[Any]) -> Tuple[str, ...]:
    """``RAW_COLUMNS`` widened to hold every secondary this experiment records."""
    count = _secondary_count(secondaries)
    head = ("scheme", "experiment", "variable_value", "run_id", "primary_metric")
    return head + tuple(
        f"secondary_metric_{i}" for i in range(1, count + 1)
    ) + ("status",)

STATUS_OK = "ok"
STATUS_FAILED = "failed"

#: A run is retried this many times before the point is abandoned. global.yaml says
#: to re-run a failure "to restore n=10"; a bound stops a deterministic failure
#: from looping forever, and the abandoned point keeps its failed rows so the
#: gap is visible rather than silent.
MAX_RETRIES_PER_RUN = 3


class HarnessError(RuntimeError):
    """Raised when a point cannot be measured to the required standard."""


@dataclass(frozen=True)
class Sample:
    """One measurement: the primary value plus any secondaries.

    The experiment supplies ``primary`` already in its reported unit — ms for a
    latency, queries/s for a throughput — because only the experiment knows which
    it is.
    """

    primary: float
    secondaries: Dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class RunRecord:
    """One row of ``raw_runs.csv``."""

    scheme: str
    experiment: str
    variable_value: Any
    run_id: int
    primary: Optional[float]
    secondaries: Dict[str, float]
    status: str
    error: str = ""

    def row(self, secondary_names: Sequence[str]) -> Dict[str, Any]:
        row = {
            "scheme": self.scheme,
            "experiment": self.experiment,
            "variable_value": self.variable_value,
            "run_id": self.run_id,
            "primary_metric": "" if self.primary is None else f"{self.primary:.6f}",
            "status": self.status,
        }
        for index, name in enumerate(secondary_names, start=1):
            value = self.secondaries.get(name)
            row[f"secondary_metric_{index}"] = (
                "" if value is None else f"{value:.6f}"
            )
        # global.yaml: "Blank secondary columns where a metric doesn't apply."
        for index in range(len(secondary_names) + 1,
                           _secondary_count(secondary_names) + 1):
            row[f"secondary_metric_{index}"] = ""
        return row


@dataclass(frozen=True)
class MetricSpec:
    """A reported metric and its unit — global.yaml fixes ms, KB, queries/s."""

    name: str
    unit: str
    is_timing: bool = False


class Experiment(Protocol):
    """What the runner needs from an experiment."""

    name: str
    number: int
    variable: str
    values: Tuple[Any, ...]
    primary: MetricSpec
    secondaries: Tuple[MetricSpec, ...]

    def prepare(self, value: Any) -> Any:
        """Untimed setup for one sweep point. Index construction lives here."""

    def measure(self, prepared: Any) -> Sample:
        """One measured run. Everything inside is on the measured path."""


@dataclass(frozen=True)
class PointResult:
    """One sweep point, aggregated."""

    variable_value: Any
    records: Tuple[RunRecord, ...]
    primary: stats.Summary
    secondaries: Dict[str, stats.Summary]
    warnings: Tuple[str, ...]

    @property
    def retained(self) -> int:
        """``n_runs`` — global.yaml requires 30 for reportable data."""
        return sum(1 for record in self.records if record.status == STATUS_OK)

    @property
    def failed(self) -> int:
        return sum(1 for record in self.records if record.status == STATUS_FAILED)


@dataclass(frozen=True)
class ExperimentResult:
    """A whole sweep, ready to write."""

    experiment: Experiment
    points: Tuple[PointResult, ...]
    metadata: RunMetadata

    @property
    def warnings(self) -> Tuple[str, ...]:
        return tuple(w for point in self.points for w in point.warnings)

    @property
    def complete(self) -> bool:
        """Every point retained the required number of runs."""
        return all(
            point.retained == self.metadata.runs for point in self.points
        )


def run_point(
    experiment: Experiment,
    value: Any,
    *,
    runs: int,
    warmups: int,
    confidence: float,
    scheme: str,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> PointResult:
    """Measure one sweep point: warm-ups, then ``runs`` retained runs.

    Setup is called once per point and excluded from every timing — global.yaml
    puts index construction offline, and re-preparing per run would put it in the
    curve.
    """
    # A point whose setup cannot be built is recorded as failed and skipped —
    # it must NOT abort the sweep. This was not merely theoretical: the frozen
    # corpus carries 4 domains while Exp. 3 sweeps d=2..10, so
    # CorpusRecordSource raises at d=6; unguarded, that propagated out of
    # run_experiment and killed the whole main.run(), meaning Exp. 5-8 never
    # executed at all. Losing three points of one experiment is a disclosable
    # limitation; losing four entire experiments to it is not.
    try:
        prepared = experiment.prepare(value)
    except Exception as exc:  # noqa: BLE001 - recorded, then skipped
        reason = f"{type(exc).__name__}: {exc}"
        return PointResult(
            variable_value=value,
            records=tuple(
                RunRecord(
                    scheme=scheme,
                    experiment=experiment.name,
                    variable_value=value,
                    run_id=run_id,
                    primary=None,
                    secondaries={},
                    status=STATUS_FAILED,
                    error=reason,
                )
                for run_id in range(1, runs + 1)
            ),
            # summarise() refuses an empty sample by design, so an explicit
            # NaN summary is built here: n=0 is what write_results must emit
            # for a point that produced no runs.
            primary=stats.Summary(
                n=0, mean=float("nan"), ci95=float("nan"),
                stdev=float("nan"), minimum=float("nan"), maximum=float("nan"),
            ),
            secondaries={},
            warnings=(
                f"{experiment.name} {experiment.variable}={value}: setup failed, "
                f"point skipped — {reason}",
            ),
        )

    # Warm-ups are executed and discarded. Not recorded: a warm-up row would
    # describe a run at a cache state the reported figures do not use.
    for _ in range(warmups):
        try:
            experiment.measure(prepared)
        except Exception:
            # A warm-up failure is not yet a result; the retained runs below will
            # surface it as a real failure if it persists.
            pass

    records: List[RunRecord] = []
    retained: List[Sample] = []
    run_id = 0
    while len(retained) < runs:
        run_id += 1
        attempts = 0
        while True:
            attempts += 1
            try:
                sample = experiment.measure(prepared)
            except Exception as exc:  # noqa: BLE001 - recorded, then retried
                records.append(
                    RunRecord(
                        scheme=scheme,
                        experiment=experiment.name,
                        variable_value=value,
                        run_id=run_id,
                        primary=None,
                        secondaries={},
                        status=STATUS_FAILED,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                if attempts > MAX_RETRIES_PER_RUN:
                    raise HarnessError(
                        f"{experiment.name} at {experiment.variable}={value}: "
                        f"run {run_id} failed {attempts} times; last error "
                        f"{type(exc).__name__}: {exc}. The failed rows are kept "
                        f"in raw_runs.csv rather than the point being dropped."
                    ) from exc
                continue
            retained.append(sample)
            records.append(
                RunRecord(
                    scheme=scheme,
                    experiment=experiment.name,
                    variable_value=value,
                    run_id=run_id,
                    primary=sample.primary,
                    secondaries=dict(sample.secondaries),
                    status=STATUS_OK,
                )
            )
            break
        if on_progress is not None:
            on_progress(len(retained), runs)

    primary_summary = stats.summarise(
        [sample.primary for sample in retained], confidence
    )
    warnings: List[str] = []
    warning = stats.check_plausibility(
        primary_summary, metric=experiment.primary.name,
        is_timing=experiment.primary.is_timing,
    )
    if warning:
        warnings.append(f"{experiment.name} {experiment.variable}={value}: {warning}")

    secondary_summaries: Dict[str, stats.Summary] = {}
    for spec in experiment.secondaries:
        values = [
            sample.secondaries[spec.name]
            for sample in retained
            if spec.name in sample.secondaries
        ]
        if values:
            secondary_summaries[spec.name] = stats.summarise(values, confidence)

    return PointResult(
        variable_value=value,
        records=tuple(records),
        primary=primary_summary,
        secondaries=secondary_summaries,
        warnings=tuple(warnings),
    )


def run_experiment(
    experiment: Experiment,
    metadata: RunMetadata,
    *,
    config: Optional[scheme_config.Configuration] = None,
    scheme: str = "ma_lb_pq_vdse",
    values: Optional[Sequence[Any]] = None,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> ExperimentResult:
    """Sweep an experiment across its points."""
    config = config or scheme_config.load()
    points = []
    for value in (experiment.values if values is None else values):
        points.append(
            run_point(
                experiment,
                value,
                runs=metadata.runs,
                warmups=metadata.warmups,
                confidence=metadata.confidence,
                scheme=scheme,
                on_progress=(
                    None
                    if on_progress is None
                    else (lambda done, total, v=value: on_progress(str(v), done, total))
                ),
            )
        )
    return ExperimentResult(
        experiment=experiment, points=tuple(points), metadata=metadata
    )


# ===========================================================================
# Output — global.yaml
# ===========================================================================
def write_raw_runs(result: ExperimentResult, path: Path) -> Path:
    """``raw_runs.csv`` — one row per run, never aggregated."""
    names = [spec.name for spec in result.experiment.secondaries]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(raw_columns(names)))
        writer.writeheader()
        for point in result.points:
            for record in point.records:
                writer.writerow(record.row(names))
    return path


def write_results(result: ExperimentResult, path: Path) -> Path:
    """``results.csv`` — the aggregate ``Plots/generate_plots.py`` reads.

    COLUMNS ARE NAMED AFTER THEIR METRIC, not numbered.

    This wrote ``secondary_1_mean``, ``secondary_2_mean``, … which put the
    meaning of a column somewhere other than the column — in the order of
    ``experiment.secondaries``, which is code, not data. Every reader then had
    to bind position to meaning by convention, and nothing checked the binding.
    That is the mechanism behind a recurring family of defects in this repo:

    * Fig. 8(c) drew ``secondary_2`` captioned "Cross-node forwards" when the
      banked column was ``max_queue_depth`` — the metric list had gained an
      entry and the figure kept its position;
    * `Exp4Verification` "counted index entries under a caption reading
      'returned results'";
    * a `psa_exp3` reference curve compared trapdoors against tokens.

    Naming the column makes the binding data rather than convention: a reader
    asks for ``cross_node_forwards_mean`` and a file that does not have it
    fails loudly instead of silently yielding whatever sits at that index.
    **Three of the four baselines already write named columns** (`guo_vdsse`,
    `yue_ge`, `perera_lv_pqabse`), so this conforms the proposed scheme to the
    convention already in the repo rather than inventing one.

    The ``secondary_N`` padding to ``MIN_SECONDARY_COLUMNS`` is dropped with it:
    it existed to keep a fixed column count, which only mattered while columns
    were addressed by number.

    RESULTS-AFFECTING for readers, not for values: every banked
    ``results.csv`` still holds the numbers it always did, but its columns are
    named the old way. `Plots/generate_plots.py` reads by name and falls back to
    position for those, saying so.
    """
    names = [spec.name for spec in result.experiment.secondaries]
    columns = ["variable_value", "primary_mean", "primary_ci95"]
    for name in names:
        columns += [f"{name}_mean", f"{name}_ci95"]
    columns.append("n_runs")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for point in result.points:
            row: Dict[str, Any] = {
                "variable_value": point.variable_value,
                "primary_mean": f"{point.primary.mean:.6f}",
                "primary_ci95": f"{point.primary.ci95:.6f}",
                "n_runs": point.retained,
            }
            for name in names:
                summary = point.secondaries.get(name)
                row[f"{name}_mean"] = (
                    "" if summary is None else f"{summary.mean:.6f}"
                )
                row[f"{name}_ci95"] = (
                    "" if summary is None else f"{summary.ci95:.6f}"
                )
            writer.writerow(row)
    return path


def write_outputs(
    result: ExperimentResult, output_dir: Path
) -> Dict[str, Path]:
    """Write all three files global.yaml requires for one experiment."""
    output_dir = Path(output_dir)
    from datetime import datetime, timezone

    result.metadata.finished_utc = datetime.now(timezone.utc).isoformat()
    if result.warnings:
        result.metadata.notes.extend(result.warnings)
    if not result.complete:
        result.metadata.notes.append(
            "at least one sweep point did not retain the required run count; "
            "n_runs in results.csv is authoritative"
        )
    return {
        "raw_runs.csv": write_raw_runs(result, output_dir / "raw_runs.csv"),
        "results.csv": write_results(result, output_dir / "results.csv"),
        "run_meta.json": result.metadata.write(output_dir / "run_meta.json"),
    }


__all__ = [
    "RAW_COLUMNS",
    "MIN_SECONDARY_COLUMNS",
    "raw_columns",
    "STATUS_OK",
    "STATUS_FAILED",
    "MAX_RETRIES_PER_RUN",
    "HarnessError",
    "Sample",
    "RunRecord",
    "MetricSpec",
    "Experiment",
    "PointResult",
    "ExperimentResult",
    "run_point",
    "run_experiment",
    "write_raw_runs",
    "write_results",
    "write_outputs",
]
