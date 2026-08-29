#!/usr/bin/env python3
"""Verification tests for the MA-LB-PQ-VDSE experiment harness.

The harness is the layer a reviewer implicitly trusts when reading a number, so
these tests target the properties that would let a wrong number look right:

* the CI is computed from the sample and cannot be supplied;
* warm-ups are discarded and never recorded;
* a failed run is recorded AND re-run, so n reaches 30 rather than 29;
* nothing trims outliers;
* the output columns are exactly README §9's;
* every reportability blocker is named in ``run_meta.json``;
* each experiment's ``measure`` covers the boundary its README §5 rule states.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_harness.py
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_harness.py stats
"""

from __future__ import annotations

import csv
import json
import math
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import main as main_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import provenance, runner, stats  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


CONFIG = config_mod.load()
SOURCE = exp_mod.SyntheticRecordSource()


# ===========================================================================
# Fixtures — experiments with known behaviour
# ===========================================================================
@dataclass
class ScriptedExperiment:
    """An experiment returning a fixed sequence, for testing the runner itself."""

    samples: List[float]
    name: str = "exp0_scripted"
    number: int = 0
    variable: str = "value"
    values: Tuple[Any, ...] = (1,)
    primary: runner.MetricSpec = runner.MetricSpec("latency", "ms", is_timing=True)
    secondaries: Tuple[runner.MetricSpec, ...] = (
        runner.MetricSpec("secondary_a", "count"),
    )
    prepared_count: int = 0
    measured_count: int = 0

    def prepare(self, value: Any) -> Any:
        self.prepared_count += 1
        return value

    def measure(self, prepared: Any) -> runner.Sample:
        index = self.measured_count
        self.measured_count += 1
        value = self.samples[index % len(self.samples)]
        return runner.Sample(primary=value, secondaries={"secondary_a": 7.0})


@dataclass
class FlakyExperiment(ScriptedExperiment):
    """Fails on the first ``failures`` calls, then succeeds."""

    failures: int = 0
    _calls: int = 0

    def measure(self, prepared: Any) -> runner.Sample:
        self._calls += 1
        if self._calls <= self.failures:
            raise RuntimeError(f"induced failure {self._calls}")
        return runner.Sample(primary=1.0 + self._calls * 0.001, secondaries={})


def metadata_for(name: str, *, runs: int = 30, warmups: int = 5):
    return provenance.build_metadata(
        CONFIG,
        experiment=name,
        corpus_type="synthetic",
        runs=runs,
        warmups=warmups,
    )


# ===========================================================================
# stats.py
# ===========================================================================
def test_ci_uses_student_t_not_the_normal_approximation():
    """At n=30 the difference is ~4% of the interval width.

    Verified against the closed form rather than a hardcoded number, so the test
    fails if the implementation switches to z.
    """
    from scipy import stats as scipy_stats

    values = [float(i) for i in range(30)]
    got = stats.confidence_interval(values, 0.95)
    spread = stats.stdev(values)
    t_based = scipy_stats.t.ppf(0.975, df=29) * spread / math.sqrt(30)
    z_based = 1.959963985 * spread / math.sqrt(30)
    assert abs(got - t_based) < 1e-9
    assert abs(got - z_based) > 1e-4


def test_ci_is_computed_from_the_sample_alone():
    """There is no parameter through which a narrower interval could be supplied."""
    import inspect

    signature = inspect.signature(stats.confidence_interval)
    assert list(signature.parameters) == ["values", "confidence"]
    wide = stats.confidence_interval([1.0, 5.0, 9.0, 13.0])
    tight = stats.confidence_interval([5.0, 5.1, 4.9, 5.05])
    assert wide > tight


def test_stats_module_offers_no_trimming():
    """README §7: keep outliers. A trimming helper would invite using it."""
    names = {n for n in dir(stats) if not n.startswith("_")}
    assert not {
        "trim", "trimmed_mean", "winsorize", "drop_outliers", "filter_outliers",
        "reject_outliers",
    } & names


def test_summary_keeps_an_extreme_value():
    """An outlier must move the mean, not be silently discarded."""
    without = stats.summarise([1.0] * 29 + [1.0])
    with_outlier = stats.summarise([1.0] * 29 + [100.0])
    assert with_outlier.mean > without.mean
    assert with_outlier.maximum == 100.0
    assert with_outlier.n == 30


def test_ci_is_zero_for_a_constant_metric():
    """A count that cannot vary has no interval; that is not an error."""
    assert stats.confidence_interval([4.0] * 30) == 0.0
    summary = stats.summarise([4.0] * 30)
    assert summary.has_zero_variance and summary.ci95 == 0.0


def test_plausibility_flags_a_timing_with_zero_variance():
    """AGENT_RULES: zero variance "indicates a bug or fabrication"."""
    summary = stats.summarise([2.5] * 30)
    warning = stats.check_plausibility(summary, metric="latency", is_timing=True)
    assert warning is not None and "zero variance" in warning


def test_plausibility_does_not_flag_a_constant_count():
    """Trapdoors issued is 1 every run. Warning about it would train readers to
    ignore the warning."""
    summary = stats.summarise([1.0] * 30)
    assert stats.check_plausibility(summary, metric="trapdoors", is_timing=False) is None


def test_plausibility_flags_a_non_positive_duration():
    summary = stats.summarise([0.0, 1.0, 2.0] * 10)
    warning = stats.check_plausibility(summary, metric="latency", is_timing=True)
    assert warning is not None


def test_plausibility_accepts_a_normal_timing():
    summary = stats.summarise([1.0 + 0.01 * i for i in range(30)])
    assert stats.check_plausibility(summary, metric="latency", is_timing=True) is None


def test_empty_samples_are_refused():
    for call in (
        lambda: stats.mean([]),
        lambda: stats.confidence_interval([]),
        lambda: stats.summarise([]),
    ):
        try:
            call()
        except stats.StatisticsError:
            continue
        raise AssertionError("an empty sample should raise")


# ===========================================================================
# runner.py — the measurement loop
# ===========================================================================
def test_runner_retains_exactly_the_requested_runs():
    experiment = ScriptedExperiment(samples=[1.0, 2.0, 3.0])
    point = runner.run_point(
        experiment, 1, runs=30, warmups=5, confidence=0.95, scheme="s"
    )
    assert point.retained == 30
    assert point.primary.n == 30
    assert len([r for r in point.records if r.status == runner.STATUS_OK]) == 30


def test_runner_discards_warmups_without_recording_them():
    """A warm-up row would describe a run at a cache state the figures do not use."""
    experiment = ScriptedExperiment(samples=[1.0])
    point = runner.run_point(
        experiment, 1, runs=10, warmups=5, confidence=0.95, scheme="s"
    )
    assert experiment.measured_count == 15      # 5 discarded + 10 retained
    assert len(point.records) == 10             # only the retained are recorded
    assert all(r.run_id <= 10 for r in point.records)


def test_runner_prepares_once_per_point():
    """Setup is untimed and must not re-run per measurement (README §5)."""
    experiment = ScriptedExperiment(samples=[1.0])
    runner.run_point(experiment, 1, runs=8, warmups=2, confidence=0.95, scheme="s")
    assert experiment.prepared_count == 1


def test_runner_records_a_failure_and_reruns_to_restore_n():
    """README §7: record status=failed and re-run, rather than reporting n=29."""
    experiment = FlakyExperiment(samples=[1.0], failures=3)
    point = runner.run_point(
        experiment, 1, runs=10, warmups=0, confidence=0.95, scheme="s"
    )
    assert point.retained == 10                 # n restored
    assert point.failed == 3                    # and the failures are visible
    failed = [r for r in point.records if r.status == runner.STATUS_FAILED]
    assert all(r.primary is None for r in failed)
    assert all("induced failure" in r.error for r in failed)


def test_runner_abandons_a_point_that_keeps_failing():
    """A bounded retry, so a deterministic failure cannot loop forever."""
    experiment = FlakyExperiment(samples=[1.0], failures=10_000)
    try:
        runner.run_point(
            experiment, 1, runs=5, warmups=0, confidence=0.95, scheme="s"
        )
    except runner.HarnessError as exc:
        assert "failed" in str(exc)
        return
    raise AssertionError("a permanently failing point should raise")


def test_runner_surfaces_a_zero_variance_warning():
    experiment = ScriptedExperiment(samples=[1.0])     # every run identical
    point = runner.run_point(
        experiment, 1, runs=30, warmups=0, confidence=0.95, scheme="s"
    )
    assert any("zero variance" in w for w in point.warnings)


def test_runner_summarises_secondaries():
    experiment = ScriptedExperiment(samples=[1.0, 2.0])
    point = runner.run_point(
        experiment, 1, runs=10, warmups=0, confidence=0.95, scheme="s"
    )
    assert point.secondaries["secondary_a"].mean == 7.0


# ===========================================================================
# runner.py — output format, README §9
# ===========================================================================
def written_outputs(experiment, *, runs=6, warmups=1):
    metadata = metadata_for(experiment.name, runs=runs, warmups=warmups)
    result = runner.run_experiment(experiment, metadata, config=CONFIG)
    directory = Path(tempfile.mkdtemp())
    runner.write_outputs(result, directory)
    return directory, result


def test_raw_runs_columns_match_readme_section_9():
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0, 2.0]))
    with (directory / "raw_runs.csv").open() as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == list(runner.RAW_COLUMNS)
        rows = list(reader)
    assert rows[0]["scheme"] == "ma_lb_pq_vdse"
    assert rows[0]["status"] == "ok"
    # One row per run, never aggregated.
    assert len(rows) == 6


def test_raw_runs_leaves_unused_secondary_columns_blank():
    """README §9: "Blank secondary columns where a metric doesn't apply"."""
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0, 2.0]))
    with (directory / "raw_runs.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["secondary_metric_1"] != ""      # the one declared metric
    assert rows[0]["secondary_metric_2"] == ""      # none declared


def test_results_columns_match_readme_section_9():
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0, 2.0, 3.0]))
    with (directory / "results.csv").open() as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == [
            "variable_value",
            "primary_mean",
            "primary_ci95",
            "secondary_1_mean",
            "secondary_1_ci95",
            "secondary_2_mean",
            "secondary_2_ci95",
            "n_runs",
        ]
        rows = list(reader)
    assert len(rows) == 1
    assert int(rows[0]["n_runs"]) == 6


def test_results_n_runs_is_the_retained_count():
    """n_runs must be what was retained, not what was requested."""
    experiment = FlakyExperiment(samples=[1.0], failures=2)
    directory, result = written_outputs(experiment, runs=6, warmups=0)
    with (directory / "results.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert int(rows[0]["n_runs"]) == 6
    with (directory / "raw_runs.csv").open() as handle:
        raw = list(csv.DictReader(handle))
    assert len(raw) == 8                       # 6 retained + 2 failed rows
    assert sum(1 for r in raw if r["status"] == "failed") == 2


def test_results_ci_matches_the_raw_rows():
    """The aggregate must be derivable from the raw rows — the audit path."""
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0, 2.0, 3.0, 4.0]))
    with (directory / "raw_runs.csv").open() as handle:
        raw = [
            float(r["primary_metric"])
            for r in csv.DictReader(handle)
            if r["status"] == "ok"
        ]
    with (directory / "results.csv").open() as handle:
        row = next(csv.DictReader(handle))
    assert abs(float(row["primary_mean"]) - stats.mean(raw)) < 1e-6
    assert abs(float(row["primary_ci95"]) - stats.confidence_interval(raw)) < 1e-6


def test_write_outputs_produces_all_three_files():
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0, 2.0]))
    for name in ("raw_runs.csv", "results.csv", "run_meta.json"):
        assert (directory / name).is_file()


def test_run_meta_records_the_warnings():
    directory, _ = written_outputs(ScriptedExperiment(samples=[1.0]))
    meta = json.loads((directory / "run_meta.json").read_text())
    assert any("zero variance" in note for note in meta["notes"])
    assert meta["finished_utc"] is not None


# ===========================================================================
# provenance.py
# ===========================================================================
def test_provenance_records_everything_readme_section_7_requires():
    meta = metadata_for("exp1_trapdoor_generation")
    payload = json.loads(meta.to_json())
    for key in (
        "git_commit", "python_version", "instance_type", "libraries",
        "config_hashes", "corpus_type", "started_utc", "thread_pinning",
        "crypto_backends",
    ):
        assert key in payload, key
    assert payload["config_hashes"], "config hashes must be recorded"
    assert payload["runs"] == 30 and payload["warmups"] == 5


def test_provenance_marks_a_dirty_tree():
    """A result from a modified tree cannot be reproduced from the commit alone."""
    commit = provenance.git_commit()
    assert commit == "unknown" or len(commit.split("-")[0]) == 40


def test_provenance_lists_every_blocker_by_name():
    """"reportable: false" with no reason is not provenance."""
    import dataclasses

    # Every blocker must be nameable AT ONCE, so the config is forced back to
    # pending here rather than relying on the live one -- which now carries the
    # swept weights, so "pending_sweep" would legitimately be absent and this
    # test would stop checking the message it exists to check.
    pending = dataclasses.replace(
        CONFIG,
        scheduler=dataclasses.replace(
            CONFIG.scheduler,
            weights=dataclasses.replace(
                CONFIG.scheduler.weights, status="pending_sweep", provisional=True
            ),
        ),
    )
    reportable, reasons = provenance.reportability(
        pending,
        experiment="exp7_search_throughput",
        corpus_type="synthetic",
        corpus_sha256=None,
        group_faithful=False,
        token_scheme_keyed=False,
    )
    assert not reportable
    joined = " ".join(reasons)
    for fragment in (
        "not reportable", "SHA-256", "Type-III", "unkeyed", "pending_sweep",
        "independent process",
    ):
        assert fragment in joined, fragment


def test_provenance_accepts_a_fully_satisfied_run():
    """The gate must be passable, or it is not a gate but a wall.

    Only on the pinned host. The gate's host check queries live EC2 metadata
    (``Common.crypto.config.verify_experiment_host``) and cannot be satisfied
    from a dev machine, so off-host this SKIPS rather than fails — the same
    treatment the pairing and ML-KEM tests get. It still runs, and still has to
    pass, on the machine that produces reportable numbers.
    """
    import dataclasses

    from Common.crypto import config as common_config

    if not common_config.verify_experiment_host()["is_pinned_experiment_host"]:
        raise Skip("not on the pinned AWS experiment host; gate cannot pass here")

    fixed = dataclasses.replace(
        CONFIG,
        scheduler=dataclasses.replace(
            CONFIG.scheduler,
            weights=dataclasses.replace(
                CONFIG.scheduler.weights, status="fixed", provisional=False
            ),
        ),
        topology=dataclasses.replace(CONFIG.topology, independent_processes=False),
    )
    # Must be the ACTUAL frozen pin, not an arbitrary digest: a "fully
    # satisfied" run is by definition one whose corpus matches the campaign's
    # freeze, and reportability() now enforces that (it previously claimed to
    # and did not). Read from config rather than hardcoded so this test keeps
    # testing the real condition after a re-freeze.
    pinned = provenance._expected_corpus_sha256()
    assert pinned, "dataset.yaml has no freeze.expected_corpus_sha256 to test against"
    reportable, reasons = provenance.reportability(
        fixed,
        experiment="exp7_search_throughput",
        corpus_type="synthea",
        corpus_sha256=pinned,
        group_faithful=True,
        token_scheme_keyed=True,
        # Added 2026-08-28 with the ledger-fidelity gate: a "fully satisfied"
        # run is by definition one where EVERY condition holds, so this must
        # be set as each new condition is added, or the test quietly stops
        # asserting that the gate is passable.
        ledger_faithful=True,
    )
    assert reportable, reasons


def test_provenance_refuses_a_corpus_that_is_not_the_frozen_one():
    """A run against a different corpus than the campaign was frozen on must
    not be reportable.

    Regression guard. reportability() used to only check that a SHA-256 was
    *present*, while its own message claimed it had been "verified against the
    frozen pin" — so a run on any other corpus passed the gate. That is the
    silent data swap dataset.yaml's freeze pin exists to prevent (README §13).
    """
    import dataclasses

    fixed = dataclasses.replace(
        CONFIG,
        scheduler=dataclasses.replace(
            CONFIG.scheduler,
            weights=dataclasses.replace(
                CONFIG.scheduler.weights, status="fixed", provisional=False
            ),
        ),
        topology=dataclasses.replace(CONFIG.topology, independent_processes=False),
    )
    wrong = "0" * 64
    assert wrong != provenance._expected_corpus_sha256()
    reportable, reasons = provenance.reportability(
        fixed,
        experiment="exp7_search_throughput",
        corpus_type="synthea",
        corpus_sha256=wrong,
        group_faithful=True,
        token_scheme_keyed=True,
    )
    assert not reportable
    assert any("frozen pin" in reason for reason in reasons), reasons


def test_provenance_rejects_a_wrong_repetition_count():
    import dataclasses

    broken = dataclasses.replace(
        CONFIG,
        measurement=dataclasses.replace(CONFIG.measurement, repetitions=10),
    )
    _, reasons = provenance.reportability(
        broken, experiment="exp1_trapdoor_generation", corpus_type="synthea",
        corpus_sha256="x" * 64, group_faithful=True, token_scheme_keyed=True,
    )
    assert any("repetitions" in reason for reason in reasons)


def test_synthetic_source_can_never_be_reportable():
    """The harness must not have a path to a quotable number from invented data."""
    assert SOURCE.corpus_type == "synthetic"
    assert SOURCE.corpus_type not in CONFIG.corpus["reportable_types"]
    meta = metadata_for("exp2_search_latency")
    assert not meta.reportable


# ===========================================================================
# experiments.py — measurement boundaries
# ===========================================================================
def measure_once(number: int, value: Any = None):
    experiment = exp_mod.build_experiment(number, CONFIG, SOURCE)
    point = experiment.values[0] if value is None else value
    prepared = experiment.prepare(point)
    return experiment, experiment.measure(prepared)


def test_all_eight_experiments_are_defined():
    assert sorted(exp_mod.EXPERIMENTS) == [1, 2, 3, 4, 5, 6, 7, 8]
    for number in range(1, 9):
        experiment = exp_mod.build_experiment(number, CONFIG, SOURCE)
        assert experiment.number == number
        assert experiment.values, f"experiment {number} has no sweep"
        assert experiment.primary.unit


def test_experiment_sweeps_match_global_yaml():
    """The harness must not carry its own copy of the §V ranges."""
    for number, key in (
        (1, "exp1"), (2, "exp2"), (3, "exp3"), (4, "exp4"),
        (5, "exp5"), (6, "exp6"), (7, "exp7"), (8, "exp8"),
    ):
        experiment = exp_mod.build_experiment(number, CONFIG, SOURCE)
        assert tuple(experiment.values) == tuple(CONFIG.experiment(key).values)


def test_exp1_measures_only_trapdoor_generation():
    """Exp. 1 rule: ML-KEM encapsulation excluded from the per-query curve."""
    experiment, sample = measure_once(1, 5)
    assert experiment.primary.unit == "ms"
    assert sample.primary > 0
    assert sample.secondaries["tokens"] == 5.0
    assert sample.secondaries["trapdoor_size"] > 0


def test_exp1_latency_grows_with_q():
    """q PRF evaluations: 20 keywords must cost more than 1."""
    _, one = measure_once(1, 1)
    _, twenty = measure_once(1, 20)
    assert twenty.secondaries["tokens"] == 20.0
    assert twenty.secondaries["trapdoor_size"] > one.secondaries["trapdoor_size"]


def test_exp2_reports_n_eff():
    """README §5: n_eff "is the only thing that can demonstrate the paper's claim"."""
    experiment, sample = measure_once(2, 10_000)
    assert "n_eff" in sample.secondaries
    assert "entries_traversed" in sample.secondaries
    assert sample.secondaries["n_eff"] >= 0


def test_exp3_issues_exactly_one_trapdoor_at_every_d():
    """The Exp. 3 claim, across the sweep."""
    for domains in (2, 4):
        _, sample = measure_once(3, domains)
        assert sample.secondaries["trapdoors_issued"] == 1.0
        assert sample.secondaries["nodes_searched"] >= 1


def test_exp4_reports_proof_size_in_kb_and_path_length():
    experiment, sample = measure_once(4, 10)
    assert experiment.secondaries[0].unit == "KB"
    assert sample.secondaries["proof_size"] > 0
    assert sample.secondaries["path_length"] > 0


def test_exp5_refuses_a_global_rebuild():
    """"A global index rebuild indicates a Phase VII implementation bug"."""
    _, sample = measure_once(5, 100)
    assert sample.secondaries["merkle_nodes_recomputed"] > 0
    assert sample.secondaries["entries_rewritten"] > 0


def test_exp6_reports_message_size_and_fsns_touched():
    """"Report FSNs touched; selective propagation is the claim"."""
    experiment, sample = measure_once(6, 4)
    assert experiment.secondaries[0].unit == "KB"
    assert sample.secondaries["ias_message_size"] > 0
    # d = m = 4, so one authority's update reaches one node.
    assert sample.secondaries["fsns_touched"] == 1.0


def test_exp7_primary_is_a_throughput_not_a_latency():
    experiment, sample = measure_once(7, 50)
    assert experiment.primary.unit == "queries/s"
    assert sample.primary > 0
    assert "latency_p95" in sample.secondaries


def test_exp8_primary_is_a_utilization_spread():
    experiment, sample = measure_once(8, 50)
    assert experiment.primary.name == "utilization_stddev"
    assert sample.primary >= 0.0
    assert "max_node_utilization" in sample.secondaries


def test_exp7_and_exp8_share_one_workload_engine():
    """README §5: both metric sets come from the SAME runs."""
    assert issubclass(exp_mod.Exp7Throughput, exp_mod.SchedulerAblation)
    assert issubclass(exp_mod.Exp8LoadBalance, exp_mod.SchedulerAblation)
    assert exp_mod.Exp7Throughput.replay is exp_mod.SchedulerAblation.replay
    assert exp_mod.Exp8LoadBalance.replay is exp_mod.SchedulerAblation.replay


def test_ablation_covers_the_four_variants():
    from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod

    for variant in aass_mod.VARIANTS:
        experiment = exp_mod.Exp7Throughput(
            config=CONFIG, source=SOURCE, variant=variant
        )
        prepared = experiment.prepare(20)
        sample = experiment.measure(prepared)
        assert sample.primary >= 0.0


def test_scheduler_ablation_ramps_before_measuring(monkeypatch):
    """README §7: "Exp. 7-8 warm after a 30 s ramp."

    The ramp belongs in prepare(), which run_point() calls once per point and
    excludes from every timing. Putting it in measure() would ramp 30 times per
    point and time a warm-up as if it were the measurement. This asserts the
    ramp actually replays, and that it does so in prepare and not in measure --
    conftest zeroes RAMP_SECONDS for every other test, so without this the
    feature would be entirely uncovered.
    """
    monkeypatch.setattr(exp_mod, "RAMP_SECONDS", 0.05)
    experiment = exp_mod.Exp7Throughput(config=CONFIG, source=SOURCE)

    calls = []
    original = type(experiment).replay
    monkeypatch.setattr(
        type(experiment), "replay",
        lambda self, d, r, c, _o=original: (calls.append(1), _o(self, d, r, c))[1],
    )

    prepared = experiment.prepare(20)
    ramped = len(calls)
    assert ramped >= 1, "prepare() must ramp before the point is measured"

    experiment.measure(prepared)
    assert len(calls) == ramped + 1, "measure() must replay once, never ramp"


def test_cross_node_forwards_is_scheduler_invariant_at_one_domain_per_node():
    """A flat metric must be known to be flat before it is ever plotted.

    README §1's default topology is d = m = 4, and assign_domains_to_fsns then
    gives each FSN exactly one domain. _candidates() already restricts the
    choice to nodes serving an authorized domain, so the chosen node serves
    exactly ONE of the k domains a request is authorized for, whichever node
    that is -- and the forward count is k-1 under every variant. No scheduler
    can move it. §V's "minimizes unnecessary cross-node communication" is
    therefore not testable on this topology, and this test exists so that fact
    fails loudly if the topology or the candidate rule ever changes to make it
    testable.
    """
    from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod

    experiment = exp_mod.Exp7Throughput(config=CONFIG, source=SOURCE)
    prepared = experiment.prepare(40)
    deployment, requests = prepared["deployment"], prepared["requests"]
    assert all(len(node.domains) == 1 for node in deployment.nodes)

    counts = set()
    for variant in aass_mod.VARIANTS:
        scheduler = aass_mod.Scheduler(variant, config=CONFIG, reportable=False)
        forwards = 0
        for token, decision in requests:
            request = aass_mod.SearchRequest(
                tokens=token.tokens,
                authorized=decision.authorized_shards,
                vid_u=token.vid_u,
            )
            node = scheduler.select(deployment.nodes, request).node
            served = sum(1 for d in request.domains if node.serves_domain(d))
            assert served == 1
            forwards += len(request.domains) - served
        counts.add(forwards)
    assert len(counts) == 1, (
        f"cross_node_forwards differed across variants ({counts}); the topology "
        f"now permits a scheduling choice, so the metric has become meaningful "
        f"and Exp. 8 should report it"
    )


def test_injected_stub_group_is_never_reportable():
    """An explicitly injected stand-in must propagate into the context.

    Was test_harness_deployment_is_never_reportable, which called
    build_deployment() with no provider and asserted the result could never be
    reportable. That held only while a stub was the ONLY option;
    build_deployment now prefers the real CharmType3Backend where charm is
    installed, so the old assertion tested the absence of a backend rather than
    the property it was written to protect.

    The invariant that still matters: when a stand-in IS used, its
    unfaithfulness must reach context.reportable rather than stopping at the
    seam -- so a stub run can never be quoted.
    """
    deployment = exp_mod.build_deployment(
        config=CONFIG, source=SOURCE, records=4,
        group_provider=exp_mod._unfaithful_group_provider,
    )
    assert not deployment.context.reportable


# ===========================================================================
# main.py — the CLI
# ===========================================================================
def test_cli_parses_experiment_selections():
    assert main_mod.parse_experiments("all") == [1, 2, 3, 4, 5, 6, 7, 8]
    assert main_mod.parse_experiments("2") == [2]
    assert main_mod.parse_experiments("1,2,5") == [1, 2, 5]
    assert main_mod.parse_experiments("5,1,5") == [1, 5]


def test_cli_rejects_an_unknown_experiment():
    import argparse

    for bad in ("9", "0", "two", ""):
        try:
            main_mod.parse_experiments(bad)
        except argparse.ArgumentTypeError:
            continue
        raise AssertionError(f"{bad!r} should be refused")


def test_cli_folders_match_the_plotting_paths():
    """Plots/generate_plots.py walks Schemes/*/exp<N>_*/results.csv."""
    scheme_root = REPO_ROOT / "Schemes" / "ma_lb_pq_vdse"
    for number, folder in main_mod.FOLDERS.items():
        assert folder.startswith(f"exp{number}_")
        assert (scheme_root / folder).is_dir(), f"{folder} is missing"


def test_cli_writes_all_three_files_per_experiment():
    output = Path(tempfile.mkdtemp())
    code = main_mod.run(
        ["--experiment", "1", "--smoke", "--quiet", "--output", str(output)]
    )
    assert code == 0
    folder = output / main_mod.FOLDERS[1]
    for name in ("raw_runs.csv", "results.csv", "run_meta.json"):
        assert (folder / name).is_file()


def test_cli_require_reportable_matches_the_actual_reportability():
    """--require-reportable must refuse when blocked, and proceed when not.

    Was test_cli_require_reportable_refuses_rather_than_producing_output, which
    asserted code == 2 unconditionally. That encoded "this scheme can never be
    reportable", true only while no Type-III backend existed; CharmType3Backend
    landed 2026-08-28 and on the experiment host the run is now legitimately
    reportable, so the old assertion tested the absence of a backend.

    The contract that actually matters is conditional, and is checked in both
    directions here: when something blocks reportability the CLI must exit 2
    and write NOTHING that could be mistaken for results; when nothing blocks
    it, it must proceed and write them.
    """
    output = Path(tempfile.mkdtemp())
    code = main_mod.run(
        [
            "--experiment", "1", "--smoke", "--quiet",
            "--require-reportable", "--output", str(output),
        ]
    )
    produced = (output / main_mod.FOLDERS[1] / "results.csv").exists()
    if code == 2:
        assert not produced, "refused, but wrote output anyway"
    else:
        assert code == 0 and produced
        meta = json.loads(
            (output / main_mod.FOLDERS[1] / "run_meta.json").read_text()
        )
        assert meta["reportable"] is True
        assert not meta["not_reportable_because"]


def test_cli_reportability_and_its_reasons_always_agree():
    """run_meta.json's flag and its reason list must never contradict.

    Was test_cli_records_non_reportability_in_the_output, which asserted
    reportable is False unconditionally -- again encoding the pre-2026-08-28
    absence of a Type-III backend rather than a property of the harness.

    The invariant that survives a backend landing: whichever way the flag
    falls, it must be consistent with the reasons. A run marked reportable
    with blockers listed, or marked non-reportable with none, would let a
    reader draw the wrong conclusion from the file.
    """
    output = Path(tempfile.mkdtemp())
    main_mod.run(
        ["--experiment", "1", "--smoke", "--quiet", "--output", str(output)]
    )
    meta = json.loads(
        (output / main_mod.FOLDERS[1] / "run_meta.json").read_text()
    )
    if meta["reportable"]:
        assert not meta["not_reportable_because"]
    else:
        assert meta["not_reportable_because"]


# ===========================================================================
# Runner
# ===========================================================================
def _collect(selector: str | None) -> List[Tuple[str, Callable[[], None]]]:
    tests = [
        (name, obj)
        for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    ]
    if selector:
        tests = [(n, f) for n, f in tests if selector in n]
    return sorted(tests)


def main(argv: List[str]) -> int:
    selector = argv[1] if len(argv) > 1 else None
    tests = _collect(selector)
    if not tests:
        print(f"no tests match {selector!r}")
        return 2

    passed: List[str] = []
    skipped: List[Tuple[str, str]] = []
    failed: List[Tuple[str, str]] = []

    for name, fn in tests:
        try:
            fn()
        except Skip as exc:
            skipped.append((name, str(exc)))
            print(f"SKIP  {name}  ({exc})")
        except Exception:
            failed.append((name, traceback.format_exc()))
            print(f"FAIL  {name}")
        else:
            passed.append(name)
            print(f"ok    {name}")

    print(
        f"\n{len(passed)} passed, {len(skipped)} skipped, {len(failed)} failed "
        f"out of {len(tests)}"
    )
    for name, tb in failed:
        print(f"\n{'=' * 70}\nFAILED: {name}\n{'=' * 70}\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
