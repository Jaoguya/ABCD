"""CLI entry point for the MA-LB-PQ-VDSE experiment harness.

Documented in ``SCHEME.md``::

    python3 -m Schemes.ma_lb_pq_vdse.src.main --experiment all \
        --config "Experiment Configuration/global.yaml" \
        --dataset Dataset/derived --runs 30

Writes ``raw_runs.csv``, ``results.csv`` and ``run_meta.json`` into each
experiment's folder, per README §9.

**Nothing this produces is reportable today**, and the reasons travel with the
output rather than living only here: ``run_meta.json`` carries
``not_reportable_because``, populated by ``harness.provenance.reportability``.
The blockers are listed in ``SCHEME.md`` — the missing v2 dataset manifest, the
absent Type-III pairing backend, the undecided keyed/unkeyed ``H``, and the
unswept λ weights. ``--require-reportable`` refuses to run rather than producing
output that could be mistaken for results.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as experiments_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import provenance, runner  # noqa: E402

SCHEME_NAME = "ma_lb_pq_vdse"

#: Output folder per experiment — the paths ``Plots/generate_plots.py`` walks.
FOLDERS = {
    1: "exp1_trapdoor_generation",
    2: "exp2_search_latency",
    3: "exp3_crossdomain_scalability",
    4: "exp4_verification_overhead",
    5: "exp5_keyword_update",
    6: "exp6_authorization_sync",
    7: "exp7_search_throughput",
    8: "exp8_load_balance",
}


def parse_experiments(value: str) -> List[int]:
    """``all``, ``2``, or ``1,2,5``."""
    if value.strip().lower() == "all":
        return sorted(FOLDERS)
    numbers = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or int(part) not in FOLDERS:
            raise argparse.ArgumentTypeError(
                f"unknown experiment {part!r}; README §5 defines 1-8"
            )
        numbers.append(int(part))
    if not numbers:
        raise argparse.ArgumentTypeError("no experiments selected")
    return sorted(set(numbers))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m Schemes.ma_lb_pq_vdse.src.main",
        description="Run the MA-LB-PQ-VDSE experiments (README §5).",
    )
    parser.add_argument("--experiment", default="all", help="all, 2, or 1,2,5")
    parser.add_argument("--config", default=None, help="path to global.yaml (informational)")
    parser.add_argument("--dataset", default=None, help="derived corpus directory")
    parser.add_argument(
        "--runs", type=int, default=None,
        help="retained runs per point (README §7 fixes 30)",
    )
    parser.add_argument(
        "--warmups", type=int, default=None,
        help="discarded warm-up runs (README §7 fixes 5)",
    )
    parser.add_argument(
        "--output", default=None,
        help="output root; defaults to this scheme's folder",
    )
    parser.add_argument(
        "--require-reportable", action="store_true",
        help="refuse to run unless every reportability condition holds",
    )
    parser.add_argument(
        "--smoke", action="store_true",
        help="one tiny sweep point and few runs, to exercise the pipeline",
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = scheme_config.load()
    numbers = parse_experiments(args.experiment)
    scheme_root = Path(__file__).resolve().parent.parent
    output_root = Path(args.output) if args.output else scheme_root

    def log(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    # --dataset used to be accepted and then silently ignored: the source was
    # hardcoded to SyntheticRecordSource, so every run stamped
    # corpus_type='synthetic' and could never be reportable no matter what the
    # caller passed or how the corpus freeze was resolved. Prefer the real
    # corpus, and fall back only when it genuinely cannot be read -- saying so
    # rather than degrading quietly.
    source: Any
    try:
        source = experiments_mod.CorpusRecordSource(corpus_dir=args.dataset)
        log(f"corpus: {source.corpus_type} "
            f"sha256={(source.corpus_sha256 or 'none')[:12]}... "
            f"|W_i|~{source.keywords_per_record} "
            f"domains={len(source.domains)} vocab={source.vocabulary}")
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        source = experiments_mod.SyntheticRecordSource()
        log(f"corpus unavailable ({type(exc).__name__}: {exc})")
        log("  falling back to SyntheticRecordSource -- runs will be marked "
            "NOT REPORTABLE (README §4 admits only corpus_type 'synthea')")
        if args.require_reportable:
            log("REFUSED: --require-reportable was passed but the verified "
                "corpus could not be loaded")
            return 2

    # Determined from what the host can ACTUALLY build, not hardcoded. This was
    # pinned to False while no Type-III backend existed; leaving it hardcoded
    # after adding CharmType3Backend would have kept the scheme permanently
    # non-reportable for a reason that was no longer true.
    try:
        from Common.crypto import pairing as _pm

        _b = _pm.get_backend("ma_lb_pq_vdse", reportable=True)
        group_faithful = _b.pairing_type == "type-3"
        log(f"pairing: {_b.name} ({_b.pairing_type}, {_b.curve}) faithful={group_faithful}")
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        group_faithful = False
        log(f"pairing: no faithful Type-III backend ({type(exc).__name__}: {exc})")

    # Evidence for the README §1 topology gate. Independent FSN processes need
    # fork (fsn/pool.py); on a platform without it the harness falls back to the
    # single-interpreter path, and reporting a process count here would assert a
    # topology the run did not use.
    import multiprocessing as _mp

    if config.topology.independent_processes and "fork" in _mp.get_all_start_methods():
        fsn_processes = int(config.topology.fog_search_nodes)
        log(f"topology: {fsn_processes} independent FSN processes (fork)")
    else:
        fsn_processes = 0
        log("topology: single interpreter — Exp. 7-8 will not be reportable")

    runs = args.runs if args.runs is not None else config.measurement.repetitions
    warmups = (
        args.warmups if args.warmups is not None else config.measurement.warmup_runs
    )
    if args.smoke:
        runs, warmups = min(runs, 3), min(warmups, 1)

    exit_code = 0
    for number in numbers:
        experiment = experiments_mod.build_experiment(number, config, source)
        metadata = provenance.build_metadata(
            config,
            experiment=experiment.name,
            corpus_type=source.corpus_type,
            corpus_sha256=source.corpus_sha256,
            group_faithful=group_faithful,
            fsn_processes=fsn_processes,
            token_scheme_keyed=True,
            runs=runs,
            warmups=warmups,
        )
        if args.require_reportable and not metadata.reportable:
            log(f"REFUSED {experiment.name}: not reportable")
            for reason in metadata.not_reportable_because:
                log(f"  - {reason}")
            exit_code = 2
            continue

        values = experiment.values[:1] if args.smoke else None
        log(
            f"{experiment.name}: {experiment.variable} over "
            f"{list(values or experiment.values)}, {runs} runs "
            f"({warmups} warm-ups)"
        )
        if not metadata.reportable:
            log("  NOT REPORTABLE — recorded in run_meta.json:")
            for reason in metadata.not_reportable_because:
                log(f"    - {reason}")

        result = runner.run_experiment(
            experiment, metadata, config=config, scheme=SCHEME_NAME, values=values
        )
        written = runner.write_outputs(result, output_root / FOLDERS[number])
        for point in result.points:
            log(
                f"  {experiment.variable}={point.variable_value}: "
                f"{point.primary.mean:.4f} ± {point.primary.ci95:.4f} "
                f"{experiment.primary.unit} (n={point.retained}"
                + (f", {point.failed} failed" if point.failed else "")
                + ")"
            )
        for warning in result.warnings:
            log(f"  WARNING {warning}")
        log(f"  wrote {', '.join(sorted(p.name for p in written.values()))}")

    return exit_code


def _force_utf8_stdout() -> None:
    """Make console output encoding-independent.

    The runners print check marks, box-drawing characters and Greek letters.
    On Linux stdout is UTF-8 and these are fine; a Windows console defaults to
    cp1252 and the first such character raises UnicodeEncodeError mid-run —
    which killed a guo run after Exp. 1 had already completed and written its
    results. Reconfiguring leaves Linux output byte-identical.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass  # already-wrapped or non-reconfigurable stream


if __name__ == "__main__":
    _force_utf8_stdout()
    raise SystemExit(run())
