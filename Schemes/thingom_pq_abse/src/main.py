"""Runner for Ref[41] — Thingom et al. PQ-ABSE.

    python -m Schemes.thingom_pq_abse.src.main --experiment 1,2,3 \
        --dataset Dataset/derived --runs 30

A run is REPORTABLE only when every one of these holds:

  * the pairing backend is the published Type-I curve (charm SS512), and
  * the corpus verifies against its frozen manifest AND the dataset.yaml pin,
    with ``corpus_type: synthea``, and
  * this process is actually running on the pinned AWS experiment host
    (``global.yaml``'s ``environment.instance_type``), not a development
    laptop or any other machine.

Anything else still runs — development on Windows is expected —
but ``run_meta.json`` records ``reportable: false`` together with the reasons,
so a development artefact cannot be mistaken for a paper number later.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from Common.crypto import pairing
from Common.crypto.config import (
    REPO_ROOT, ConfigError, assert_config_unchanged, get,
    snapshot_config_state, verify_experiment_host,
)

from . import experiments
from .harness import write_all, write_raw_runs, write_results

from infra import sweep

# global.yaml defaults. These live here rather than in a config file because
# "Experiment Configuration/global.yaml" — referenced by
# SystemConfiguration.md — does not exist in the repository yet. Every value that affects
# a NUMBER (attribute count, pairing curve) is read from crypto.yaml instead,
# so it is covered by the config hash in run_meta.json.
DEFAULT_REPETITIONS = 10
DEFAULT_WARMUPS = 5
DEFAULT_Q = 5
DEFAULT_SEED = 20260804

EXP1_Q_VALUES = list(range(1, 21))

# Capped 2026-08-27, raised 2026-08-28, to fit a 24h-per-track wall-clock
# budget on the pinned AWS host. Ref[41] has no index structure
# or early termination — every candidate costs a real 2u+1 pairings — so the
# published 10^4-10^6 sweep is far out of budget even measured (not
# guessed). 2026-08-28: search parallelized across 2 forked processes
# (hardware-utilization detail, not an algorithmic change — see
# experiments.py's _parallel_search and its Feasibility notes for
# the disclosure). Measured 1.94-1.95x speedup in isolation, verified correct
# (identical pairing counts and match sets vs. single-threaded) on both
# Exp.2's and Exp.3's actual call shapes.
#
# Sizing uses the WORST end-to-end rate observed through the real
# experiment_2/experiment_3 code paths (0.389 ms/pairing, from Exp.3 at d=3
# where pool churn is highest), not the 0.361 ms/pairing best case measured
# in isolation — a hard 24h cap should be sized against the worst case.
# At these values: Exp.2 ~7.94h + Exp.3 ~12.51h = ~20.45h, ~3.55h margin.
# EXP3_TOTAL_INDEX_SIZE=4_000 was considered and rejected: it lands at
# ~22.2h, only ~1.8h of margin.
# N MUST be a point global.yaml's exp2_search_latency.values actually sweeps.
# A brief 2026-08-28 change to 20_000 -- taken because the parallel speedup made
# it affordable -- aligned with NO other scheme's measurements: generate_plots.py
# draws every scheme on one axis, so Ref[41] would have been a lone point at
# 2x10^4 with nothing to compare it against. Affordability never sets this
# value; comparability does.
#
# Now the FULL sweep, matching global.yaml exactly, so Ref[41] spans the same
# 10^4-10^6 axis as ma_lb, perera and yue_ge rather than sitting at one point.
#
# What made that affordable is NOT a faster scheme -- the pairing count per
# candidate is untouched. Two things changed:
#   1. experiments.py's chunksize was `len(index) // 8`, a constant 8 chunks at
#      any process count, so speedup capped at 8x however wide the host. It now
#      follows _SEARCH_PROCESSES.
#   2. Exp. 2 runs at n=1 for this scheme, not the usual 10 + 5 warm-ups. At
#      n=15 the sweep is ~71h; at n=1 it is ~4.7h on 8 workers. (The ~165h
#      figure this was sized against was n=35, before the 30 -> 10 change;
#      rescaling on the same per-run basis gives ~71h, still far past budget,
#      so the n=1 decision below is unchanged.)
#
# n=1 is a REAL cost and must be disclosed, not hidden: this scheme's Exp. 2
# points carry no confidence interval and no error bar, while every other
# scheme's do. A single run cannot be distinguished from an outlier. It is the
# honest trade for measuring the published 10^4-10^6 range at all, and §V has to
# say so.
EXP2_INDEX_SIZES = [10**4, 5 * 10**4, 10**5, 5 * 10**5, 10**6]
EXP3_DOMAIN_COUNTS = list(range(2, 11))
EXP3_TOTAL_INDEX_SIZE = 2_000  # held constant across the d sweep; see experiment_3()

OUTPUT_DIRS = {
    "1": "exp1_trapdoor_generation",
    "2": "exp2_search_latency",
    "3": "exp3_crossdomain_scalability",
}


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Schemes.thingom_pq_abse.src.main",
        description="Run Ref[41] experiments 1-3.",
    )
    parser.add_argument(
        "--experiment",
        default="1,2,3",
        help="comma-separated experiment numbers, or 'all' (Ref[41] runs 1,2,3)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="optional experiment config; crypto.yaml is always read regardless",
    )
    parser.add_argument("--dataset", default=None, help="corpus directory")
    parser.add_argument("--runs", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--points", default=None,
        help=(
            "run only these sweep values so one experiment can be split across "
            "instances (e.g. '2-5'). Exp. 3's nine d-points at ~1.4h each are "
            "the longest job in this track, and this is what makes them "
            "parallel; infra/merge_points.py reassembles the shards."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="output root (default: this scheme's folder)",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help=(
            "permit a development pairing backend and an unverified corpus. "
            "Output is marked reportable:false."
        ),
    )
    parser.add_argument(
        "--max-seconds-per-run",
        type=float,
        default=7200.0,
        help=(
            "per-point wall-clock budget. Points whose estimated cost exceeds "
            "it are recorded as status=failed rather than attempted."
        ),
    )
    # RAISED 1800 -> 7200 on 2026-08-30. At 1800 the sweep could not reach the
    # range it is supposed to measure: a live run recorded N=50,000 as
    # `budget_exceeded_est2157s_budget1800s` and stopped with two rows in
    # raw_runs.csv, so 10^5, 5x10^5 and 10^6 were never attempted. Projected
    # per-run cost at 10^6 is ~9256 s at P=8 and ~1157 s at P=64, from the one
    # measured point (N=10^4, P=8, 740,464 ms aggregate CPU).
    #
    # 7200 regardless of P: at P=64 that is ~6.2x headroom, where 1800 gave
    # 1.55x -- and the estimator this budget is compared against is itself a
    # linear extrapolation from a single measurement, so thin margin converts
    # a real point into status=failed on estimator error alone.
    #
    # This changes no measured quantity. A timeout decides whether a run
    # finishes, never what it reports.
    return parser.parse_args(argv)


def resolve_experiments(spec: str) -> List[str]:
    if spec.strip().lower() == "all":
        return ["1", "2", "3"]
    selected = [item.strip() for item in spec.split(",") if item.strip()]
    unknown = [item for item in selected if item not in OUTPUT_DIRS]
    if unknown:
        raise SystemExit(
            f"Ref[41] runs experiments 1, 2 and 3 only; "
            f"got {', '.join(unknown)}"
        )
    return selected


def load_keywords(
    dataset_dir: Optional[str], *, dev: bool
) -> Tuple[List[str], Optional[Dict[str, Any]], List[str]]:
    """Return ``(keywords, manifest, blockers)``.

    The verified corpus is the only reportable source. When it is absent the
    development sample is used and a blocker is recorded — never silently.
    """
    blockers: List[str] = []
    try:
        from Dataset.corpus import load_verified_corpus

        records, manifest = load_verified_corpus(
            corpus_dir=Path(dataset_dir) if dataset_dir else None
        )
        universe = sorted({keyword for record in records for keyword in record.kw})
        if manifest.get("corpus_type") != "synthea":
            blockers.append(
                f"corpus_type is {manifest.get('corpus_type')!r}, not 'synthea' "
                f""
            )
        return universe, manifest, blockers
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        blockers.append(f"verified corpus unavailable: {type(exc).__name__}: {exc}")

    if not dev:
        raise SystemExit(
            "\n".join(
                [
                    "Refusing to run: the frozen corpus did not verify.",
                    f"  {blockers[-1]}",
                    "",
                    "Pass --dev to run against the development sample. Output "
                    "will be marked reportable:false.",
                ]
            )
        )

    sample = _find_sample(dataset_dir)
    if sample is None:
        raise SystemExit(
            "No corpus and no development sample found under Dataset/derived."
        )
    blockers.append(f"using development sample {sample.name}, not the frozen corpus")

    universe = set()
    with sample.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                universe.update(json.loads(line).get("kw", []))
    return sorted(universe), None, blockers


def _find_sample(dataset_dir: Optional[str]) -> Optional[Path]:
    directory = Path(dataset_dir) if dataset_dir else REPO_ROOT / "Dataset" / "derived"
    candidates = sorted(directory.glob("sample_v*_*records.jsonl"), reverse=True)
    return candidates[0] if candidates else None


def resolve_backend(dev: bool) -> Tuple[Any, List[str]]:
    """Build the pairing backend and report why it may not be reportable."""
    blockers: List[str] = []
    try:
        backend = pairing.get_backend("thingom_pq_abse", reportable=not dev)
    except pairing.UnfaithfulBackendError as exc:
        raise SystemExit(
            f"{exc}\n\nPass --dev to run on the Type-III development backend; "
            f"output will be marked reportable:false."
        ) from exc
    except pairing.PairingUnavailableError as exc:
        raise SystemExit(
            f"No pairing backend is installed.\n  {exc}\n\n"
            f"Ref[41] needs charm-crypto for its published Type-I SS512 curve "
            f". It is Linux-only."
        ) from exc

    if backend.pairing_type != "type-1":
        # Not merely unreportable — UNRUNNABLE. Ref[41] pairs two elements of
        # the same group everywhere (e(i,i) in setup, e(CS_3j, L_1z) in
        # search). On a Type-III backend the second argument must come from
        # G2, so the very first pairing in setup() raises from inside the
        # library. Fail here with the reason instead.
        raise SystemExit(
            f"Ref[41] cannot run on {backend.name!r} ({backend.pairing_type}).\n"
            f"\n"
            f"Its construction pairs two elements of the SAME group throughout "
            f"(e : I1 x I1 -> I2, Ref[41].md:162). A Type-III backend has no "
            f"such operation, so --dev does not give a usable development path "
            f"for this scheme — unlike the Type-III schemes the fallback in "
            f"crypto.yaml was added for.\n"
            f"\n"
            f"charm-crypto (Linux only) is required to run Ref[41] at all."
        )
    return backend, blockers


def attribute_count() -> int:
    """Number of user attributes ``u``, from crypto.yaml.

    Not published for the benchmark by either Ref[41] or the manuscript's §V —
    Ref[41] fixes u=30 only for its own figure captions (:472). Held in
    crypto.yaml so the value is hashed into every run_meta.json.
    """
    try:
        return int(get("thingom_pq_abse", "attributes", "u"))
    except ConfigError as exc:
        raise SystemExit(
            "crypto.yaml has no thingom_pq_abse.attributes.u.\n"
            "Ref[41]'s trapdoor is 2u exponentiations and its search is 2u+1 "
            "pairings per candidate, so this value places the baseline on "
            "Exp. 1 and Exp. 2. It must be set deliberately, not defaulted.\n"
            f"  {exc}"
        ) from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Freeze the configuration this run is measured under, before anything is
    # measured. assert_config_unchanged() re-checks at every sweep-point
    # boundary and aborts if it moved.
    snapshot_config_state()
    args = parse_args(argv)
    selected = resolve_experiments(args.experiment)

    if args.config and not Path(args.config).is_file():
        raise SystemExit(
            f"--config {args.config!r} not found. Note that "
            f"'Experiment Configuration/global.yaml' does not exist in this "
            f"repository yet; crypto.yaml is read automatically and does not "
            f"need to be passed."
        )

    backend, backend_blockers = resolve_backend(args.dev)
    keywords, manifest, corpus_blockers = load_keywords(args.dataset, dev=args.dev)
    if not keywords:
        raise SystemExit("keyword universe is empty; cannot build a workload")

    host = verify_experiment_host()
    host_blockers: List[str] = []
    if not host["host_check_satisfied"]:
        host_blockers.append(
            f"not running on the pinned AWS experiment host: expected "
            f"{host['expected_instance_type']!r}, detected "
            f"{host['detected_instance_type'] or 'not EC2'!r} on "
            f"{host['platform']!r}"
        )

    blockers = backend_blockers + corpus_blockers + host_blockers
    if args.dev:
        blockers.append("--dev was passed; verification gates were relaxed")
    reportable = not blockers

    u = attribute_count()
    workload = experiments.build_workload(
        backend, attribute_count=u, keywords=keywords, seed=args.seed
    )

    started = _datetime.datetime.now(_datetime.timezone.utc).isoformat()
    output_root = Path(args.output) if args.output else Path(__file__).resolve().parents[1]

    parameters: Dict[str, Any] = {
        "repetitions": args.runs,
        "warmups_discarded": args.warmups,
        "q_default": DEFAULT_Q,
        "attribute_count_u": u,
        "pairing_backend": backend.name,
        "pairing_type": backend.pairing_type,
        "seed": args.seed,
        "keyword_universe_size": len(keywords),
        "max_seconds_per_run": args.max_seconds_per_run,
        "multi_keyword_mode": (
            "native: q independent trapdoors + q independent searches, "
            "client-side intersection (Ref[41] is single-keyword)"
        ),
        # Provenance for the two 2026-08-28 decisions that change what a
        # reported number MEANS. Prose is not machine-readable
        # provenance, and neither fact is otherwise recoverable
        # from the outputs: exp3's variable is d, so the held index size
        # appears in no results.csv column at all.
        "exp2_search_processes": experiments._SEARCH_PROCESSES,
        "exp3_search_processes": 1,  # single-threaded on purpose; see experiment_3()
        "exp2_index_sizes": list(EXP2_INDEX_SIZES),
        "exp2_projection": _PROJECTION_PROVENANCE,
        "exp3_total_index_size": EXP3_TOTAL_INDEX_SIZE,
        "exp3_domain_counts": list(EXP3_DOMAIN_COUNTS),
    }

    _print_banner(reportable, blockers, parameters)

    for number in selected:
        # Resolved BEFORE the run so the per-point flush has a destination.
        directory = sweep.shard_dir(output_root / OUTPUT_DIRS[number], args.points)

        def _flush(size: int, partial, _dir: Path = directory) -> None:
            """Persist completed points. Fired between points, never in a span."""
            # Abort rather than measure later points under changed parameters.
            assert_config_unchanged()
            _dir.mkdir(parents=True, exist_ok=True)
            write_raw_runs(_dir / "raw_runs.csv", partial)
            write_results(_dir / "results.csv", partial)
            # run_meta.json is written only on completion, so its absence is
            # the incomplete signal. This says how far the sweep actually got.
            (_dir / "PARTIAL").write_text(
                f"in progress -- completed through N={size}\n"
                f"{len(partial.runs)} runs recorded so far\n"
                "run_meta.json is absent until the sweep finishes; if it is "
                "missing this directory is INCOMPLETE and not reportable.\n",
                encoding="utf-8",
            )
            print(f"  [flush] wrote partial results through N={size}", flush=True)

        result = _run_one(number, workload, args, on_point_complete=_flush)
        write_all(
            directory,
            result,
            started_utc=started,
            dataset_manifest=manifest,
            parameters={**parameters, "columns": result.columns},
            reportable=reportable,
            reportable_blockers=blockers,
        )
        # run_meta.json now exists, so the sweep completed and the marker
        # would misreport it. Cleared after, never before.
        (directory / "PARTIAL").unlink(missing_ok=True)
        ok = sum(1 for run in result.runs if run.status == "ok")
        try:
            shown = directory.relative_to(REPO_ROOT)
        except ValueError:  # --output pointed outside the repository
            shown = directory
        print(f"  exp{number}: {ok}/{len(result.runs)} runs ok -> {shown}")

    return 0


#: Filled by Exp. 2's projection so run_meta can carry the anchors, the fitted
#: slope and intercept, and the linearity residual -- every projected point
#: must be reconstructible from the record without re-running anything.
_PROJECTION_PROVENANCE: Dict[str, Any] = {}


def _run_one(number: str, workload: experiments.Workload, args: argparse.Namespace,
             *, on_point_complete=None):
    points = getattr(args, "points", None)
    if number == "1":
        return experiments.experiment_1(
            workload,
            q_values=sweep.select(EXP1_Q_VALUES, points),
            repetitions=args.runs,
            warmups=args.warmups,
        )
    if number == "2":
        # PROJECTED, not swept. Ref[41] has no index and no early termination, so
        # a real N=10^6 search is ~q*10^6*(2u+1) pairings and days of compute --
        # not runnable, which is why the published sweep was never reproduced.
        # Real searches run to N=10,000; the four larger points are derived from
        # the fitted per-record slope. Cost is linear in N by construction, so
        # the curve is a straight line and that is a property of the scheme, not
        # an artefact of the fit.
        #
        # The projection uses the SLOPE, never cost(1)*N: a single search costs
        # `fixed + per_candidate`, where `fixed` is trapdoor generation and query
        # planning done once per query. Multiplying that by N would charge the
        # setup a million times over and inflate this baseline -- and inflating a
        # baseline inflates our own advantage.
        result, projection = experiments.experiment_2_projected(
            workload,
            index_sizes=sweep.select(EXP2_INDEX_SIZES, points),
            q=DEFAULT_Q,
            repetitions=args.runs,
            warmups=args.warmups,
        )
        _PROJECTION_PROVENANCE.update(projection)
        return result
    return experiments.experiment_3(
        workload,
        domain_counts=sweep.select(EXP3_DOMAIN_COUNTS, points),
        total_index_size=EXP3_TOTAL_INDEX_SIZE,
        q=DEFAULT_Q,
        repetitions=args.runs,
        warmups=args.warmups,
        max_seconds_per_run=args.max_seconds_per_run,
    )


def _print_banner(
    reportable: bool, blockers: Sequence[str], parameters: Dict[str, Any]
) -> None:
    print(f"Ref[41] Thingom PQ-ABSE  |  reportable={reportable}")
    print(
        f"  pairing={parameters['pairing_backend']} "
        f"({parameters['pairing_type']})  u={parameters['attribute_count_u']}  "
        f"runs={parameters['repetitions']}"
    )
    for blocker in blockers:
        print(f"  NOT REPORTABLE: {blocker}")


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
    sys.exit(main())
