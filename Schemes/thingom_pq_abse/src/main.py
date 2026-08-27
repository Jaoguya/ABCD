"""Runner for Ref[41] — Thingom et al. PQ-ABSE.

    python -m Schemes.thingom_pq_abse.src.main --experiment 1,2,3 \
        --dataset Dataset/derived --runs 30

A run is REPORTABLE only when every one of these holds:

  * the pairing backend is the published Type-I curve (charm SS512), and
  * the corpus verifies against its frozen manifest AND the dataset.yaml pin,
    with ``corpus_type: synthea``, and
  * this process is actually running on the pinned AWS experiment host
    (``global.yaml``'s ``environment.instance_type``), not a development
    laptop or any other machine (README §1).

Anything else still runs — development on Windows is expected (README §1) —
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
from Common.crypto.config import REPO_ROOT, ConfigError, get, verify_experiment_host

from . import experiments
from .harness import write_all

# README §6 defaults. These live here rather than in a config file because
# "Experiment Configuration/global.yaml" — referenced by SCHEME.md and
# README §8 — does not exist in the repository yet. Every value that affects
# a NUMBER (attribute count, pairing curve) is read from crypto.yaml instead,
# so it is covered by the config hash in run_meta.json.
DEFAULT_REPETITIONS = 30
DEFAULT_WARMUPS = 5
DEFAULT_Q = 5
DEFAULT_INDEX_SIZE = 10**5
DEFAULT_DOMAINS = 4
DEFAULT_SEED = 20260804

EXP1_Q_VALUES = list(range(1, 21))
EXP2_INDEX_SIZES = [10**4, 10**5, 10**6]
EXP3_DOMAIN_COUNTS = list(range(2, 11))

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
        default=1800.0,
        help=(
            "per-point wall-clock budget. Points whose estimated cost exceeds "
            "it are recorded as status=failed rather than attempted."
        ),
    )
    return parser.parse_args(argv)


def resolve_experiments(spec: str) -> List[str]:
    if spec.strip().lower() == "all":
        return ["1", "2", "3"]
    selected = [item.strip() for item in spec.split(",") if item.strip()]
    unknown = [item for item in selected if item not in OUTPUT_DIRS]
    if unknown:
        raise SystemExit(
            f"Ref[41] runs experiments 1, 2 and 3 only (SCHEME.md); "
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
                f"(README §15)"
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
            f"(README §1). It is Linux-only."
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
    if not host["is_pinned_experiment_host"]:
        host_blockers.append(
            f"not running on the pinned AWS experiment host: expected "
            f"{host['expected_instance_type']!r}, detected "
            f"{host['detected_instance_type'] or 'not EC2'!r} on "
            f"{host['platform']!r} (README §1)"
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
    }

    _print_banner(reportable, blockers, parameters)

    for number in selected:
        result = _run_one(number, workload, args)
        directory = output_root / OUTPUT_DIRS[number]
        write_all(
            directory,
            result,
            started_utc=started,
            dataset_manifest=manifest,
            parameters={**parameters, "columns": result.columns},
            reportable=reportable,
            reportable_blockers=blockers,
        )
        ok = sum(1 for run in result.runs if run.status == "ok")
        try:
            shown = directory.relative_to(REPO_ROOT)
        except ValueError:  # --output pointed outside the repository
            shown = directory
        print(f"  exp{number}: {ok}/{len(result.runs)} runs ok -> {shown}")

    return 0


def _run_one(number: str, workload: experiments.Workload, args: argparse.Namespace):
    if number == "1":
        return experiments.experiment_1(
            workload,
            q_values=EXP1_Q_VALUES,
            repetitions=args.runs,
            warmups=args.warmups,
        )
    if number == "2":
        return experiments.experiment_2(
            workload,
            index_sizes=EXP2_INDEX_SIZES,
            q=DEFAULT_Q,
            repetitions=args.runs,
            warmups=args.warmups,
            max_seconds_per_run=args.max_seconds_per_run,
        )
    return experiments.experiment_3(
        workload,
        domain_counts=EXP3_DOMAIN_COUNTS,
        shard_size=DEFAULT_INDEX_SIZE // DEFAULT_DOMAINS,
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
