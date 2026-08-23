"""``run_meta.json`` — provenance for every result, per README §7.

"Each ``results.csv`` gets a ``run_meta.json``: git commit, instance type, Python
and library versions, dataset SHA-256, corpus type, config hashes, UTC start
time."

The point of this file is that a number in the paper can be traced back to the
tree, the corpus and the host that produced it. So every field is **read from the
environment, never supplied by a caller** — a provenance record that could be
passed the commit it claims would record what someone believed rather than what
ran.

:func:`reportability` collects the conditions AGENT_RULES requires for a result to
be quotable. It returns the failing reasons rather than a bool, because
``run_meta.json`` records *why* a run was not reportable, and "reportable: false"
with no reason is not provenance.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import environment_report  # noqa: E402
from Common.crypto.config import REPO_ROOT  # noqa: E402

from .. import config as scheme_config  # noqa: E402

SCHEME_NAME = "ma_lb_pq_vdse"


def git_commit() -> str:
    """The commit that produced this result, or an explicit marker.

    ``unknown`` rather than a guess when git cannot answer: an invented hash in a
    provenance record is worse than an admitted gap. ``-dirty`` is appended when
    the tree has uncommitted changes, because a result from a modified tree cannot
    be reproduced from the commit alone.
    """
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if commit.returncode != 0:
            return "unknown"
        sha = commit.stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return f"{sha}-dirty" if status.stdout.strip() else sha
    except Exception:
        return "unknown"


def library_versions() -> Dict[str, str]:
    """Versions of the libraries a measurement could depend on."""
    versions: Dict[str, str] = {}
    for name in ("numpy", "scipy", "bitarray", "mmh3", "cryptography", "pandas"):
        try:
            module = __import__(name)
            versions[name] = getattr(module, "__version__", "unknown")
        except Exception:
            versions[name] = "absent"
    return versions


@dataclass
class RunMetadata:
    """Everything README §7 requires, plus why the run is or is not reportable."""

    scheme: str
    experiment: str
    started_utc: str
    finished_utc: Optional[str]
    git_commit: str
    python_version: str
    platform: str
    instance_type: str
    libraries: Dict[str, str]
    crypto_backends: Dict[str, Any]
    config_hashes: Dict[str, str]
    corpus_type: str
    corpus_sha256: Optional[str]
    dataset_records: Optional[int]
    thread_pinning: Dict[str, Optional[str]]
    runs: int
    warmups: int
    confidence: float
    reportable: bool
    not_reportable_because: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        return path


def reportability(
    config: scheme_config.Configuration,
    *,
    experiment: str,
    corpus_type: str,
    corpus_sha256: Optional[str],
    group_faithful: bool,
    token_scheme_keyed: Optional[bool],
) -> Tuple[bool, List[str]]:
    """Every condition a quotable number must satisfy, and which ones failed.

    Each entry corresponds to a decision recorded in ``SCHEME.md``. Collected in
    one place so a runner cannot report a figure by forgetting a check, and so the
    reasons land in ``run_meta.json`` where a reader can see them.
    """
    reasons: List[str] = []

    if corpus_type not in config.corpus["reportable_types"]:
        reasons.append(
            f"corpus_type={corpus_type!r} is not reportable; README §4 admits "
            f"only {list(config.corpus['reportable_types'])}"
        )
    if corpus_sha256 is None:
        reasons.append(
            "no corpus SHA-256: the corpus was not loaded and verified against "
            "the frozen pin"
        )

    if not group_faithful:
        reasons.append(
            "the bilinear group came from an injected provider, not a faithful "
            "Type-III backend (crypto.yaml: backend_implemented: false)"
        )

    if token_scheme_keyed is False:
        reasons.append(
            "index tokens use an unkeyed H, which is invertible over the "
            "2,006-keyword vocabulary; the keyed/unkeyed choice is undecided"
        )
    elif token_scheme_keyed is None:
        reasons.append("no token scheme was resolved for this run")

    if experiment in ("exp7_search_throughput", "exp8_load_balance"):
        if not config.scheduler.weights.is_fixed:
            reasons.append(
                f"AASS weights are {config.scheduler.weights.status!r}; "
                f"README §14 issue #5 requires the documented hold-out sweep first"
            )
        if config.topology.independent_processes:
            reasons.append(
                "README §1 requires each FSN to be an independent process; the "
                "harness runs them in one interpreter, so a concurrency result "
                "would not measure the stated topology"
            )

    if config.measurement.repetitions != 30:
        reasons.append(
            f"measurement.repetitions is {config.measurement.repetitions}, not 30"
        )

    return (not reasons), reasons


def build_metadata(
    config: scheme_config.Configuration,
    *,
    experiment: str,
    corpus_type: str,
    corpus_sha256: Optional[str] = None,
    dataset_records: Optional[int] = None,
    group_faithful: bool = False,
    token_scheme_keyed: Optional[bool] = None,
    runs: Optional[int] = None,
    warmups: Optional[int] = None,
    notes: Optional[List[str]] = None,
) -> RunMetadata:
    """Assemble ``run_meta.json`` at the start of a run."""
    reportable, reasons = reportability(
        config,
        experiment=experiment,
        corpus_type=corpus_type,
        corpus_sha256=corpus_sha256,
        group_faithful=group_faithful,
        token_scheme_keyed=token_scheme_keyed,
    )
    return RunMetadata(
        scheme=SCHEME_NAME,
        experiment=experiment,
        started_utc=datetime.now(timezone.utc).isoformat(),
        finished_utc=None,
        git_commit=git_commit(),
        python_version=platform.python_version(),
        platform=platform.platform(),
        instance_type=str(config.environment.get("instance_type", "unknown")),
        libraries=library_versions(),
        crypto_backends=environment_report(),
        config_hashes=scheme_config.config_hashes(),
        corpus_type=corpus_type,
        corpus_sha256=corpus_sha256,
        dataset_records=dataset_records,
        thread_pinning=scheme_config.thread_pinning_report(),
        runs=config.measurement.repetitions if runs is None else runs,
        warmups=config.measurement.warmup_runs if warmups is None else warmups,
        confidence=config.measurement.confidence_interval,
        reportable=reportable,
        not_reportable_because=reasons,
        notes=list(notes or ()),
    )


__all__ = [
    "SCHEME_NAME",
    "RunMetadata",
    "git_commit",
    "library_versions",
    "reportability",
    "build_metadata",
]
