"""``run_meta.json`` — provenance for every result, per README §7.

"Each ``results.csv`` gets a ``run_meta.json``: git commit, instance type, Python
and library versions, dataset SHA-256, corpus type, config hashes, UTC start
time."

The point of this file is that a number in the paper can be traced back to the
tree, the corpus and the host that produced it. So every field is **read from the
environment, never supplied by a caller** — a provenance record that could be
passed the commit it claims would record what someone believed rather than what
ran.

:func:`reportability` collects the conditions required for a result to
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
from Common.crypto.config import REPO_ROOT, verify_experiment_host  # noqa: E402

from .. import config as scheme_config  # noqa: E402

SCHEME_NAME = "ma_lb_pq_vdse"


#: Paths a run necessarily rewrites as it produces output, so their being
#: modified says nothing about whether the CODE was modified.
#:
#: This exclusion exists because the unscoped check could never fire usefully.
#: Result directories are git-TRACKED and not ignored, and ``fleet.sh deploy``
#: restores them onto every node before a run; the run then overwrites
#: ``results.csv`` / ``raw_runs.csv`` and stamps ``run_meta.json`` afterwards.
#: So ``git status --porcelain`` was already non-empty at stamp time and EVERY
#: fleet run recorded ``-dirty`` by construction -- the eight Exp. 7-8 result
#: dirs at 0536312 all carry it. A marker that is always on cannot distinguish
#: a modified scheme from an experiment writing its own output, which is the
#: one thing it exists to do.
_OUTPUT_ARTIFACTS = (
    "results.csv",
    "raw_runs.csv",
    "run_meta.json",
    # Written by harness/lambda_sweep.py into exp7_search_throughput/. It is a
    # run's output like any other, so regenerating it must not mark the tree
    # dirty -- and infra/fleet.sh's deploy-restore must preserve it for the same
    # reason. Keep the two lists in step.
    "lambda_sweep.csv",
)


def _is_own_output(path: str) -> bool:
    """True for a path that is a run's own output rather than its inputs."""
    parts = path.split("/")
    if parts[:1] == ["Plots"] and parts[1:2] == ["output"]:
        return True
    # Schemes/<scheme>/<exp-dir>/<artifact>
    return (
        len(parts) == 4
        and parts[0] == "Schemes"
        and parts[2].startswith("exp")
        and parts[3] in _OUTPUT_ARTIFACTS
    )


def _dirty_paths() -> List[str]:
    """Uncommitted paths that could actually change what a run measures.

    ``git status --porcelain`` over the whole repo, minus the run's own output.
    Anything else still counts -- source, config, dataset, infra -- so a genuinely
    modified tree is still caught.
    """
    # -uall: without it git collapses an untracked directory to a single
    # "Schemes/<scheme>/<exp-dir>/" entry, which _is_own_output cannot classify
    # (it has no filename) and which therefore counted as dirty. Measured on the
    # fleet: an untracked exp6 result dir marked a host dirty on its own.
    status = subprocess.run(
        ["git", "status", "--porcelain", "-uall"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    dirty = []
    for line in status.stdout.splitlines():
        if not line.strip():
            continue
        # "XY path" and "XY orig -> path" for renames; take the destination.
        path = line[3:].strip().split(" -> ")[-1].strip('"')
        if not _is_own_output(path):
            dirty.append(path)
    return dirty


def git_commit() -> str:
    """The commit that produced this result, or an explicit marker.

    ``unknown`` rather than a guess when git cannot answer: an invented hash in a
    provenance record is worse than an admitted gap. ``-dirty`` is appended when
    the tree has uncommitted changes, because a result from a modified tree cannot
    be reproduced from the commit alone -- EXCLUDING the run's own output, which
    every run rewrites and which therefore made the marker fire unconditionally.
    See :data:`_OUTPUT_ARTIFACTS`.
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
        return f"{sha}-dirty" if _dirty_paths() else sha
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
    #: What the config PINNED, or "unknown" once c457e28 dropped the pin. It is
    #: not what the run executed on, so it cannot answer "which host produced
    #: this number" -- see ``experiment_host``.
    instance_type: str
    #: What the run ACTUALLY executed on, from the EC2 metadata service. Every
    #: baseline scheme has recorded this since c457e28; this scheme did not, so
    #: with the pin dropped its results carried no recoverable host at all. §V
    #: discloses the host per scheme, which needs it recorded per run.
    experiment_host: Dict[str, Any]
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


def _expected_corpus_sha256() -> Optional[str]:
    """dataset.yaml's ``freeze.expected_corpus_sha256``, or None if unset.

    Returns None rather than raising when the config or key is absent: an
    unset pin means the campaign has not been frozen yet, which is a legitimate
    early state, not a reportability failure on its own.
    """
    try:
        from Common.crypto.config import load_dataset_config

        freeze = (load_dataset_config().get("freeze") or {})
        pinned = freeze.get("expected_corpus_sha256")
        return str(pinned) if pinned else None
    except Exception:  # noqa: BLE001 - a missing/unreadable pin must not crash a run
        return None


#: A result is superseded when the code that produced it is known to have had a
#: defect that changes what the experiment measures. This is a fact about this
#: repo's history, not a tunable, which is why it lives here rather than in
#: config: 5cf65f9 fixed three such defects in Exp. 7-8 -- every arm paid AASS's
#: cost vector, the queue feedback loop was dead so `least_loaded` collapsed onto
#: `no_lb`, and prepare() built 32 records against README §6's 10^5. Numbers from
#: before it are not comparable with numbers from after it.
#:
#: Judged at READ time from the commit the record already carries. A stamped
#: run_meta.json is never rewritten -- this module's contract is that provenance
#: is measured, never supplied, and editing a record to say what we now believe
#: would make it a statement of belief. So the record keeps saying what it said,
#: and the reader derives the consequence.
SUPERSEDED_BEFORE: Dict[int, str] = {
    7: "5cf65f9b8c0323252f604dd3ae2f8f0a599435b1",
    8: "5cf65f9b8c0323252f604dd3ae2f8f0a599435b1",
}


def _is_ancestor(older: str, newer: str) -> Optional[bool]:
    """True if ``older`` is an ancestor of ``newer``; None if git cannot say.

    None rather than False when the answer is unknown -- a shallow clone or a
    missing object must not silently downgrade to "not superseded".
    """
    try:
        proc = subprocess.run(
            ["git", "merge-base", "--is-ancestor", older, newer],
            cwd=REPO_ROOT, capture_output=True, timeout=10,
        )
    except Exception:  # noqa: BLE001
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None  # 128: unknown revision, shallow clone, not a repo


def superseded_reason(experiment_number: int, git_commit: str) -> Optional[str]:
    """Why an already-written result should not be quoted, or None.

    ``git_commit`` is taken verbatim from a run_meta.json, so it may carry the
    ``-dirty`` suffix; the suffix is stripped before the ancestry test because
    dirtiness is a separate question from staleness.
    """
    boundary = SUPERSEDED_BEFORE.get(experiment_number)
    if not boundary or not git_commit:
        return None
    sha = git_commit[:-len("-dirty")] if git_commit.endswith("-dirty") else git_commit
    if sha == "unknown":
        return (
            f"Exp. {experiment_number}: the producing commit is unknown, so it "
            f"cannot be shown to postdate {boundary[:9]}"
        )
    older = _is_ancestor(sha, boundary)
    if older is None:
        return (
            f"Exp. {experiment_number}: cannot determine whether {sha[:9]} "
            f"predates {boundary[:9]} (commit not present in this clone)"
        )
    if older and sha != boundary:
        return (
            f"Exp. {experiment_number}: produced at {sha[:9]}, which predates "
            f"{boundary[:9]} -- that commit fixed the shared costing overhead, "
            f"the dead queue loop and the 32-record index, so this result does "
            f"not measure what the experiment now measures"
        )
    return None


def reportability(
    config: scheme_config.Configuration,
    *,
    experiment: str,
    corpus_type: str,
    corpus_sha256: Optional[str],
    group_faithful: bool,
    token_scheme_keyed: Optional[bool],
    ledger_faithful: bool = False,
    fsn_processes: int = 0,
) -> Tuple[bool, List[str]]:
    """Every condition a quotable number must satisfy, and which ones failed.

    Each entry corresponds to a decision recorded in ``SCHEME.md``. Collected in
    one place so a runner cannot report a figure by forgetting a check, and so the
    reasons land in ``run_meta.json`` where a reader can see them.
    """
    reasons: List[str] = []

    host = verify_experiment_host()
    if not host["host_check_satisfied"]:
        reasons.append(
            f"not running on the pinned AWS experiment host: expected "
            f"{host['expected_instance_type']!r}, detected "
            f"{host['detected_instance_type'] or 'not EC2'!r} on "
            f"{host['platform']!r} (README §1)"
        )

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
    else:
        # The message above promised a comparison against the frozen pin, but
        # nothing here performed one: a run against a DIFFERENT corpus than the
        # campaign was frozen on would have passed this gate and been marked
        # reportable, which is precisely the silent data swap
        # dataset.yaml's freeze pin exists to prevent (README §13, "The corpus
        # is frozen"). Dataset/corpus.py guards its own loader, but a scheme
        # that obtains a digest another way bypassed that entirely. Checked
        # here so the gate matches what it claims. Added 2026-08-28.
        pinned = _expected_corpus_sha256()
        if pinned and pinned != corpus_sha256:
            reasons.append(
                f"corpus SHA-256 {corpus_sha256[:12]}... does not match "
                f"dataset.yaml's frozen pin {pinned[:12]}...; results from a "
                f"different corpus are not comparable to the campaign "
                f"(README §13). Either restore the frozen corpus or re-freeze "
                f"and re-run EVERY scheme."
            )

    if not group_faithful:
        reasons.append(
            "the bilinear group came from an injected provider, not a faithful "
            "Type-III backend (crypto.yaml: backend_implemented: false)"
        )

    # Scoped to the experiments whose MEASURED path actually touches the chain,
    # rather than blanket. Exp. 1/2/3/5/6/7/8 never read or write the ledger on a
    # timed path, so blocking them on it would be a false blocker -- and a gate
    # that fires when it should not trains readers to ignore it.
    #
    # Exp. 6 WAS listed here (451df65, 2026-08-28) on the grounds that it "times
    # DIAS through to blockchain anchoring (README §5, Phase VII Step 5)". Removed
    # 2026-09-03: that justification cited a PROTOCOL STEP, not a measurement
    # boundary, and it does not hold against the code. ``sync/ias.py::synchronize``
    # takes ``ledger`` as OPTIONAL and anchors only inside ``if ledger is not
    # None``; Exp. 6's runner has never passed one, so Step 7 is not on its timed
    # path. Two independent sources agree it is outside the boundary: README §5
    # ends Exp. 6 at "until all affected FSNs report the new VID", and
    # ``tab:cost``'s authorization-synchronization row is O(delta)T_H +
    # O(log d)T_MT with no chain term. Exp. 4 keeps the gate because §5 puts
    # "chain consistency" INSIDE its boundary in as many words.
    #
    # §V must state the exclusion and report anchoring separately -- the treatment
    # README §5 already gives ML-KEM encapsulation in Exp. 1. If Phase VII Step 5
    # is ever brought inside the boundary, the runner must pass a ledger and
    # ``exp6_authorization_sync`` must come back into this tuple.
    if experiment in ("exp4_verification_overhead",) and not ledger_faithful:
        # README §1 states the ledger is Hyperledger Fabric v2.5, but the
        # harness runs chain.ledger.InProcessLedger -- whose OWN docstring says
        # it is "NOT a substitute for Fabric once Fog Search Nodes become
        # independent processes" and that "Exp. 4 is where it starts to be
        # measured". Exp. 4 reports verification overhead (Merkle proof +
        # commitment recomputation + CHAIN CONSISTENCY), so an in-memory hash
        # chain understates the anchoring cost the paper claims. That gap was
        # documented in the ledger module but never reached run_meta.json, so a
        # figure could have been quoted without it travelling along. Added
        # 2026-08-28.
        reasons.append(
            "the ledger is an in-process hash chain, not the Hyperledger "
            "Fabric v2.5 deployment README §1 specifies; Exp. 4's chain-"
            "consistency cost is therefore understated (see "
            "chain/ledger.py::InProcessLedger)"
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
        # Was an UNCONDITIONAL blocker: the harness had no multi-process path,
        # so declaring the requirement in global.yaml could only ever fail it.
        # fsn/pool.py now runs one forked worker per node, so this checks
        # whether the run ACTUALLY used that path rather than whether the
        # requirement is declared. Passing fsn_processes=N (N>1) is the
        # evidence; the runner takes it from the live pool's worker PIDs, so it
        # cannot be asserted by a caller that did not spawn them.
        if config.topology.independent_processes and not fsn_processes:
            reasons.append(
                "README §1 requires each FSN to be an independent process; this "
                "run executed them in one interpreter, so a concurrency result "
                "would not measure the stated topology"
            )

    # WAS `!= 30`. Retargeted to 10 on the user's instruction, 2026-09-03, the
    # same day the campaign moved to 10 repetitions. Kept rather than removed:
    # this is the gate that stamps run_meta.json `reportable`, so its job is to
    # refuse any run whose replication count does not match what the manuscript
    # claims. That makes it the LAST line of defence against publishing a figure
    # whose n differs from section V's stated methodology.
    #
    # SECTION V MUST NOW SAY 10, NOT 30. If it still reads "the average of 30
    # independent runs" when the paper is submitted, this check is passing runs
    # that the text misdescribes -- which is the exact failure it exists to
    # prevent, just pointed the other way.
    #
    # Note the statistical consequence, which is not cosmetic: the 95% t
    # multiplier is 2.26 at n=10 against 2.05 at n=30, so every confidence
    # interval widens by roughly 10% before any change in the underlying
    # variance. Intervals in the new figures are not comparable to the banked
    # ones on width alone.
    if config.measurement.repetitions != 10:
        reasons.append(
            f"measurement.repetitions is {config.measurement.repetitions}, not 10"
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
    ledger_faithful: bool = False,
    fsn_processes: int = 0,
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
        ledger_faithful=ledger_faithful,
        fsn_processes=fsn_processes,
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
        experiment_host=verify_experiment_host(),
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
