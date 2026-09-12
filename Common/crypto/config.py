"""Loader for ``Experiment Configuration/crypto.yaml``.

Every cryptographic parameter used anywhere in the benchmark is read through
this module. Scheme source must never hardcode a parameter value, because
``run_meta.json`` records the hash of the config file as provenance for the
numbers a run produces (skill.md) — a hardcoded value would be invisible to
that record.
"""

from __future__ import annotations

import hashlib
import functools
import os
import platform
import shutil
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Common/crypto/config.py -> Common/crypto -> Common -> <repo root>
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "Experiment Configuration"
CRYPTO_CONFIG_PATH = CONFIG_DIR / "crypto.yaml"
DATASET_CONFIG_PATH = CONFIG_DIR / "dataset.yaml"
GLOBAL_CONFIG_PATH = CONFIG_DIR / "global.yaml"

_cache: Dict[Path, Dict[str, Any]] = {}
_cache_lock = threading.Lock()


class ConfigError(RuntimeError):
    """Raised when a config file is missing, malformed, or lacks a key."""


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise ConfigError(
            f"config file not found: {path}\n"
            f"Expected it at the repository's 'Experiment Configuration/' "
            f"directory (skill.md)."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ConfigError(f"config file is not a YAML mapping: {path}")
    return data


def load(path: Path = CRYPTO_CONFIG_PATH, *, reload: bool = False) -> Dict[str, Any]:
    """Return the parsed config, cached per path.

    The cache exists so that a tight measurement loop does not re-read and
    re-parse YAML between repetitions, which would show up in the timings.
    """
    with _cache_lock:
        if reload or path not in _cache:
            _cache[path] = _load_yaml(path)
        return _cache[path]


def load_dataset_config(*, reload: bool = False) -> Dict[str, Any]:
    """Return the parsed ``dataset.yaml``."""
    return load(DATASET_CONFIG_PATH, reload=reload)


def get(*keys: str, path: Path = CRYPTO_CONFIG_PATH) -> Any:
    """Fetch a nested config value, e.g. ``get("global", "aead", "key_bits")``.

    Raises ConfigError naming the full key path when a key is absent, so a
    typo in a scheme fails loudly at setup instead of silently defaulting to
    something that would quietly change a reported number.
    """
    node: Any = load(path)
    walked: list[str] = []
    for key in keys:
        walked.append(key)
        if not isinstance(node, dict) or key not in node:
            raise ConfigError(
                f"missing key {'.'.join(walked)!r} in {path.name}"
            )
        node = node[key]
    return node


def scheme_params(scheme: str) -> Dict[str, Any]:
    """Return the whole parameter block for one scheme.

    ``scheme`` is the folder name under ``Schemes/`` — e.g. ``guo_vdsse``.
    """
    return get(scheme)


@functools.lru_cache(maxsize=1)
def _detect_aws_instance_type(
    timeout: float = 2.0, attempts: int = 3
) -> Optional[str]:
    """Best-effort EC2 instance type of the host actually running this process.

    Reads the IMDSv2 metadata service (token-gated, so IMDSv1-disabled hosts
    still answer). Returns ``None`` off EC2 — a Mac, a personal PC, any
    non-AWS box — never raises: this sits behind ``environment_report()``,
    which every run_meta.json gets, reportable or not, so a stall or a dev
    laptop with no route to 169.254.169.254 must not block a run.

    The timeout was 0.3s and applied twice, which is not enough on a box doing
    what this repo does to boxes. Both fleet nodes returned ``None`` here while
    at 100% CPU mid index-build (one at 14.1 GB RSS), with IMDS demonstrably
    healthy: HttpEndpoint enabled, HttpTokens required, hop limit 2, and the v2
    handshake below is correct. A probe that reports "not on the pinned host"
    because the host was BUSY is measuring load, not identity.

    None of this is on a timed path — every caller is a provenance or
    reportability check (``provenance.py``, each scheme's ``harness.py``,
    ``environment_report()``), never a measurement loop — so seconds spent here
    change no reported number.

    Cached: a process cannot migrate between instances, so the answer is fixed
    for its lifetime. Without this the retries would be paid at every call site
    -- and off EC2, where all three attempts always expire, that is the full
    ``attempts * timeout`` each time.
    """
    for attempt in range(attempts):
        try:
            token_request = urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            )
            with urllib.request.urlopen(token_request, timeout=timeout) as resp:
                token = resp.read().decode("utf-8")
            type_request = urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/instance-type",
                headers={"X-aws-ec2-metadata-token": token},
            )
            with urllib.request.urlopen(type_request, timeout=timeout) as resp:
                return resp.read().decode("utf-8").strip()
        except (urllib.error.URLError, OSError, TimeoutError):
            # Off EC2 this fails identically every time, so the retries cost a
            # dev laptop `attempts * timeout` once per run and nothing else.
            if attempt == attempts - 1:
                return None
    return None


def verify_experiment_host(*, require: bool = False) -> Dict[str, Any]:
    """Confirm this run is on the pinned AWS experiment host (skill.md).

    skill.md pins one experiment host and §V claims all schemes were
    measured on identical hardware; a figure produced anywhere else — this
    laptop, a personal PC, any other AWS box — would make that false (see
    ``MacOS/SETUP.md``). This checks the live EC2 metadata service against
    ``global.yaml``'s ``environment.instance_type`` rather than trusting a
    caller-supplied value, the same reasoning ``provenance.git_commit()``
    uses for the commit hash.

    ``require=True`` raises when the host does not match, for entry points
    that must refuse to proceed at all. The default ``require=False`` just
    returns the finding, so it is recorded in every run_meta.json — including
    non-reportable dev runs, where seeing *why* a run does not count matters
    as much as the reportable ones.
    """
    # THE PIN IS NOW OPTIONAL. global.yaml's environment.instance_type was
    # dropped on the user's instruction so guo and thingom can run on hosts
    # sized for their actual memory and core needs; §V discloses the hosts
    # instead of claiming one type. get() raises on a missing key, and every
    # scheme calls this, so an absent pin must be a STATE rather than an error
    # -- deleting the line without this would brick all five harnesses.
    #
    # Three states, kept distinct because they mean different things:
    #   no pin configured   -> nothing to violate; the host is not evidence
    #                          for or against a run
    #   pinned and matched  -> as before
    #   pinned and mismatch -> as before, still condemns the run
    try:
        raw = get("environment", "instance_type", path=GLOBAL_CONFIG_PATH)
    except ConfigError:
        raw = None
    expected = (
        None
        if raw is None or str(raw).strip().lower() in ("", "none", "null", "~")
        else str(raw)
    )
    pin_configured = expected is not None
    detected = _detect_aws_instance_type()
    # False when unpinned: there is no pinned host, so nothing can BE it.
    # Truth here would read as "we verified the host" to anyone skimming.
    is_pinned_host = pin_configured and detected == expected
    report: Dict[str, Any] = {
        "expected_instance_type": expected,
        "detected_instance_type": detected,
        "platform": platform.platform(),
        "pin_configured": pin_configured,
        "is_pinned_experiment_host": is_pinned_host,
        # What reportability should gate on, and the ONLY field that changed
        # meaning: "no host rule was broken". Unpinned runs satisfy it
        # vacuously; pinned ones satisfy it only by matching. Callers that
        # gated on is_pinned_experiment_host would now reject every run under
        # an unpinned config, which is not what dropping the pin meant.
        "host_check_satisfied": (not pin_configured) or is_pinned_host,
        # "could not ask" and "asked, wrong answer" both produced
        # is_pinned_experiment_host=False and were indistinguishable in the
        # record. They mean opposite things: the first says nothing about the
        # host, the second condemns it. Record which one happened.
        "metadata_reachable": detected is not None,
    }
    if require and not report["host_check_satisfied"]:
        raise ConfigError(
            f"not running on the pinned experiment host: expected AWS "
            f"{expected!r}, detected {detected or 'no EC2 metadata service reachable'!r} "
            f"on {report['platform']!r}. skill.md: only the pinned AWS host "
            f"produces reportable results."
        )
    return report


def _all_config_files() -> List[Path]:
    """Every file under CONFIG_DIR, not just the top-level ``*.yaml``.

    ``config_hashes()`` globs ``*.yaml`` and so covers four of the eight files;
    it feeds run_meta.json and its coverage is deliberately left alone here so
    recorded provenance hashes do not change meaning. The GUARD below wants
    everything, including ``planning/runtime_estimates.csv`` and the two
    ``workload/*.yaml`` files.
    """
    files = [p for p in CONFIG_DIR.rglob("*") if p.is_file()]
    # The CORPUS MANIFEST belongs in the guard too, and it is not under
    # CONFIG_DIR. The fix that pins query selection guarantees every shard
    # draws from records[:reference_n] with the same rng -- it does NOT
    # guarantee every shard has the same `records`. Five processes on one node
    # read one file, so it holds by accident; it stops holding the moment
    # shards run on separate instances, which is exactly what global.yaml's
    # `granularity: sweep_point` is for.
    #
    # Not hypothetical: README's 2026-08-27 entry records the frozen corpus
    # being "lost and regenerated non-identically". Two shards measuring
    # different corpora and reporting one curve is the same silent
    # disagreement the query-set bug produced, wearing different clothes.
    manifest = REPO_ROOT / "Dataset" / "dataset_manifest.json"
    if manifest.is_file():
        files.append(manifest)
    return sorted(files)


def _guard_key(path: Path) -> str:
    """Stable name for a guarded file, for files inside CONFIG_DIR or outside."""
    try:
        return path.relative_to(CONFIG_DIR).as_posix()
    except ValueError:
        return path.relative_to(REPO_ROOT).as_posix()


_CONFIG_BASELINE: Optional[Dict[str, str]] = None
_CONFIG_SNAPSHOT_DIR: Optional[Path] = None


def snapshot_config_state() -> Dict[str, str]:
    """Hash every config file and copy it OUTSIDE the repo. Idempotent.

    Called once at process start. The copy exists so a run that trips the
    guard can be diagnosed -- and recovered -- against what it actually
    started with, rather than against whatever the tree holds afterwards.

    Why this exists: the whole ``Experiment Configuration`` directory was
    emptied mid-session on 2026-08-30 while a campaign was being prepared, and
    it had happened twice earlier the same day. global.yaml carries the sweep
    values, the query width and the thread count, so a long run that continued
    across a change to it would silently produce points measured under two
    different configurations with nothing in the record to say so.
    """
    global _CONFIG_BASELINE, _CONFIG_SNAPSHOT_DIR
    if _CONFIG_BASELINE is not None:
        return _CONFIG_BASELINE

    baseline: Dict[str, str] = {}
    dest = Path(tempfile.gettempdir()) / f"ojcoms-config-snapshot-{os.getpid()}"
    for path in _all_config_files():
        rel = _guard_key(path)
        baseline[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        except OSError:
            # A snapshot we cannot write is not a reason to refuse to run --
            # the hashes are what enforce the guard, the copy only aids
            # recovery. Degrade rather than block.
            pass
    _CONFIG_BASELINE = baseline
    _CONFIG_SNAPSHOT_DIR = dest
    return baseline


def assert_config_unchanged() -> None:
    """Raise if any config file changed, appeared or vanished since start.

    Call at sweep-point boundaries. Aborting a run at hour six is expensive;
    finishing one whose later points were measured under different parameters,
    and not knowing which, is worse -- that produces a figure nobody can
    defend and no way to tell which points are affected.

    A no-op before ``snapshot_config_state()`` has run, so importing this
    module never imposes the check on callers that did not ask for it.
    """
    if _CONFIG_BASELINE is None:
        return
    current = {
        _guard_key(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in _all_config_files()
    }
    problems: List[str] = []
    for rel, digest in sorted(_CONFIG_BASELINE.items()):
        if rel not in current:
            problems.append(f"{rel}: DELETED since the run started")
        elif current[rel] != digest:
            problems.append(
                f"{rel}: MODIFIED since the run started "
                f"({digest[:12]} -> {current[rel][:12]})"
            )
    for rel in sorted(set(current) - set(_CONFIG_BASELINE)):
        problems.append(f"{rel}: APPEARED after the run started")
    if problems:
        raise ConfigError(
            "experiment configuration changed mid-run; aborting so that no "
            "figure mixes points measured under different parameters:\n  "
            + "\n  ".join(problems)
            + (
                f"\nthe configuration this run started with was copied to "
                f"{_CONFIG_SNAPSHOT_DIR}"
                if _CONFIG_SNAPSHOT_DIR is not None
                else ""
            )
        )


def config_hashes() -> Dict[str, str]:
    """SHA-256 of each config file, for embedding in ``run_meta.json``.

    Hashing the file bytes (rather than the parsed dict) means a comment-only
    edit still changes the recorded hash. That is deliberate: the comments in
    crypto.yaml carry the published-vs-benchmark provenance of each value, and
    a reviewer tracing a number back should see that the annotation changed.
    """
    hashes: Dict[str, str] = {}
    for path in sorted(CONFIG_DIR.glob("*.yaml")):
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def available_memory_bytes() -> Optional[int]:
    """Bytes of memory actually available to a new allocation, or None.

    ``MemAvailable`` on Linux, which is the kernel's own estimate of what a
    workload can claim without swapping -- not ``MemFree``, which excludes
    reclaimable page cache and would understate headroom by tens of GB on a
    box that has just written a corpus.

    Returns None rather than guessing when it cannot tell (macOS, a container
    with no /proc). A guard that cannot measure must not block a run; every
    caller treats None as "unknown, proceed".
    """
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    try:  # POSIX fallback: free pages only, so this UNDERSTATES availability
        return os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None


def assert_memory_for(projected_bytes: float, label: str, *, margin: float = 1.25) -> None:
    """Refuse to start a point that will not fit, instead of being OOM-killed.

    An OOM kill arrives as SIGKILL: no traceback, no partial results, no line
    in the log saying what happened. The 2026-08-28 campaign died exactly that
    way (rc=137, anon-rss 15.67 GB) and the cause had to be reconstructed
    afterwards from instance metrics. Failing here instead costs one clear
    message before any time is spent on the point.

    ``margin`` is headroom over the projection, not over the measurement --
    these projections come from bytes-per-record figures that are themselves
    extrapolations, so 1.25 covers ordinary error, not a wrong model.

    Unknown availability proceeds: see ``available_memory_bytes``.
    """
    available = available_memory_bytes()
    if available is None:
        return
    needed = projected_bytes * margin
    if available < needed:
        raise ConfigError(
            f"refusing to start {label}: projects "
            f"{projected_bytes / 2**30:.1f} GiB, needs "
            f"{needed / 2**30:.1f} GiB with a {margin:.2f}x margin, but only "
            f"{available / 2**30:.1f} GiB is available. Use a larger host or "
            f"drop this point -- proceeding would be OOM-killed with no "
            f"partial results and no traceback."
        )
