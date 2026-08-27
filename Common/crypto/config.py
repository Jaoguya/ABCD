"""Loader for ``Experiment Configuration/crypto.yaml``.

Every cryptographic parameter used anywhere in the benchmark is read through
this module. Scheme source must never hardcode a parameter value, because
``run_meta.json`` records the hash of the config file as provenance for the
numbers a run produces (README §7) — a hardcoded value would be invisible to
that record.
"""

from __future__ import annotations

import hashlib
import platform
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

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
            f"directory (README §8)."
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


def _detect_aws_instance_type(timeout: float = 0.3) -> Optional[str]:
    """Best-effort EC2 instance type of the host actually running this process.

    Reads the IMDSv2 metadata service (token-gated, so IMDSv1-disabled hosts
    still answer). Returns ``None`` off EC2 — a Mac, a personal PC, any
    non-AWS box — never raises: this sits behind ``environment_report()``,
    which every run_meta.json gets, reportable or not, so a 0.3s stall or a
    dev laptop with no route to 169.254.169.254 must not block a run.
    """
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
        return None


def verify_experiment_host(*, require: bool = False) -> Dict[str, Any]:
    """Confirm this run is on the pinned AWS experiment host (README §1).

    README §1 pins one experiment host and §V claims all schemes were
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
    expected = str(get("environment", "instance_type", path=GLOBAL_CONFIG_PATH))
    detected = _detect_aws_instance_type()
    is_pinned_host = detected == expected
    report: Dict[str, Any] = {
        "expected_instance_type": expected,
        "detected_instance_type": detected,
        "platform": platform.platform(),
        "is_pinned_experiment_host": is_pinned_host,
    }
    if require and not is_pinned_host:
        raise ConfigError(
            f"not running on the pinned experiment host: expected AWS "
            f"{expected!r}, detected {detected or 'no EC2 metadata service reachable'!r} "
            f"on {report['platform']!r}. README §1: only the pinned AWS host "
            f"produces reportable results."
        )
    return report


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
