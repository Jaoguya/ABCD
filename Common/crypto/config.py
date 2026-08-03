"""Loader for ``Experiment Configuration/crypto.yaml``.

Every cryptographic parameter used anywhere in the benchmark is read through
this module. Scheme source must never hardcode a parameter value, because
``run_meta.json`` records the hash of the config file as provenance for the
numbers a run produces (README §7) — a hardcoded value would be invisible to
that record.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, Dict

import yaml

# Common/crypto/config.py -> Common/crypto -> Common -> <repo root>
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "Experiment Configuration"
CRYPTO_CONFIG_PATH = CONFIG_DIR / "crypto.yaml"
DATASET_CONFIG_PATH = CONFIG_DIR / "dataset.yaml"

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
