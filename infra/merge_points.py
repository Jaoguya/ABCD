#!/usr/bin/env python3
"""Reassemble the shards written by ``--points`` into one result set.

    python3 infra/merge_points.py Schemes/ma_lb_pq_vdse/exp7_search_throughput

Finds every ``<dir>__points-*`` sibling, concatenates their ``raw_runs.csv``,
re-aggregates, and writes a single ``results.csv`` + ``raw_runs.csv`` into
``<dir>``.

WHY RE-AGGREGATE RATHER THAN CONCATENATE results.csv
----------------------------------------------------
``results.csv`` holds means and 95% CIs. Averaging two shards' means is only
correct when they carry equal run counts, and a CI cannot be recovered from
other CIs at all. README §9 makes ``raw_runs.csv`` the source of truth — one row
per run, never aggregated — so the merge re-derives the aggregate from raw runs,
which is exactly what a single unsharded process would have produced.

WHAT IT REFUSES
---------------
A campaign assembled from shards that did not come from the same code, the same
corpus, or the same config is not one campaign. Every shard's ``run_meta.json``
must agree on ``git_commit``, ``dataset_sha256`` and ``config_hashes``, and a
disagreement is an error rather than a warning — silently merging them would
produce a figure whose points came from different systems.

Duplicate sweep values across shards are also an error: it means two instances
ran the same point, so the merged file would double-count it.

It also refuses when the base directory already holds results from a commit
NEWER than the shards. The merge overwrites the base, and stale shards left
behind by ``fleet.sh deploy`` would otherwise silently replace a good unsharded
re-run with an older campaign's data.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _shards(base: Path) -> List[Path]:
    return sorted(base.parent.glob(f"{base.name}__points-*"))


def _check_provenance(shards: List[Path], base: Path) -> Dict[str, object]:
    metas = {}
    for shard in shards:
        meta_path = shard / "run_meta.json"
        if not meta_path.exists():
            raise SystemExit(f"{shard.name}: no run_meta.json — cannot merge")
        metas[shard.name] = json.loads(meta_path.read_text())

    first_name, first = next(iter(metas.items()))

    # Corpus and config must match exactly -- a different corpus or a different
    # parameter set is a different experiment, full stop.
    for name, meta in metas.items():
        for key in ("dataset_sha256", "config_hashes"):
            if meta.get(key) != first.get(key):
                raise SystemExit(
                    f"shards disagree on {key!r}:\n"
                    f"  {first_name}: {first.get(key)!r}\n"
                    f"  {name}: {meta.get(key)!r}\n"
                    "These shards did not come from the same system; merging "
                    "them would produce a figure mixing two campaigns."
                )

    # git_commit is checked differently, on purpose. A bare hash comparison
    # rejects shards that ran IDENTICAL code merely because an unrelated commit
    # landed in between -- which happens whenever one straggler point is
    # relaunched. What actually matters is whether the code THIS SCHEME
    # executes differs. So compare the hashes, and when they differ, ask git
    # whether anything the scheme runs changed between them.
    commits = {m.get("git_commit") for m in metas.values()}
    if len(commits) > 1:
        scheme = first.get("scheme") or ""
        paths = [f"Schemes/{scheme}", "Common", "Experiment Configuration"]
        # A change to a DIFFERENT experiment's runner is irrelevant here: it
        # cannot affect what this one measured. Without this, one straggler
        # point relaunched after an unrelated experiment was edited blocks the
        # merge forever. Shared code (scheme.py, harness.py, config) has no
        # experiment number in its path and is therefore never excluded.
        import re as _re
        m = _re.search(r"exp(\d+)", base.name)
        this_exp = m.group(1) if m else None
        ordered = sorted(c for c in commits if c)
        drift = []
        for other in ordered[1:]:
            out = subprocess.run(
                ["git", "diff", "--name-only", f"{ordered[0]}..{other}", "--"]
                + paths,
                capture_output=True, text=True, cwd=REPO_ROOT)
            if out.returncode != 0:
                raise SystemExit(
                    f"shards span commits {ordered} and git could not compare "
                    f"them ({out.stderr.strip()[:120]}). Refusing to merge."
                )
            for ln in out.stdout.split():
                if not ln:
                    continue
                other_exp = _re.search(r"exp(\d+)", ln)
                if this_exp and other_exp and other_exp.group(1) != this_exp:
                    continue  # another experiment's runner
                drift.append(ln)
        if drift:
            raise SystemExit(
                f"shards span commits {ordered}, and code this scheme runs "
                f"changed between them:\n  "
                + "\n  ".join(sorted(set(drift))[:8])
                + "\nMerging them would mix two versions of the experiment. "
                "Re-run the older shards at the newer commit."
            )
        print(f"  note: shards span {len(commits)} commits, but nothing under "
              f"{', '.join(paths)} differs between them — merging.")
    return first


def _sha(commit: str) -> str:
    """A run_meta git_commit with any ``-dirty`` suffix stripped."""
    return commit[:-len("-dirty")] if commit.endswith("-dirty") else commit


def _refuse_if_base_is_newer(base: Path, shard_commit: str) -> None:
    """Refuse to overwrite a base directory that already holds NEWER results.

    merge() rewrites <base>/results.csv and raw_runs.csv from the shards. That
    is right when the shards ARE the run. It is destructive when the base was
    since re-run unsharded and the shards are leftovers from an older campaign
    that `fleet.sh deploy` restored onto the node.

    Real case this guards: perera_lv_pqabse/exp3_crossdomain_scalability holds a
    fresh full 9-point sweep, while its __points-2..10 siblings are stale
    restores. Merging would have replaced good data with old data and reported
    success.

    Fails CLOSED -- if git cannot place the two commits relative to each other,
    that is a refusal, not a pass.
    """
    meta_path = base / "run_meta.json"
    if not meta_path.exists():
        return
    try:
        base_commit = _sha(str(json.loads(meta_path.read_text()).get("git_commit", "")))
    except Exception:  # noqa: BLE001 - unreadable provenance is not a licence
        raise SystemExit(
            f"{base.name}/run_meta.json is unreadable; refusing to overwrite it."
        )
    shard_commit = _sha(shard_commit)
    if not base_commit or not shard_commit or base_commit == shard_commit:
        return

    proc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", shard_commit, base_commit],
        capture_output=True, cwd=REPO_ROOT,
    )
    if proc.returncode == 1:
        return  # shards are NEWER than the base: the normal, intended case
    if proc.returncode != 0:
        raise SystemExit(
            f"cannot place shard commit {shard_commit[:9]} relative to "
            f"{base.name}'s {base_commit[:9]}. Refusing to merge rather than "
            f"risk overwriting newer results with older ones."
        )
    raise SystemExit(
        f"{base.name} already holds results from {base_commit[:9]}, which is "
        f"NEWER than the shards' {shard_commit[:9]}.\n"
        f"Merging would overwrite good data with an older campaign's shards -- "
        f"most likely leftovers restored by `fleet.sh deploy`.\n"
        f"If the shards really are what you want, delete {base.name}/"
        f"results.csv and raw_runs.csv first, deliberately."
    )


def merge(base: Path, *, dry_run: bool = False) -> int:
    shards = _shards(base)
    if not shards:
        raise SystemExit(f"no shards found matching {base.name}__points-*")

    meta = _check_provenance(shards, base)
    _refuse_if_base_is_newer(base, str(meta.get("git_commit", "")))

    rows: List[Dict[str, str]] = []
    seen: Dict[str, str] = {}
    fieldnames: List[str] = []
    for shard in shards:
        raw = shard / "raw_runs.csv"
        if not raw.exists():
            raise SystemExit(f"{shard.name}: no raw_runs.csv")
        with raw.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = fieldnames or list(reader.fieldnames or [])
            for row in reader:
                value = row["variable_value"]
                if value in seen and seen[value] != shard.name:
                    raise SystemExit(
                        f"sweep value {value!r} appears in both "
                        f"{seen[value]} and {shard.name}; two instances ran the "
                        "same point and the merge would double-count it."
                    )
                seen[value] = shard.name
                rows.append(row)

    print(f"{base.name}: {len(shards)} shards, {len(rows)} runs, "
          f"{len(set(seen))} sweep points")
    for shard in shards:
        print(f"  {shard.name}")
    if dry_run:
        return 0

    base.mkdir(parents=True, exist_ok=True)
    out_raw = base / "raw_runs.csv"
    with out_raw.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Column NAMES for the aggregate are scheme-specific and are not
    # recoverable from raw_runs.csv: ma_lb writes `secondary_1_mean` while the
    # other schemes write the metric's real name (`trapdoors_issued_mean`).
    # Take them from a shard's own results.csv and map positionally, so the
    # merged file is byte-compatible with what Plots/generate_plots.py reads.
    _reaggregate(rows, base / "results.csv",
                 template=_result_columns(shards[0]))
    (base / "run_meta.json").write_text(
        json.dumps({**meta, "merged_from": [s.name for s in shards]}, indent=2)
        + "\n", encoding="utf-8",
    )
    print(f"  -> {out_raw.parent}/  (raw_runs.csv, results.csv, run_meta.json)")
    return 0


def _result_columns(shard: Path) -> List[str]:
    """The aggregate column names this scheme writes."""
    path = shard / "results.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh).fieldnames or [])


def _reaggregate(rows: List[Dict[str, str]], out: Path,
                 *, template: List[str]) -> None:
    """mean +/- 95% CI per sweep point, from the raw runs (README §7)."""
    import math
    from scipy import stats

    sec_cols = [c for c in rows[0] if c.startswith("secondary_metric_")]
    # Positional map: the i-th raw secondary column becomes the i-th
    # `*_mean`/`*_ci95` pair between primary_ci95 and n_runs.
    named = [f[: -len("_mean")] for f in template
             if f.endswith("_mean") and f != "primary_mean"]
    if named and len(named) != len(sec_cols):
        raise SystemExit(
            f"{out.parent.name}: results.csv names {len(named)} secondary "
            f"metrics but raw_runs.csv has {len(sec_cols)}; refusing to guess "
            "which is which."
        )
    labels = named or [c for c in sec_cols]
    groups: Dict[str, List[Dict[str, str]]] = {}
    for row in rows:
        groups.setdefault(row["variable_value"], []).append(row)

    def ci95(vals: List[float]) -> float:
        n = len(vals)
        if n <= 1:
            return 0.0
        mean = sum(vals) / n
        sd = math.sqrt(sum((v - mean) ** 2 for v in vals) / (n - 1))
        return stats.t.ppf(0.975, df=n - 1) * sd / math.sqrt(n)

    def sort_key(v: str):
        try:
            return (0, float(v))
        except ValueError:
            return (1, v)

    out_rows = []
    for value in sorted(groups, key=sort_key):
        runs = groups[value]
        primary = [float(r["primary_metric"]) for r in runs]
        entry = {
            "variable_value": value,
            "primary_mean": round(sum(primary) / len(primary), 6),
            "primary_ci95": round(ci95(primary), 6),
        }
        for col, label in zip(sec_cols, labels):
            vals = []
            for r in runs:
                try:
                    vals.append(float(r[col]))
                except (TypeError, ValueError):
                    pass
            entry[f"{label}_mean"] = round(sum(vals) / len(vals), 6) if vals else ""
            entry[f"{label}_ci95"] = round(ci95(vals), 6) if vals else ""
        entry["n_runs"] = len(runs)
        out_rows.append(entry)

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(out_rows[0].keys()))
        writer.writeheader()
        writer.writerows(out_rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("experiment_dir", type=Path,
                    help="the unsharded directory, e.g. Schemes/x/exp3_...")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    return merge(args.experiment_dir, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
