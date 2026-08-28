"""Sweep-point selection, so one experiment can be split across instances.

WHY
---
A campaign's wall-clock is bounded by its largest INDIVISIBLE unit of work.
Running one scheme per instance makes that unit a whole scheme track (~25 h);
running one experiment per instance makes it a whole experiment. Several of the
long experiments are internally a loop over independent sweep points —
``ma_lb_pq_vdse``'s Exp. 7-8 is 20 independent (concurrency, variant) configs at
~0.9 h each, ``thingom_pq_abse``'s Exp. 3 is 9 independent ``d`` points at
~1.4 h — so splitting at that granularity turns ~17.5 h into ~0.9 h of
wall-clock, at the same total compute and therefore the same cost.

``--points`` selects which sweep values this process runs. Each shard writes to
its own output directory; ``infra/merge_points.py`` reassembles them.

WHAT IT DOES NOT DO
-------------------
It does not make every experiment splittable. ``guo_vdsse`` and
``perera_lv_pqabse`` Exp. 2 grow ONE index across the sweep (the points are
nested prefixes, so rebuilding per point costs 1.88x), which makes them
inherently sequential — a shard for the largest N would rebuild everything below
it anyway and save nothing. Splitting those is allowed but pointless, and the
runners say so rather than silently accepting it.

FORMS
-----
    --points 2,5,10          explicit values
    --points 2-5             inclusive range, numeric values only
    --points 10000,1000000   values must match the sweep exactly

A value not in the experiment's sweep is an ERROR, not a silent no-op: a typo
that quietly runs zero points would leave a hole in the campaign that only
surfaces when the figure is drawn.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Sequence


class SweepSelectionError(ValueError):
    """Raised when --points names something the experiment does not sweep."""


def parse(spec: Optional[str]) -> Optional[List[str]]:
    """Parse a ``--points`` spec into a list of string tokens, or None."""
    if spec is None:
        return None
    spec = spec.strip()
    if not spec:
        return None

    tokens: List[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(-?\d+)\s*-\s*(-?\d+)", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                raise SweepSelectionError(
                    f"range {part!r} is empty: {lo} > {hi}"
                )
            tokens.extend(str(v) for v in range(lo, hi + 1))
        else:
            tokens.append(part)
    return tokens or None


def select(values: Sequence[Any], spec: Optional[str]) -> List[Any]:
    """Filter ``values`` down to the ones ``spec`` names, preserving order."""
    wanted = parse(spec)
    if wanted is None:
        return list(values)

    by_str = {str(v): v for v in values}
    unknown = [t for t in wanted if t not in by_str]
    if unknown:
        raise SweepSelectionError(
            f"--points names {unknown!r}, which this experiment does not "
            f"sweep. Its points are: {[str(v) for v in values]}"
        )
    keep = {by_str[t] for t in wanted}
    return [v for v in values if v in keep]


def suffix(spec: Optional[str]) -> str:
    """Directory suffix for one shard's output, or '' for a whole sweep.

    Shards must not write to the same directory: they run on different
    instances and would otherwise overwrite each other's results.csv, leaving
    a campaign that looks complete and is not.
    """
    tokens = parse(spec)
    if tokens is None:
        return ""
    safe = "_".join(re.sub(r"[^0-9A-Za-z.+-]", "", t) for t in tokens)
    return f"__points-{safe}" if safe else ""


def shard_dir(base, spec: Optional[str]):
    """``base`` for a whole sweep, ``base__points-...`` for one shard."""
    tail = suffix(spec)
    return base if not tail else base.parent / (base.name + tail)


__all__ = ["SweepSelectionError", "parse", "select", "shard_dir", "suffix"]
