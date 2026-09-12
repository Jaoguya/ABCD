"""Does the measurement agree with the cost table?

The chain this project runs on is:

    tab:cost  ->  the experiments  ->  the results  ->  Section VI's prose

Each link is derived from the one before it. The cost table says what should
scale with what; the experiments are designed to sweep exactly those variables;
the results are what the sweep produces; and Section VI describes the results
once they exist.

**So this file does not restate the table.** It used to: two hardcoded lists,
``CLAIMS`` and ``PSA_CLAIMS``, each holding a copy of every cell as a string
alongside the shape it should produce. That copy is a fourth thing to keep in
step with the other three, and it drifted -- ``CLAIMS`` was still asserting the
pre-rebuild construction's rows (``O(q)T_H`` for token generation against the
manuscript's ``O(|T_Q|)T_H``) long after the scheme stopped computing them, and
every one of its assertions was skipping for want of results nobody noticed were
missing. A check that silently stops checking is worse than no check.

The table itself lives in ``Overleaf/MA-LB-PQ-VDSE.tex`` (``tab:cost``) and is
described in ``skill.md``. Both were deleted from here on 2026-09-12.

What remains is the one assertion that is NOT a restatement: a structural
invariant the table implies, checked against the data rather than against a
string. If it fails, the row is wrong -- and no amount of re-copying the table
into test code would have caught it.
"""

from __future__ import annotations

import collections
import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

#: How much two factorizations of the same ``|T_Q|`` may differ before the row
#: is wrong. Wide enough to absorb timer noise on a loaded host, narrow enough
#: that a genuine per-policy term (which would scale with ``|P_U|``, i.e. 4x
#: between the arms this compares) cannot hide inside it.
MAX_FACTORIZATION_SPREAD = 1.35


def test_token_generation_cost_depends_on_the_product_not_its_factorization():
    """``O(|T_Q|)T_H`` says ``q=20,|P_U|=1`` and ``q=5,|P_U|=4`` cost the same.

    This is the one claim in ``tab:cost`` that the previous construction could
    not even express, because its trapdoor had no ``|P_U|``. If it fails, the
    row is wrong: the cost has a per-policy term the notation hides.

    ACROSS THE ARMS, not within one. Experiment 1 sweeps ``q`` inside a
    directory and ``|P_U|`` across directories, so a given ``|T_Q|`` is reached
    by two different factorizations only when two arms are read together --
    ``|T_Q| = 20`` is ``q=20`` in pu1, ``q=10`` in pu2 and ``q=5`` in pu4.
    Reading a single directory would find no contested ``|T_Q|`` at all and
    skip, which is how this test would silently stop checking the one claim it
    exists for.
    """
    paths = sorted(
        (REPO / "Schemes" / "ma_lb_pq_vdse").glob(
            "exp1_trapdoor_generation__pu*/raw_runs.csv"
        )
    )
    if not paths:
        pytest.skip("no Exp. 1 results yet")

    by_tokens = collections.defaultdict(list)
    rows = []
    for path in paths:
        with path.open(newline="", encoding="utf-8") as handle:
            rows.extend(csv.DictReader(handle))

    for row in rows:
        if row.get("status") != "ok":
            continue
        try:
            # raw_runs.csv columns are primary_metric / secondary_metric_N;
            # the aggregated results.csv uses primary_mean / secondary_N_mean.
            tokens = int(float(row["secondary_metric_1"]))    # |T_Q|
            latency = float(row["primary_metric"])
            keywords = int(float(row["secondary_metric_2"]))  # q
        except (KeyError, TypeError, ValueError):
            continue
        by_tokens[tokens].append((keywords, latency))

    contested = {
        t: rs for t, rs in by_tokens.items() if len({q for q, _ in rs}) > 1
    }
    if not contested:
        pytest.skip("no |T_Q| reached by more than one factorization")

    for tokens, rs in sorted(contested.items()):
        means = {}
        for q, latency in rs:
            means.setdefault(q, []).append(latency)
        averaged = {q: sum(v) / len(v) for q, v in means.items()}
        spread = max(averaged.values()) / min(averaged.values())
        assert spread <= MAX_FACTORIZATION_SPREAD, (
            f"|T_Q|={tokens} costs {averaged} depending on how it is factored "
            f"into (q, |P_U|) -- a {spread:.2f}x spread. The tab:cost row "
            f"O(|T_Q|)T_H claims the product alone determines the cost, so "
            f"either the row needs a per-policy term or the implementation is "
            f"doing per-policy work it should not."
        )
