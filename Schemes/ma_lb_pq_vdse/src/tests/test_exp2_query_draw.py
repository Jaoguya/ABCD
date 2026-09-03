"""Exp. 2 draws a new query per run, at the selectivity the baselines use.

It used to query ``keywords[0]`` of the first record in the domain, once, for
every run of every point. guo and yue_ge each draw a NEW keyword per run
(``yue_ge/exp2_search_latency/runner.py:130,158``), and Peony++ is
output-sensitive -- its cost IS the number of matching files. So the two schemes
were answering different questions, and our flat curve measured the
repeatability of one arbitrary keyword rather than search latency over a
realistic query load.

These tests pin the draw itself. They deliberately use a hand-built frequency
Counter rather than the corpus: the synthetic source spreads keywords almost
uniformly, so it cannot exercise the rare/common bounds that matter on Synthea.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto.rng import DeterministicRNG  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as X  # noqa: E402


def rng(label: str = "t") -> DeterministicRNG:
    return DeterministicRNG(X.EXP2_QUERY_SEED).spawn(label)


# ===========================================================================
# select_query_keywords -- the selectivity bounds
# ===========================================================================
def test_keywords_below_min_frequency_are_skipped():
    """Too rare to produce a measurable traversal."""
    freq = Counter({"rare": X.QUERY_MIN_FREQUENCY - 1})
    freq.update({f"ok{i}": X.QUERY_MIN_FREQUENCY for i in range(20)})
    got = X.select_query_keywords(freq, rng(), 5, total_records=1000)
    assert "rare" not in got


def test_keywords_above_max_share_are_skipped():
    """So common they swamp the scan and hide the scaling."""
    total = 100
    freq = Counter({"everywhere": int(total * X.QUERY_MAX_SHARE) + 1})
    freq.update({f"ok{i}": 10 for i in range(20)})
    got = X.select_query_keywords(freq, rng(), 5, total_records=total)
    assert "everywhere" not in got


def test_falls_back_to_the_whole_vocabulary_when_bounds_leave_too_few():
    """A small point must still produce a query, not fail the sweep."""
    freq = Counter({"a": 1, "b": 1, "c": 1})
    got = X.select_query_keywords(freq, rng(), 3, total_records=10)
    assert sorted(got) == ["a", "b", "c"]


def test_an_empty_index_is_an_error_not_a_silent_empty_draw():
    with pytest.raises(ValueError):
        X.select_query_keywords(Counter(), rng(), 3)


def test_draw_is_deterministic():
    freq = Counter({f"kw{i}": 10 for i in range(50)})
    a = X.select_query_keywords(freq, rng(), 15, total_records=100)
    b = X.select_query_keywords(freq, rng(), 15, total_records=100)
    assert a == b


def test_draw_has_no_repeats_when_the_vocabulary_allows():
    freq = Counter({f"kw{i}": 10 for i in range(50)})
    got = X.select_query_keywords(freq, rng(), 15, total_records=100)
    assert len(got) == len(set(got)) == 15


def test_bounds_match_the_baselines():
    """These are copied from yue_ge/src/workload.py; drift makes the numbers
    incomparable without anything failing."""
    assert (X.QUERY_MIN_FREQUENCY, X.QUERY_MAX_SHARE) == (5, 0.5)


# ===========================================================================
# The experiment rotates through the draw
# ===========================================================================
@pytest.fixture(scope="module")
def prepared():
    conf = scheme_config.load()
    exp = X.Exp2SearchLatency(config=conf, source=X.SyntheticRecordSource())
    return conf, exp, exp.prepare(10_000)


def test_prepare_draws_warmups_plus_repetitions(prepared):
    conf, _, p = prepared
    m = conf.measurement
    assert len(p["keywords"]) == m.warmup_runs + m.repetitions


def test_every_call_advances_to_a_new_keyword(prepared):
    _, exp, p = prepared
    p["cursor"][0] = 0
    seen = []
    for _ in range(len(p["keywords"])):
        seen.append(p["keywords"][p["cursor"][0] % len(p["keywords"])])
        exp.measure(p)
    assert len(set(seen)) == len(p["keywords"]), "a keyword was reused early"


def test_the_pool_cycles_rather_than_running_out(prepared):
    """Retries call measure again; the point must not crash on exhaustion."""
    _, exp, p = prepared
    p["cursor"][0] = 0
    n = len(p["keywords"])
    for _ in range(n + 3):
        exp.measure(p)
    assert p["cursor"][0] == n + 3


def test_n_eff_now_varies_across_runs(prepared):
    """The whole purpose: cost must track the query, not a fixed keyword."""
    _, exp, p = prepared
    p["cursor"][0] = 0
    vals = {exp.measure(p).secondaries["n_eff"] for _ in range(len(p["keywords"]))}
    assert len(vals) > 1, "every run still returns the same candidate count"
