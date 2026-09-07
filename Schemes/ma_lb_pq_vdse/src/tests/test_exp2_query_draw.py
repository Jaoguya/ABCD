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


def test_the_query_carries_the_published_q(prepared):
    """SVI: "each query contains five keywords"; global.yaml fixes it at 5.

    Exp. 2 issued ONE keyword until 2026-09-07 -- the same defect the
    2026-09-06 sweep fixed for Exp. 7/8, whose entry wrongly recorded that
    "every other experiment honours it". Nothing pinned q here, so nothing
    failed. This does.
    """
    conf, _, p = prepared
    q = conf.defaults.keywords_per_query
    assert p["queries"], "no queries were prepared"
    for query in p["queries"]:
        assert len(query) == len(set(query)), "a query repeats a keyword"
        assert len(query) == q, f"query carries {len(query)} keywords, not q={q}"


def test_the_query_keywords_co_occur_in_a_real_record(prepared):
    """Five INDEPENDENTLY drawn keywords match nothing over |W_i| ~= 32.

    That is how guo's Exp. 2 came to measure a search short-circuiting on its
    first miss, and how psa_exp2 banked n_eff = 0.0 at every sweep point. The
    completion draws the other q-1 from a record that carries the anchor, so
    the conjunction is answerable by construction.
    """
    _, exp, p = prepared
    deployment = p["deployment"]
    carried = {
        frozenset(entry["record"].keywords) for entry in deployment.records
    }
    for query in p["queries"]:
        assert any(set(query) <= record for record in carried), (
            f"no single record carries all of {query}; the conjunction "
            f"cannot match and the point would time an empty search"
        )


def test_the_pool_cycles_rather_than_running_out(prepared):
    """Retries call measure again; the point must not crash on exhaustion."""
    _, exp, p = prepared
    p["cursor"][0] = 0
    n = len(p["keywords"])
    for _ in range(n + 3):
        exp.measure(p)
    assert p["cursor"][0] == n + 3


def test_the_query_changes_from_run_to_run(prepared):
    """The whole purpose: cost must track the query, not a fixed one.

    This asserted that `n_eff` VARIES, which held while the query was a single
    keyword drawn from a frequency band. Under the q=5 conjunctive query
    (2026-09-07) it no longer holds ON THE SYNTHETIC SOURCE: that source lays
    keywords out near-uniformly -- `kw:{(rid*6+k) % 2006}` -- so every record
    carries a structurally identical neighbourhood and five co-occurring
    keywords match the same count every time. The uniformity is a property of
    the fixture, which this file's own docstring already warns about, not of
    the experiment; on the Synthea corpus |W_i| runs 5..64 over a Zipf
    vocabulary and n_eff moves.

    So this now pins the thing the 2026-09-03 defect actually broke -- a query
    reused verbatim for every run of every point -- rather than a proxy the
    fixture can no longer show. `test_exp2_query_is_answerable` covers the
    other half: that the query matches something.
    """
    _, exp, p = prepared
    p["cursor"][0] = 0
    issued = []
    for _ in range(len(p["queries"])):
        issued.append(tuple(p["queries"][p["cursor"][0] % len(p["queries"])]))
        exp.measure(p)
    assert len(set(issued)) == len(issued), "a query was reused across runs"


def test_exp2_query_is_answerable(prepared):
    """n_eff > 0. The suite asserted `>= 0`, which passes on the empty result.

    That is not hypothetical: it is exactly what went undetected in guo's
    Exp. 2 for 150 banked runs and in psa_exp2 at every sweep point.
    """
    _, exp, p = prepared
    p["cursor"][0] = 0
    assert exp.measure(p).secondaries["n_eff"] > 0
