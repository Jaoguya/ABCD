"""``tab:cost``'s asymptotic claims, checked against the measured curves.

Why this is a test and not a paragraph
--------------------------------------
This audit used to live in README §17.7/§17.8 as hand-written verdicts. Every
rerun invalidated them and nobody rewrote them, so by 2026-09-04 three of its
four rows were false:

  * "[30] trapdoor ... linear fit needs an impossible -3.99 ms intercept" --
    the fit is R^2 0.999 with a POSITIVE 0.0008 ms intercept. A -3.99 ms
    intercept is 50x the largest value in the series; it cannot have come from
    this data at all.
  * "Search row implies linear in d ... sublinear, therefore fails" -- the row
    is O(dT_H) + O(n_eff)(T_F+T_H), a d-linear term PLUS a d-independent one.
    Growth that flattens is what two terms predict, not a refutation of them.
  * "[54] verification ... never measured" -- measured since 6652245.

A prose verdict about a number goes stale the moment the number is re-measured.
This file re-derives the verdict from results.csv every run, so the audit cannot
drift from the data again, and costs nothing to keep current.

What a claim means here
-----------------------
``LINEAR`` does not mean "passes through the origin". Every row in the table is
a SUM, and the terms that do not depend on the swept variable land in the
intercept -- Exp. 1's fixed nonce, Exp. 3's O(n_eff) candidate filtering. So a
linear claim is tested as: a straight line fits well, the slope is positive, and
the intercept is not so negative that the linear model is obviously the wrong
shape.

``CONSTANT`` is tested as bounded growth rather than a flat line: [35]'s
O(1)T_PRF trapdoor rises 53% from q=1 to q=10 and then plateaus, which is a
fixed cost plus saturating overhead -- not the 20x a linear cost would show
across that sweep.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

LINEAR = "linear"
CONSTANT = "constant"
#: The curve's own confidence intervals are wider than the effect any shape
#: claim would produce, so neither confirming nor refuting the row is possible
#: from it. Recorded rather than silently passed, because "we could not tell"
#: is a different statement from "it matches" and §V must not cite a shape from
#: such a curve. The assertion is that the noise is really there: if the
#: measurement is ever tightened, this fails and the row gets re-classified.
NOT_DISCRIMINABLE = "not_discriminable"

#: A row marked NOT_DISCRIMINABLE must show at least this CI, as a fraction of
#: the mean, in the median point.
MIN_NOISE_FRACTION = 0.20

#: TWO TABLES, because there are two constructions.
#:
#: The rows below are the SUPERSEDED ``tab:cost`` -- the one the implemented
#: Option D scheme satisfies and every banked results.csv was measured under.
#: They are still asserted because that data is still what §V would cite today.
#: The current manuscript's rows are different in all five cells; they are
#: asserted separately in ``PSA_CLAIMS``, against the ``psa_*`` directories, so
#: neither table is checked against the other's data. This is divergence D6 --
#: see ``MANUSCRIPT_DIVERGENCE.md``.
#:
#: (scheme, experiment dir, tab:cost cell, swept symbol, claim shape)
CLAIMS = [
    ("ma_lb_pq_vdse", "exp1_trapdoor_generation",
     "Proposed / Trapdoor  O(q)T_H", "q", LINEAR),
    ("ma_lb_pq_vdse", "exp3_crossdomain_scalability",
     "Proposed / Search  O(dT_H)+O(n_eff)(T_F+T_H)", "d", LINEAR),
    ("ma_lb_pq_vdse", "exp4_verification_overhead",
     "Proposed / Verification  O(r)T_MT+O(r)T_H", "r", LINEAR),
    ("ma_lb_pq_vdse", "exp5_keyword_update",
     "Proposed / Keyword Update  O(k)T_H+O(log n)T_MT", "k", LINEAR),
    ("ma_lb_pq_vdse", "exp6_authorization_sync__ias",
     "Proposed / Auth. Sync  O(delta)T_H+O(log d)T_MT", "delta", LINEAR),
    ("yue_ge", "exp1_trapdoor_generation",
     "[30] / Trapdoor  O(q)T_CPRF", "q", LINEAR),
    ("guo_vdsse", "exp1_trapdoor_generation",
     "[35] / Trapdoor  O(1)T_PRF", "q", CONSTANT),
    ("guo_vdsse", "exp4_verification_overhead",
     "[35] / Verification  O(x)T_MAC", "x", LINEAR),
    ("yue_ge", "exp4_verification_overhead",
     "[30] / Verification  O(n_w^l)", "r", LINEAR),
    ("perera_lv_pqabse", "exp4_verification_overhead",
     "[54] / Verification  O(x log N)T_H+O(x)(T_Ver+T_MAC)", "x", LINEAR),
    # ML-DSA-65 signs by rejection sampling, so T_Sig's iteration count -- and
    # its latency -- vary per call. The measured CIs run 32-56% of the mean,
    # which swamps both the O(|T|)T_PRF growth and the constant it sits on.
    ("perera_lv_pqabse", "exp1_trapdoor_generation",
     "[54] / Trapdoor  O(|T|)T_PRF+T_Sig", "q", NOT_DISCRIMINABLE),
    # Added 2026-09-07. All three had a measured curve and a tab:cost row, and
    # neither this list nor the coverage test below reached them: the loop ran
    # over four schemes (thingom absent) and two experiments (5 absent).
    ("thingom_pq_abse", "exp1_trapdoor_generation",
     "[41] / Trapdoor  O(u+q)(T_H+T_Mul)+T_E", "q", LINEAR),
    ("yue_ge", "exp5_keyword_update",
     "[30] / Dynamic Update  O(k)", "k", LINEAR),
    # [35]'s row is written in `t` (keywords in a record-level index), not in
    # the swept `k`. It is asserted linear in k because the per-keyword hash/PRF
    # and puncturable-PRF work the row names is applied once per updated pair,
    # which is what §V's Exp. 5 paragraph says of it.
    ("guo_vdsse", "exp5_keyword_update",
     "[35] / Dynamic Update  O(t)(T_H+T_PRF)+T_Punc", "k", LINEAR),
]

#: Exp. 2 is deliberately absent from CLAIMS, and this records why so the
#: coverage test can tell a REASONED omission from an oversight.
#:
#: Every Search row is written in a variable that is not the swept one. [30] is
#: O(n_w^l), [35] O(xq), [41] (2e+1)T_P + O(e)(T_E+T_Mul), [54]
#: O(|T|)T_L + O(n_cand)T_BF, ours O(|T_Q|)T_L -- none is a function of N. Under
#: the constant-selectivity workload the match count rises with N, so the
#: measured curves rise, but that growth is a property of the WORKLOAD, not a
#: prediction any of these rows makes. §V says so itself for the proposed
#: scheme: "the main growth arises from output-sensitive result processing".
#:
#: Asserting a shape here would be inventing a claim the table does not make.
EXP2_NOT_SHAPE_ASSERTABLE = "exp2_search_latency"

#: A straight line must explain this much of the variance.
MIN_R2 = 0.95
#: How negative an intercept may be, as a fraction of the largest measured
#: value, before the linear model is the wrong shape rather than a fit with an
#: offset. Exp. 5 sits at -4.6% on a log-spaced sweep; -3.99 ms against a
#: 0.078 ms series, the claim this file replaces, is -5100%.
MIN_INTERCEPT_FRACTION = -0.15
#: A cost claimed O(1) may drift by harness overhead but must not scale with
#: the input. The sweeps here span 20x, so anything near-linear blows past this.
MAX_CONSTANT_RATIO = 2.5
#: How far two factorizations of the same |T_Q| may differ before O(|T_Q|)T_H is
#: the wrong shape. Generous, because these are microsecond-scale measurements
#: where scheduler noise is a real fraction of the mean; a genuine per-policy
#: term would show up as a spread growing with |P_U|, not as 20% jitter.
MAX_FACTORIZATION_SPREAD = 1.35


def _load(scheme: str, experiment: str, x_column: str = "variable_value"):
    """Load (x, y, ci) from a results.csv.

    ``x_column`` exists because one sweep does not put its cost driver in
    ``variable_value``: ``psa_exp1``'s sweep value is an INDEX into the
    ``(q, |P_U|)`` pairs, since ``|T_Q|`` is not injective over them (see that
    experiment's docstring). Fitting against the index would be fitting against
    an ordinal, which is why this parameter is here rather than a comment
    apologising for the axis.
    """
    path = REPO / "Schemes" / scheme / experiment / "results.csv"
    if not path.is_file():
        return None, path
    xs, ys, cis = [], [], []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            try:
                x = float(row[x_column])
                y = float(row["primary_mean"])
            except (KeyError, TypeError, ValueError):
                continue
            try:
                ci = float(row.get("primary_ci95", ""))
            except (TypeError, ValueError):
                ci = float("nan")
            if x > 0 and y > 0:
                xs.append(x)
                ys.append(y)
                cis.append(ci)
    return (xs, ys, cis), path


def _linear_fit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_t = sum((y - my) ** 2 for y in ys)
    ss_r = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - ss_r / ss_t if ss_t > 0 else 1.0
    return slope, intercept, r2


@pytest.mark.parametrize(
    "scheme,experiment,cell,symbol,shape",
    CLAIMS,
    ids=[c[2].split("  ")[0].replace(" ", "") for c in CLAIMS],
)
def test_cost_table_claim_matches_the_measurement(
    scheme, experiment, cell, symbol, shape
):
    data, path = _load(scheme, experiment)
    if data is None:
        pytest.skip(f"no results yet for {cell} ({path.relative_to(REPO)})")
    xs, ys, cis = data
    if len(xs) < 3:
        pytest.skip(f"{cell}: {len(xs)} point(s), too few to fit")

    if shape is NOT_DISCRIMINABLE:
        fractions = sorted(ci / y for y, ci in zip(ys, cis)
                           if ci == ci and y > 0)
        assert fractions, f"{cell}: no usable confidence intervals"
        median = fractions[len(fractions) // 2]
        assert median >= MIN_NOISE_FRACTION, (
            f"{cell} is recorded as too noisy to test, but its median CI is "
            f"now {median:.1%} of the mean (< {MIN_NOISE_FRACTION:.0%}). The "
            f"measurement has been tightened, so this row can and should now "
            f"be classified LINEAR or CONSTANT and actually checked."
        )
        return

    if shape is CONSTANT:
        ratio = max(ys) / min(ys)
        assert ratio <= MAX_CONSTANT_RATIO, (
            f"{cell} claims a cost independent of {symbol}, but the measured "
            f"latency spans {ratio:.2f}x across {symbol}="
            f"{min(xs):g}..{max(xs):g}. Either the table is wrong or the "
            f"implementation is not the published one."
        )
        return

    slope, intercept, r2 = _linear_fit(xs, ys)
    assert slope > 0, (
        f"{cell} claims a cost growing in {symbol}, but the fitted slope is "
        f"{slope:.6g}"
    )
    assert r2 >= MIN_R2, (
        f"{cell} claims a term linear in {symbol}; a straight line explains "
        f"only R^2={r2:.4f} of the measured curve (need {MIN_R2}). The table "
        f"row and the implementation disagree about the shape of the cost."
    )
    floor = MIN_INTERCEPT_FRACTION * max(ys)
    assert intercept >= floor, (
        f"{cell}: the linear fit needs an intercept of {intercept:.6g} ms "
        f"against a largest measured value of {max(ys):.6g} ms. A cost cannot "
        f"start that far below zero, so the linear model is the wrong shape "
        f"here even though R^2={r2:.4f}."
    )


#: The CURRENT manuscript's ``tab:cost`` row for the proposed scheme, checked
#: against the policy-state-aware track (``harness/psa_experiments.py``).
#:
#: Only the cells that track produces are here. The manuscript's Search row
#: ``O(|T_Q|)T_L`` and Verification row ``O(r log t)T_H + O(r)T_BC`` need the
#: full online path and the ledger, which the PSA track deliberately does not
#: fork -- so they have no data and are absent rather than asserted against a
#: measurement of something else.
#: (scheme, dir, cell, symbol, shape, x column in results.csv)
PSA_CLAIMS = [
    # The |P_U|=1 ARM. Exp. 1 writes one directory per authorization scope
    # (`__pu1/2/4/8`) because §V sweeps q WHILE varying |P_U|; there is no
    # un-suffixed directory to read. Any arm would fit -- within an arm
    # |T_Q| = q*|P_U| is linear in q -- and pu1 is the one where |T_Q| IS q,
    # so the fitted slope is the per-token cost directly.
    ("ma_lb_pq_vdse", "psa_exp1_token_generation__pu1",
     "Proposed(PSA) / Token Generation  O(|T_Q|)T_H", "|T_Q|", LINEAR,
     "secondary_1_mean"),
    ("ma_lb_pq_vdse", "psa_exp5_retokenization",
     "Proposed(PSA) / Dynamic Update  O(k log t)T_H", "k", LINEAR,
     "variable_value"),
    ("ma_lb_pq_vdse", "psa_exp6_affected_ratio__dias",
     "Proposed(PSA) / Auth. Sync  O(a + k log t)T_H", "affected ratio", LINEAR,
     "variable_value"),
    # Added 2026-09-07. The scope note above said the PSA track does not fork
    # Verification, so its row was "correspondingly absent". It IS forked --
    # PsaExp4Verification is in PSA_EXPERIMENTS and psa_exp4_verification_
    # overhead/ holds a 10-run sweep -- so the row is assertable and was simply
    # not being asserted. Its PSA Search row stays absent for the reason in
    # EXP2_NOT_SHAPE_ASSERTABLE, which does not depend on the construction.
    ("ma_lb_pq_vdse", "psa_exp4_verification_overhead",
     "Proposed(PSA) / Verification  O(r log t)T_H + O(r)T_BC", "r", LINEAR,
     "variable_value"),
]


@pytest.mark.parametrize(
    "scheme,experiment,cell,symbol,shape,x_column",
    PSA_CLAIMS,
    ids=[c[2].split("  ")[0].replace(" ", "") for c in PSA_CLAIMS],
)
def test_psa_cost_table_claim_matches_the_measurement(
    scheme, experiment, cell, symbol, shape, x_column
):
    """The current manuscript's rows, against the construction that implements them.

    Skips until the PSA track has been run on a campaign host. That skip is the
    correct state, not a gap: the numbers must come from the same machine as the
    Option D ones or the comparison the row exists for is meaningless.
    """
    data, path = _load(scheme, experiment, x_column)
    if data is None:
        pytest.skip(
            f"no policy-state-aware results yet for {cell} "
            f"({path.relative_to(REPO)}); run "
            f"`python -m Schemes.ma_lb_pq_vdse.src.main --construction psa`"
        )
    xs, ys, _ = data
    if len(xs) < 3:
        pytest.skip(f"{cell}: {len(xs)} point(s), too few to fit")
    slope, intercept, r2 = _linear_fit(xs, ys)
    assert slope > 0, (
        f"{cell} claims a cost growing in {symbol}, but the fitted slope is "
        f"{slope:.6g}"
    )
    assert r2 >= MIN_R2, (
        f"{cell} claims a term linear in {symbol}; a straight line explains "
        f"only R^2={r2:.4f} of the measured curve (need {MIN_R2})"
    )
    floor = MIN_INTERCEPT_FRACTION * max(ys)
    assert intercept >= floor, (
        f"{cell}: the linear fit needs an intercept of {intercept:.6g} ms "
        f"against a largest measured value of {max(ys):.6g} ms"
    )


def test_psa_exp1_cost_depends_on_the_product_not_its_factorization():
    """``O(|T_Q|)T_H`` says ``q=20,|P_U|=1`` and ``q=5,|P_U|=4`` cost the same.

    This is the one claim in the current ``tab:cost`` that the previous table
    could not even express, because Option D's trapdoor has no ``|P_U|``. If it
    fails, the row is wrong: the cost has a per-policy term the notation hides.
    """
    # ACROSS THE ARMS, not within one. Exp. 1 sweeps q inside a directory and
    # |P_U| across directories, so a given |T_Q| is reached by two different
    # factorizations only when two arms are read together: |T_Q|=20 is
    # q=20 in pu1, q=10 in pu2 and q=5 in pu4. Reading a single directory
    # would find no contested |T_Q| at all and skip, which is how this test
    # would silently stop checking the one claim it exists for.
    paths = sorted(
        (REPO / "Schemes" / "ma_lb_pq_vdse").glob(
            "psa_exp1_token_generation__pu*/raw_runs.csv"
        )
    )
    if not paths:
        pytest.skip("no policy-state-aware Exp. 1 results yet")

    import collections

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
        t: rows for t, rows in by_tokens.items()
        if len({q for q, _ in rows}) > 1
    }
    if not contested:
        pytest.skip("no |T_Q| reached by more than one factorization")

    for tokens, rows in sorted(contested.items()):
        means = {}
        for q, latency in rows:
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


def test_every_measurable_cost_row_is_covered():
    """A table row that gains an experiment must gain a claim here too.

    Exp. 7-8 have no tab:cost row and Exp. 9 measures a count, not a cost, so
    they are legitimately absent. Everything else that produces a latency curve
    is asserted above.
    """
    covered = {(scheme, exp) for scheme, exp, _, _, _ in CLAIMS}
    missing = []
    # thingom_pq_abse was absent from this tuple, so its Exp. 1 curve -- and the
    # tab:cost row O(u+q)(T_H+T_Mul)+T_E above it -- went unasserted while the
    # docstring claimed full coverage. Exp. 5 was absent from the pairs for the
    # same reason: [30]'s O(k) and [35]'s update row both have curves.
    for scheme in ("ma_lb_pq_vdse", "guo_vdsse", "yue_ge", "perera_lv_pqabse",
                   "thingom_pq_abse"):
        for number, name in ((1, "exp1_trapdoor_generation"),
                             (4, "exp4_verification_overhead"),
                             (5, "exp5_keyword_update")):
            path = REPO / "Schemes" / scheme / name / "results.csv"
            if path.is_file() and (scheme, name) not in covered:
                missing.append(f"{scheme}/{name}")
    assert not missing, (
        "these have measured curves but no tab:cost claim asserted: "
        + ", ".join(sorted(missing))
    )
