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
]

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


def _load(scheme: str, experiment: str):
    path = REPO / "Schemes" / scheme / experiment / "results.csv"
    if not path.is_file():
        return None, path
    xs, ys, cis = [], [], []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            try:
                x = float(row["variable_value"])
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


def test_every_measurable_cost_row_is_covered():
    """A table row that gains an experiment must gain a claim here too.

    Exp. 7-8 have no tab:cost row and Exp. 9 measures a count, not a cost, so
    they are legitimately absent. Everything else that produces a latency curve
    is asserted above.
    """
    covered = {(scheme, exp) for scheme, exp, _, _, _ in CLAIMS}
    missing = []
    for scheme in ("ma_lb_pq_vdse", "guo_vdsse", "yue_ge", "perera_lv_pqabse"):
        for number, name in ((1, "exp1_trapdoor_generation"),
                             (4, "exp4_verification_overhead")):
            path = REPO / "Schemes" / scheme / name / "results.csv"
            if path.is_file() and (scheme, name) not in covered:
                missing.append(f"{scheme}/{name}")
    assert not missing, (
        "these have measured curves but no tab:cost claim asserted: "
        + ", ".join(sorted(missing))
    )
