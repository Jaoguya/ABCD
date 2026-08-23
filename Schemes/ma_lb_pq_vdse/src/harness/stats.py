"""Aggregation for the experiment harness — README §7.

"Report mean ± 95% CI" over 30 runs. Two rules from AGENT_RULES' reviewer checks
are enforced here rather than left to discipline:

* **The CI is computed from the runs, never hardcoded.** :func:`confidence_interval`
  takes the sample and nothing else, so there is no parameter through which a
  narrower interval could be supplied.
* **Outliers are kept.** There is deliberately no trimming, winsorising or
  filtering function in this module. README §7: "Keep them. If a run fails, record
  ``status=failed`` in ``raw_runs.csv`` and re-run to restore n=30 rather than
  dropping it."

Uses Student's *t*, not the normal approximation: at n = 30 the difference is
about 4% on the interval width (t = 2.045 vs z = 1.960), which is the wrong
direction to be casual about when the interval is what a reviewer reads.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Sequence

from scipy import stats


class StatisticsError(RuntimeError):
    """Raised when a sample cannot be summarised."""


@dataclass(frozen=True)
class Summary:
    """Mean, 95% CI half-width, and the diagnostics a reviewer would ask for."""

    n: int
    mean: float
    ci95: float
    stdev: float
    minimum: float
    maximum: float

    @property
    def relative_ci(self) -> float:
        """CI half-width as a fraction of the mean — 0 when the mean is 0."""
        return 0.0 if self.mean == 0 else abs(self.ci95 / self.mean)

    @property
    def has_zero_variance(self) -> bool:
        """Every run identical.

        Correct for a count that cannot vary (trapdoors issued, FSNs touched) and a
        red flag for a latency. :func:`check_plausibility` decides which case it is;
        this only reports the fact.
        """
        return self.stdev == 0.0


def mean(values: Sequence[float]) -> float:
    if not values:
        raise StatisticsError("cannot take the mean of an empty sample")
    return sum(values) / len(values)


def stdev(values: Sequence[float]) -> float:
    """Sample standard deviation (n-1). Zero for a single observation."""
    if len(values) < 2:
        return 0.0
    average = mean(values)
    variance = sum((value - average) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def confidence_interval(values: Sequence[float], confidence: float = 0.95) -> float:
    """Half-width of the ``confidence`` interval, from the sample alone.

    Returns 0.0 for a degenerate sample — one observation, or one with no spread —
    rather than raising: a constant metric legitimately has no interval, and
    raising would make the harness unable to report a count.
    """
    if not values:
        raise StatisticsError("cannot compute a CI for an empty sample")
    if not 0.0 < confidence < 1.0:
        raise StatisticsError(f"confidence must be in (0, 1), got {confidence}")
    n = len(values)
    if n < 2:
        return 0.0
    spread = stdev(values)
    if spread == 0.0:
        return 0.0
    critical = stats.t.ppf(0.5 + confidence / 2.0, df=n - 1)
    return float(critical * spread / math.sqrt(n))


def summarise(values: Sequence[float], confidence: float = 0.95) -> Summary:
    """Summarise one metric across the retained runs."""
    if not values:
        raise StatisticsError("cannot summarise an empty sample")
    return Summary(
        n=len(values),
        mean=mean(values),
        ci95=confidence_interval(values, confidence),
        stdev=stdev(values),
        minimum=min(values),
        maximum=max(values),
    )


def check_plausibility(
    summary: Summary, *, metric: str, is_timing: bool
) -> Optional[str]:
    """Return a warning if a summary looks like a bug rather than a measurement.

    AGENT_RULES' reviewer checks call out "zero variance or implausibly low
    variance" as indicating "a bug or fabrication". Applied only to timings: a
    count that is the same every run (one trapdoor issued, one FSN touched) is
    correct, and warning about it would train the reader to ignore the warning.

    Returns a string rather than raising, because a suspicious sample is still a
    measurement and the run should record it. Suppressing it would be the
    fabrication the check exists to catch.
    """
    if not is_timing:
        return None
    if summary.n < 2:
        return f"{metric}: only {summary.n} retained run(s); no interval is meaningful"
    if summary.has_zero_variance:
        return (
            f"{metric}: zero variance across {summary.n} timed runs — a real timer "
            f"does not repeat exactly, so this indicates a cached result, a "
            f"clock with insufficient resolution, or a fabricated value"
        )
    if summary.relative_ci < 1e-6:
        return (
            f"{metric}: 95% CI is {summary.relative_ci:.2e} of the mean, which is "
            f"implausibly tight for a timed measurement"
        )
    if summary.minimum <= 0:
        return f"{metric}: a timed run reported {summary.minimum}, which is not a duration"
    return None


__all__ = [
    "StatisticsError",
    "Summary",
    "mean",
    "stdev",
    "confidence_interval",
    "summarise",
    "check_plausibility",
]
