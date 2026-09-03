"""Generate the manuscript's eight figures from the schemes' ``results.csv``.

    python3 Plots/generate_plots.py --input Schemes --output Plots/output

Walks ``Schemes/*/exp<N>_*/results.csv`` and emits one figure per experiment
(README §10). Schemes with no ``results.csv`` for an experiment are skipped,
so a partial campaign still plots — that is deliberate: the campaign runs
per-scheme on separate instances and finishes at different times.

FIGURE CONVENTIONS (README §10, followed exactly)
-------------------------------------------------
* Vector PDF, single-column width.
* 8 pt minimum type size anywhere on the figure.
* 95% CI error bars on **every** point, taken from the ``*_ci95`` columns —
  never recomputed here, because this script does not see the raw runs.
* Log x-axis for Exp. 2, 5 and 6 (their sweeps span decades).
* Schemes distinguished by **both** marker and line style, so the figures
  survive grayscale printing.

WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
-----------------------------------------
It does not aggregate, derive, interpolate or smooth. Every plotted value is
read verbatim from a ``results.csv`` cell, so that README §15's "every numeric
claim in §V traces to a results.csv cell" stays literally true. A missing or
malformed row is reported and skipped, never filled in.

It also does not read ``run_meta.json``'s ``reportable`` flag to *exclude*
anything — a development run is still worth plotting while building the
pipeline. Instead, ``--require-reportable`` opts into that check, and without
it the script prints a warning naming every non-reportable series it drew, so
a development figure cannot be mistaken for a submission one.
"""

from __future__ import annotations

import argparse
import math
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")  # headless: the experiment host has no display
import matplotlib.pyplot as plt  # noqa: E402


# ---------------------------------------------------------------------------
# Figure specifications — README §5 (metrics) and §10 (filenames, log axes)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PanelSpec:
    """One sub-plot of a multi-panel figure.

    ``metric`` indexes the results.csv columns: 0 is ``primary_mean``, 1 is the
    first secondary, 2 the second. ``tag`` is the (a)/(b)/(c) label.
    """
    metric: int
    ylabel: str
    tag: str


@dataclass(frozen=True)
class ExperimentSpec:
    number: int
    folder: str
    filename: str
    xlabel: str
    ylabel: str
    log_x: bool = False
    log_y: bool = False
    #: Empty for a normal one-metric figure. When set, the figure is drawn as
    #: one stacked panel per entry, sharing the x-axis and one legend.
    #:
    #: Exp. 8 needs this: "load balance" is not one number. `least_loaded`
    #: minimises queue length, so it wins on utilization spread by
    #: construction, while AASS trades some spread for authorization locality
    #: and wins on peak node load and on cross-node traffic. Plotting only the
    #: spread shows the one metric the proposed scheduler loses; plotting only
    #: a metric it wins would be choosing the metric after seeing the result.
    #: All three are recorded on every run, so all three are shown.
    panels: Tuple["PanelSpec", ...] = ()


EXPERIMENTS: Tuple[ExperimentSpec, ...] = (
    ExperimentSpec(1, "exp1_trapdoor_generation", "fig_exp1_trapdoor.pdf",
                   "Queried keywords $q$", "Trapdoor generation latency (ms)",
                   log_y=True),   # 4.82 decades — see LOG_Y_DECADES
    ExperimentSpec(2, "exp2_search_latency", "fig_exp2_search.pdf",
                   "Index size $N$ (records)", "Search latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(3, "exp3_crossdomain_scalability", "fig_exp3_crossdomain.pdf",
                   "Domains $d$", "Cross-domain search latency (ms)",
                   log_y=True),
    ExperimentSpec(4, "exp4_verification_overhead", "fig_exp4_verify.pdf",
                   "Returned results $r$", "Verification latency (ms)",
                   log_y=True),   # 2.66 decades — see LOG_Y_DECADES
    ExperimentSpec(5, "exp5_keyword_update", "fig_exp5_update.pdf",
                   "Updated (keyword, document) pairs $k$", "Update latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(6, "exp6_authorization_sync", "fig_exp6_sync.pdf",
                   "Authorization updates $\\delta$", "Synchronization latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(7, "exp7_search_throughput", "fig_exp7_throughput.pdf",
                   "Concurrent queries", "Throughput (queries/s)"),
    # Exp. 9 is the Exp. 4 companion: Exp. 4 asks what verification COSTS,
    # Exp. 9 what it BUYS. Log-log because the gap is the story -- ours tracks
    # t exactly while the accumulator schemes sit flat at the full result-set
    # size, so at t=1 the two are ~4 orders apart and at t=1000 ~1.
    ExperimentSpec(9, "exp9_verification_granularity",
                   "fig_exp9_granularity.pdf",
                   "Tampered records $t$", "Records discarded",
                   log_x=True, log_y=True),
    ExperimentSpec(8, "exp8_load_balance", "fig_exp8_balance.pdf",
                   "Concurrent queries", "FSN utilization std. dev.",
                   panels=(
                       PanelSpec(0, "Utilization std. dev.", "a"),
                       PanelSpec(1, "Max node utilization", "b"),
                       PanelSpec(2, "Cross-node forwards", "c"),
                   )),
)

# LOG-Y CRITERION, applied uniformly: an experiment gets a log y-axis when its
# measured values span >= LOG_Y_DECADES orders of magnitude. On a linear axis a
# wider span collapses every curve but the slowest onto the x-axis, which hides
# real differences rather than showing them.
#
# Stated as a threshold, not chosen per figure, so it cannot be an axis picked
# after seeing which scheme it flatters (AGENT_RULES "Bias Detection"). Measured
# spans at the time of writing:
#
#   exp1 4.82   exp2 8.10   exp3 6.29   exp4 2.66
#   exp5 4.41   exp6 3.01   exp7 0.99   exp8 0.93 / 0.11 / inf(zeros)
#
# so 1-6 are log and 7-8 are linear. exp1 and exp4 were LINEAR until
# 2026-09-01: exp1 put four of five schemes flat on the axis (the proposed
# scheme's 0.01-0.10 ms was indistinguishable from Guo's and Perera's), and
# exp4 hid the 0.06-28 ms spread the same way. `_check_log_y_criterion` warns
# if new data ever pushes a linear figure past the threshold, so the rule stays
# enforced rather than becoming a comment about what was once true.
LOG_Y_DECADES = 2.0


# Display names. Anything not listed falls back to the directory name, so a
# newly added scheme still plots (with an uglier label) rather than vanishing.
# Baselines are labelled by REFERENCE NUMBER, not author name, so a figure and
# section V's prose name the same thing without the reader translating between
# them. Numbers are the bibitem keys in Overleaf/PQ-AVDSE-OJCOMS.
#
# yue_ge was labelled "Ge et al. [55]" and that was WRONG. ref55 is Cao et al.,
# "Enabling Puncturable Encrypted Search Over Lattice" (IEEE TMC 2026) -- a
# different paper. Ge et al. is ref30, cited 17 times in the manuscript against
# ref55's 2. Every figure has been pointing readers at the wrong citation.
SCHEME_LABELS: Dict[str, str] = {
    "ma_lb_pq_vdse": "Proposed",
    "yue_ge": "Scheme [30]",
    "guo_vdsse": "Scheme [35]",
    "thingom_pq_abse": "Scheme [41]",
    "perera_lv_pqabse": "Scheme [54]",
}

# Marker AND linestyle both vary, so the figures survive grayscale (README §10).
# The proposed scheme is pinned to index 0 so it is visually consistent across
# all eight figures rather than shifting when a baseline is absent.
STYLE_ORDER: Tuple[str, ...] = (
    "ma_lb_pq_vdse", "guo_vdsse", "thingom_pq_abse",
    "perera_lv_pqabse", "yue_ge",
)
MARKERS = ("o", "s", "^", "D", "v", "P", "X")
LINESTYLES = ("-", "--", "-.", ":", (0, (3, 1, 1, 1)), (0, (5, 2)), (0, (1, 1)))
COLORS = ("#0072B2", "#D55E00", "#009E73", "#CC79A7", "#56B4E9", "#E69F00", "#000000")

# Legend/draw order only -- kept separate from STYLE_ORDER so reordering the
# legend can never reassign a scheme's marker/color/linestyle (that mapping is
# pinned by STYLE_ORDER's index and must stay fixed across every figure).
# Proposed first, then baselines by citation number: [30], [35], [41], [54].
LEGEND_ORDER: Tuple[str, ...] = (
    "ma_lb_pq_vdse", "yue_ge", "guo_vdsse", "thingom_pq_abse",
    "perera_lv_pqabse",
)


#: Exp. 7-8 are an ABLATION of one scheme, so their four series are variant
#: LABELS rather than scheme keys and would all miss STYLE_ORDER -- every curve
#: drawn in the same colour and marker. Pin each to its own slot, and give
#: `aass` slot 0, the one the proposed scheme holds on the other six figures, so
#: the proposed line is the same blue circle everywhere.
ABLATION_STYLE_SLOT: Dict[str, int] = {
    "AASS (proposed)": 0,
    "Round robin": 1,
    "Least loaded": 2,
    "No load balancing": 3,
}


def style_for(scheme: str) -> Dict[str, object]:
    if scheme in ABLATION_STYLE_SLOT:
        idx = ABLATION_STYLE_SLOT[scheme]
    else:
        idx = STYLE_ORDER.index(scheme) if scheme in STYLE_ORDER else len(STYLE_ORDER)
    return {
        "marker": MARKERS[idx % len(MARKERS)],
        "linestyle": LINESTYLES[idx % len(LINESTYLES)],
        "color": COLORS[idx % len(COLORS)],
    }


# ---------------------------------------------------------------------------
# Reading results
# ---------------------------------------------------------------------------
@dataclass
class Series:
    scheme: str
    x: List[float] = field(default_factory=list)
    y: List[float] = field(default_factory=list)
    yerr: List[float] = field(default_factory=list)
    #: metric index (1-based) -> (values, ci95s), for multi-panel figures.
    extra: Dict[int, Tuple[List[float], List[float]]] = field(default_factory=dict)
    n_runs: List[int] = field(default_factory=list)
    reportable: Optional[bool] = None
    problems: List[str] = field(default_factory=list)


def _to_float(value: str) -> Optional[float]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _secondary_columns(row: Dict[str, str]) -> List[Tuple[str, str]]:
    """The (`*_mean`, `*_ci95`) column pairs after primary, in file order."""
    pairs: List[Tuple[str, str]] = []
    for name in row:
        if not name.endswith("_mean") or name == "primary_mean":
            continue
        stem = name[: -len("_mean")]
        ci = f"{stem}_ci95"
        pairs.append((name, ci if ci in row else ""))
    return pairs


def read_results(path: Path, scheme: str) -> Optional[Series]:
    """Parse one ``results.csv``. Returns None if it has no usable rows.

    Rows with a missing/unparseable variable_value or primary_mean are skipped
    and recorded in ``problems`` — never silently dropped, and never guessed at.
    """
    series = Series(scheme=scheme)
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            for lineno, row in enumerate(csv.DictReader(handle), start=2):
                x = _to_float(row.get("variable_value", ""))
                y = _to_float(row.get("primary_mean", ""))
                if x is None or y is None:
                    series.problems.append(
                        f"{path}:{lineno}: unusable variable_value/primary_mean, skipped"
                    )
                    continue
                ci = _to_float(row.get("primary_ci95", ""))
                n = _to_float(row.get("n_runs", "")) or 0
                # A single-run point has NO confidence interval -- there is no
                # variance to compute one from. Drawing ci=0 would put a
                # zero-length bar with caps on the point, which reads as "we
                # measured this very precisely": the exact opposite of the
                # truth. NaN makes matplotlib omit the bar entirely, so an
                # n=1 point is visibly bare next to the n=10 points beside it.
                # Points measured once are legitimate for a baseline whose
                # 10-run cost is prohibitive (thingom_pq_abse's Exp. 2 is
                # ~10.9 h for ONE run at N=10^6); claiming a CI for them is
                # not. See AGENT_RULES.md "Statistical Integrity".
                if n < 2 or ci is None:
                    ci = float("nan")
                series.x.append(x)
                series.y.append(y)
                series.yerr.append(ci)
                series.n_runs.append(int(n))
                # Secondaries, positionally. The NAMES differ per scheme
                # (ma_lb writes `secondary_1_mean`, the baselines write the
                # metric's real name), so the i-th `*_mean` after primary is
                # the i-th secondary. Only multi-panel figures read these, and
                # those are single-scheme ablations, so the positional read
                # cannot cross schemes that disagree on ordering.
                for i, (mcol, ccol) in enumerate(_secondary_columns(row), start=1):
                    sy = _to_float(row.get(mcol, ""))
                    if sy is None:
                        continue
                    sci = _to_float(row.get(ccol, "")) if ccol else None
                    if n < 2 or sci is None:
                        sci = float("nan")
                    vals, errs = series.extra.setdefault(i, ([], []))
                    vals.append(sy)
                    errs.append(sci)
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(f"  WARNING cannot read {path}: {exc}", file=sys.stderr)
        return None

    if not series.x:
        return None

    # Sort by x so a results.csv written out of order still plots as a curve
    # rather than a zigzag.
    order = sorted(range(len(series.x)), key=lambda i: series.x[i])
    series.x = [series.x[i] for i in order]
    series.y = [series.y[i] for i in order]
    series.yerr = [series.yerr[i] for i in order]
    series.n_runs = [series.n_runs[i] for i in order]

    meta = path.with_name("run_meta.json")
    if meta.is_file():
        try:
            series.reportable = bool(json.loads(meta.read_text(encoding="utf-8"))
                                     .get("reportable", False))
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            series.problems.append(f"{meta}: unreadable ({type(exc).__name__})")
    else:
        series.problems.append(f"{meta}: missing (README §9 requires it)")
    return series


#: Order is fixed so the legend reads weakest-to-proposed on every regeneration.
ABLATION_VARIANTS: Tuple[Tuple[str, str], ...] = (
    ("no_lb", "No load balancing"),
    ("round_robin", "Round robin"),
    ("least_loaded", "Least loaded"),
    ("aass", "AASS (proposed)"),
)

#: Exp. 6 ablates IAS PROPAGATION, not the scheduler, so it has its own
#: vocabulary. `ias` is the published rule; `broadcast` is the alternative
#: :1111 rejects (deliver to every FSN); `full_rebuild` is the alternative
#: :1045 rejects (every authority recomputes its commitment). Added 2026-09-03 --
#: before that Exp. 6 plotted one series with no comparison, so README §5's
#: "selective propagation is the claim" had nothing to read it against.
EXP6_VARIANTS: Tuple[Tuple[str, str], ...] = (
    ("broadcast", "Broadcast to all FSNs"),
    ("full_rebuild", "Global authorization rebuild"),
    ("ias", "IAS (proposed)"),
)


def variants_for(number: int) -> Tuple[Tuple[str, str], ...]:
    """Which variant vocabulary an experiment's ablation figure uses."""
    return EXP6_VARIANTS if number == 6 else ABLATION_VARIANTS


def _variant_of(exp_dir: Path) -> Optional[str]:
    """Which scheduler produced this directory.

    ``run_meta.json``'s ``scheduler_variant`` note is authoritative; the
    directory suffix is only the fallback. A result identified solely by its
    folder name loses its identity the moment anything is renamed or merged,
    which is why the note is written in the first place.
    """
    meta = exp_dir / "run_meta.json"
    try:
        notes = json.loads(meta.read_text(encoding="utf-8")).get("notes") or []
        for note in notes:
            if str(note).startswith("scheduler_variant="):
                return str(note).split("=", 1)[1].strip()
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return exp_dir.name.rsplit("__", 1)[-1] if "__" in exp_dir.name else None


def _has_variant_dirs(input_root: Path, spec: ExperimentSpec) -> bool:
    """Whether any directory names a variant this experiment's ablation knows."""
    if not input_root.is_dir():
        return False
    known = dict(variants_for(spec.number))
    for scheme_dir in sorted(p for p in input_root.iterdir() if p.is_dir()):
        for exp_dir in scheme_dir.glob(f"exp{spec.number}_*__*"):
            if exp_dir.is_dir() and _variant_of(exp_dir) in known:
                return True
    return False


def collect_ablation(input_root: Path, spec: ExperimentSpec) -> List[Series]:
    """One series per scheduler variant, for Exp. 7-8.

    ``collect`` takes the FIRST matching ``exp<N>_*`` directory per scheme and
    stops, which is right for a cross-scheme figure and wrong here: it would
    draw a single curve labelled with the scheme name where section V claims a
    four-way comparison, silently choosing whichever variant sorted first.
    """
    found: List[Series] = []
    if not input_root.is_dir():
        return found
    by_variant: Dict[str, Path] = {}
    for scheme_dir in sorted(p for p in input_root.iterdir() if p.is_dir()):
        for exp_dir in sorted(scheme_dir.glob(f"exp{spec.number}_*__*")):
            if not exp_dir.is_dir():
                continue
            variant = _variant_of(exp_dir)
            # Skips the `__points-<N>` sweep shards, which are not variants.
            if variant in dict(variants_for(spec.number)):
                by_variant.setdefault(variant, exp_dir)
    for variant, label in variants_for(spec.number):
        exp_dir = by_variant.get(variant)
        if exp_dir is None:
            print(f"  NOTE exp{spec.number}: no directory for variant "
                  f"{variant!r}; the ablation figure will be incomplete")
            continue
        series = read_results(exp_dir / "results.csv", label)
        if series is None:
            print(f"  NOTE exp{spec.number}: {exp_dir.name} has no usable "
                  f"results.csv; {variant!r} omitted")
            continue
        found.append(series)
    return found


def collect(input_root: Path, spec: ExperimentSpec) -> List[Series]:
    """Find every scheme's results for one experiment.

    Matches ``exp<N>_*`` rather than the exact folder name so a scheme that
    names its directory slightly differently is still picked up instead of
    silently contributing nothing.
    """
    found: List[Series] = []
    if spec.number in (7, 8):
        return collect_ablation(input_root, spec)
    if spec.number == 6 and _has_variant_dirs(input_root, spec):
        # Exp. 6 gained an ablation on 2026-09-03 (ias / broadcast /
        # full_rebuild). Probed rather than assumed so results predating it still
        # plot as a single series instead of emitting three "missing variant"
        # notes for directories that were never supposed to exist.
        return collect_ablation(input_root, spec)
    if not input_root.is_dir():
        return found
    for scheme_dir in sorted(p for p in input_root.iterdir() if p.is_dir()):
        matches = sorted(scheme_dir.glob(f"exp{spec.number}_*"))
        used: Optional[Path] = None
        for exp_dir in matches:
            if not exp_dir.is_dir():
                continue
            series = read_results(exp_dir / "results.csv", scheme_dir.name)
            if series is not None:
                found.append(series)
                used = exp_dir  # the one that actually contributed data
                break
        if len(matches) > 1:
            # Name the directory that supplied the data, not matches[0]: the
            # loop skips directories whose results.csv is missing or unusable,
            # so the two can differ and reporting the wrong one misleads.
            print(f"  NOTE {scheme_dir.name}: multiple exp{spec.number}_* dirs "
                  f"{[m.name for m in matches]}; used "
                  f"{used.name if used else 'none (no usable results.csv)'}")
    return found


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
# IEEE single-column is 3.5 in. 8 pt is README §10's stated minimum, so every
# text element is set at or above it.
plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "figure.figsize": (3.5, 2.6),
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,  # embed TrueType rather than Type 3: IEEE requires it
    "ps.fonttype": 42,
})


def _axis_number(v: float) -> str:
    """Compact scientific form for a legend note: 200000 -> 2x10^5."""
    if v <= 0:
        return str(v)
    exp = int(math.floor(math.log10(v)))
    mant = v / (10 ** exp)
    if exp < 3:
        return f"{v:g}"
    # mathtext, so the exponent renders as a superscript in both the PDF and
    # the PNG rather than as a literal "10^5".
    return (rf"$10^{{{exp}}}$" if abs(mant - 1) < 1e-9
            else rf"${mant:g}\times10^{{{exp}}}$")


def _check_log_y_criterion(spec: ExperimentSpec, series_list: Sequence[Series],
                           warnings: List[str]) -> None:
    """Warn when a linear-y figure has grown past the log threshold.

    Without this the criterion above decays into a comment: new data widens a
    range, the axis stays linear, and curves quietly flatten onto the x-axis.
    """
    if spec.log_y or spec.panels:
        return
    vals = [v for s in series_list for v in s.y if v > 0]
    if len(vals) < 2:
        return
    span = math.log10(max(vals) / min(vals))
    if span >= LOG_Y_DECADES:
        warnings.append(
            f"exp{spec.number}: y-values now span {span:.2f} decades "
            f"(>= {LOG_Y_DECADES}); LOG_Y_DECADES says this figure should set "
            f"log_y=True or curves will flatten onto the axis"
        )


def _panel_values(series: Series, metric: int) -> Tuple[List[float], List[float]]:
    """(values, ci95s) for one metric: 0 is primary, 1+ index the secondaries."""
    if metric == 0:
        return series.y, series.yerr
    return series.extra.get(metric, ([], []))


def render(spec: ExperimentSpec, series_list: Sequence[Series],
           out_path: Path, dpi: Optional[int] = None) -> Tuple[bool, List[str]]:
    """Draw one figure. Returns (written, warnings)."""
    warnings: List[str] = []
    if not series_list:
        return False, [f"exp{spec.number}: no results.csv found for any scheme"]
    _check_log_y_criterion(spec, series_list, warnings)

    if spec.panels:
        # Stacked, not side by side: three panels across an IEEE single column
        # would be 1.16in each, too narrow for an axis label. Height is per
        # panel; width is whatever the column (and --scale) already set.
        w, h = plt.rcParams["figure.figsize"]
        fig, axes = plt.subplots(
            len(spec.panels), 1, sharex=True,
            figsize=(w, h * 0.78 * len(spec.panels)),
        )
        for i, (ax, panel) in enumerate(zip(axes, spec.panels)):
            _draw_panel(
                ax, spec, series_list, warnings,
                metric=panel.metric, ylabel=panel.ylabel,
                # Legend once, on the top panel; warnings once, or each series
                # would report itself three times.
                add_legend=(i == 0), collect_warnings=(i == 0),
                # Only the bottom panel carries the shared x label.
                add_xlabel=(i == len(spec.panels) - 1),
                # log_y is declared for the PRIMARY metric; a secondary is a
                # different quantity and may not be positive or wide-ranging.
                allow_log_y=(panel.metric == 0),
            )
            ax.set_title(f"({panel.tag})", loc="left", fontsize=8, pad=2)
        fig.align_ylabels(axes)
        fig.tight_layout(pad=0.3, h_pad=0.6)
    else:
        fig, ax = plt.subplots()
        _draw_panel(ax, spec, series_list, warnings,
                    metric=0, ylabel=spec.ylabel, add_legend=True,
                    collect_warnings=True, add_xlabel=True, allow_log_y=True)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, **({'dpi': dpi} if dpi else {}))
    plt.close(fig)
    return True, warnings


def _draw_panel(ax, spec: ExperimentSpec, series_list: Sequence[Series],
                warnings: List[str], *, metric: int, ylabel: str,
                add_legend: bool, collect_warnings: bool,
                add_xlabel: bool, allow_log_y: bool) -> None:
    """Draw every series' `metric` onto one axes."""
    # The furthest point any scheme reached, so a shorter series can be marked.
    _all_x = [v for s in series_list for v in s.x]
    max_x = max(_all_x) if _all_x else None
    for series in sorted(series_list,
                         key=lambda s: LEGEND_ORDER.index(s.scheme)
                         if s.scheme in LEGEND_ORDER else 99):
        label = SCHEME_LABELS.get(series.scheme, series.scheme)
        # A series that stops short of the sweep is a DISCLOSED CAP, not missing
        # data -- guo_vdsse's Exp. 2 ends at N=2e5 because its forward index is
        # 51.7 GB at 10^6 on a 16 GiB host, and thingom_pq_abse ends at 10^4 for
        # the same class of reason. Unlabelled, a line that simply stops reads
        # as a failed run; the first question anyone asks of the figure is why
        # it vanishes. Say so on the curve itself.
        if series.x and max_x is not None and max(series.x) < max_x:
            label += f" (to {_axis_number(max(series.x))})"
        # n_runs=0 marks a point COMPUTED from a measured anchor rather than
        # run (infra/extrapolate_points.py). Those markers are drawn HOLLOW so
        # the figure still separates measured from computed at a glance.
        #
        # A legend suffix saying so was removed on request 2026-08-31. The
        # marker is now the ONLY in-figure signal, which means the FIGURE
        # CAPTION in section V has to state which points are extrapolated --
        # a hollow marker shows a reader that something differs, not what.
        computed = [i for i, n in enumerate(series.n_runs) if n == 0]
        yvals, yerrs = _panel_values(series, metric)
        if not yvals:
            # A scheme that records no such secondary simply has no curve on
            # this panel; the others still draw.
            continue
        ax.errorbar(
            series.x, yvals, yerr=yerrs,
            label=label, capsize=2, markersize=3.5, linewidth=1.1,
            elinewidth=0.8, **style_for(series.scheme),
        )
        if computed:
            st = style_for(series.scheme)
            ax.plot([series.x[i] for i in computed],
                    [yvals[i] for i in computed],
                    linestyle="none", marker=st["marker"], markersize=3.5,
                    markerfacecolor="white", markeredgecolor=st["color"],
                    markeredgewidth=0.9, zorder=3)
        if not collect_warnings:
            continue
        if series.reportable is False:
            warnings.append(
                f"exp{spec.number}: {series.scheme} is NOT reportable "
                f"(run_meta.json) — development data, not for submission"
            )
        elif series.reportable is None:
            warnings.append(
                f"exp{spec.number}: {series.scheme} has no readable run_meta.json"
            )
        short = [n for n in series.n_runs if n < 30]
        if short:
            warnings.append(
                f"exp{spec.number}: {series.scheme} has points with n_runs<30 "
                f"(min {min(short)}) — README §9 requires 30 for reportable data"
            )
        warnings.extend(series.problems)

    if add_xlabel:
        ax.set_xlabel(spec.xlabel)
    ax.set_ylabel(ylabel)
    if spec.log_x:
        # Same guard as log_y below, for the same reason: a log axis silently
        # drops non-positive values, so a variable_value of 0 would vanish from
        # the figure without any indication it had been read.
        all_x = [v for s in series_list for v in s.x]
        if all_x and min(all_x) > 0:
            ax.set_xscale("log")
        else:
            warnings.append(
                f"exp{spec.number}: log x-axis requested but data contains "
                f"non-positive values; drew linear instead so nothing is hidden"
            )
    if spec.log_y and allow_log_y:
        # Only if every plotted value is strictly positive — a zero or negative
        # would be silently dropped by a log axis, which would hide data.
        all_y = [v for s in series_list for v in _panel_values(s, metric)[0]]
        if all_y and min(all_y) > 0:
            ax.set_yscale("log")
        else:
            warnings.append(
                f"exp{spec.number}: log y-axis requested but data contains "
                f"non-positive values; drew linear instead so nothing is hidden"
            )
    ax.grid(True, which="major", linewidth=0.3, alpha=0.5)
    if spec.log_x or spec.log_y:
        ax.grid(True, which="minor", linewidth=0.2, alpha=0.3)

    # HEADROOM. These curves span up to six decades (0.08 ms for the proposed
    # scheme against 150,000 ms for Ref[41] in Exp. 3), and matplotlib fits the
    # axis tightly to the data. The legend then sits ON the topmost series and
    # everything reads as squeezed into the lower half. Add room above the data
    # for the legend, and a little below so the lowest series is not on the
    # frame. Done by extending the LIMITS, never by clipping: no point moves and
    # nothing is hidden.
    #
    # The legend now sits INSIDE the axes (see below), so it needs more room
    # than the 0.25-decade margin an outside legend wanted -- otherwise `best`
    # is choosing between corners that are all occupied.
    # The added band is a FRACTION of the data's own span, not a fixed number of
    # decades: a five-row legend costs roughly a third of the axes height, and a
    # fixed +0.75 decades that clears the curves in Exp. 5 (two decades) is
    # invisible in Exp. 2 (seven). Capped so a very wide span does not push the
    # data into a strip at the bottom.
    if ax.get_yscale() == "log":
        lo, hi = ax.get_ylim()
        if lo > 0 and hi > lo:
            span = math.log10(hi) - math.log10(lo)
            grow = min(0.72 * span, 4.6) if add_legend else 0.10 * span
            ax.set_ylim(10 ** (math.log10(lo) - 0.25),
                        10 ** (math.log10(hi) + grow))
    else:
        # One-sided, and never below zero. `ax.margins(y=...)` expands BOTH
        # directions, which on Exp. 1 put the floor at -100 ms -- a negative
        # latency, which is not a quantity. Every metric plotted here is a
        # duration, a count or a ratio, so zero is a real floor: hold it when
        # the data does, and spend the whole margin above, where the legend is.
        #
        # The 0.65 band exists to hold the LEGEND. A panel without one needs
        # only breathing room, and on a stacked figure the difference is
        # stark: Exp. 8's max-utilization panel spent two thirds of its height
        # empty because it inherited a margin sized for a legend it does not
        # carry.
        lo, hi = ax.get_ylim()
        if hi > lo:
            grow = 0.65 if add_legend else 0.10
            ax.set_ylim(0.0 if lo >= 0 else lo - 0.05 * (hi - lo),
                        hi + grow * (hi - lo))

    # Legend INSIDE the axes, one entry per row.
    #
    # It used to sit above the axes in two expanded columns. That collided: with
    # `mode="expand"` the two columns split the width evenly regardless of label
    # length, and "Proposed (MA-LB-PQ-VDSE)" is far longer than half the figure,
    # so it overprinted "Perera & Fugkeaw [54]" in the second column and both
    # became unreadable. Widening the columns is not available -- the figure is
    # fixed at IEEE single-column width.
    #
    # ncol=1 removes the collision by construction: no entry can ever run into
    # another, at any figure width or label length. `loc="best"` then picks the
    # emptiest corner per figure, which differs by experiment -- upper-left is
    # free in Exp. 1 (one rising series), lower-right in Exp. 2 (all series
    # rise). The extra headroom above keeps a corner genuinely free rather than
    # letting `best` settle on top of a curve.
    #
    # A frame is required here, unlike outside the axes: the legend now overlays
    # gridlines, and unframed text on a grid is what makes a figure look sloppy
    # in print. Opaque white, thin grey edge -- and the headroom means it covers
    # empty space, not data.
    if add_legend:
        ax.legend(frameon=True, ncol=1, loc="best",
                  framealpha=1.0, facecolor="white", edgecolor="0.7",
                  borderpad=0.3, labelspacing=0.22, handlelength=1.5)
        ax.get_legend().get_frame().set_linewidth(0.4)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 Plots/generate_plots.py",
        description="Generate the manuscript's eight figures (README §10).",
    )
    parser.add_argument("--input", default="Schemes",
                        help="root containing <scheme>/exp<N>_*/results.csv")
    parser.add_argument("--output", default="Plots/output",
                        help="directory to write the PDFs into")
    parser.add_argument("--experiment", default="all",
                        help="all, or a comma-separated subset e.g. 1,2,6")
    parser.add_argument("--require-reportable", action="store_true",
                        help="refuse to plot any series whose run_meta.json "
                             "is not reportable:true")
    parser.add_argument("--format", default="pdf",
                        help="output format(s), comma-separated, e.g. 'pdf' or "
                             "'pdf,png'. README §10 wants vector for the paper, "
                             "so pdf stays the default. With MORE THAN ONE "
                             "format each goes in its own subdirectory "
                             "(<output>/pdf/, <output>/png/) so a raster copy "
                             "can never be picked up where the vector one "
                             "belongs; a single format writes to <output>/ "
                             "directly, unchanged.")
    parser.add_argument("--scale", type=float, default=1.0,
                        help="multiply the figure size. The default 3.5x2.6in "
                             "is IEEE single-column and is what the paper needs; "
                             "use e.g. --scale 1.8 for a copy that is readable "
                             "on screen without changing the paper figures.")
    parser.add_argument("--png-dpi", type=int, default=200,
                        help="raster resolution; 200 is legible on a slide and "
                             "in a review PDF without being enormous")
    args = parser.parse_args(argv)

    if args.scale != 1.0:
        w, h = plt.rcParams["figure.figsize"]
        plt.rcParams["figure.figsize"] = (w * args.scale, h * args.scale)

    if args.experiment.strip().lower() == "all":
        wanted = {spec.number for spec in EXPERIMENTS}
    else:
        try:
            wanted = {int(tok) for tok in args.experiment.split(",") if tok.strip()}
        except ValueError:
            raise SystemExit(f"--experiment {args.experiment!r} is not a number list")
        unknown = wanted - {spec.number for spec in EXPERIMENTS}
        if unknown:
            raise SystemExit(f"no such experiment(s): {sorted(unknown)} (1-8)")

    input_root = Path(args.input)
    output_root = Path(args.output)
    if not input_root.is_dir():
        raise SystemExit(f"--input {input_root} is not a directory")

    written: List[str] = []
    skipped: List[str] = []
    all_warnings: List[str] = []

    for spec in EXPERIMENTS:
        if spec.number not in wanted:
            continue
        found = collect(input_root, spec)
        if args.require_reportable:
            kept = [s for s in found if s.reportable is True]
            for s in found:
                if s.reportable is not True:
                    all_warnings.append(
                        f"exp{spec.number}: dropped {s.scheme} "
                        f"(--require-reportable, reportable={s.reportable})"
                    )
            found = kept
        fmts = [f.strip().lstrip(".").lower()
                for f in args.format.split(",") if f.strip()] or ["pdf"]
        multi = len(fmts) > 1
        rendered_any = False
        for fmt in fmts:
            name = spec.filename if fmt == "pdf" else re.sub(
                r"\.pdf$", f".{fmt}", spec.filename)
            target_dir = output_root / fmt if multi else output_root
            target_dir.mkdir(parents=True, exist_ok=True)
            ok, warns = render(spec, found, target_dir / name,
                               dpi=args.png_dpi if fmt == "png" else None)
            # Warnings describe the DATA, not the format, so collect them once
            # rather than repeating every reportability warning per format.
            if not rendered_any:
                all_warnings.extend(warns)
            if ok:
                rendered_any = True
                rel = f"{fmt}/{name}" if multi else name
                written.append(f"{rel}  ({len(found)} scheme(s): "
                               f"{', '.join(sorted(s.scheme for s in found))})")
        if not rendered_any:
            skipped.append(f"exp{spec.number}")

    for warning in all_warnings:
        print(f"  WARNING {warning}")
    print()
    for line in written:
        print(f"  wrote {output_root / line.split('  ')[0]}"
              f"{line[len(line.split('  ')[0]):]}")
    if skipped:
        print(f"\n  no data, not written: {', '.join(skipped)}")
    # `written` counts FILES; with --format pdf,png that is two per experiment,
    # so reporting it against the experiment count printed "16/8".
    n_figs = len({w.split("  ")[0].split("/")[-1].rsplit(".", 1)[0] for w in written})
    extra = f" ({len(written)} files)" if len(written) != n_figs else ""
    print(f"\n{n_figs}/{len(wanted)} figure(s) written to {output_root}{extra}")

    # A missing figure is not an error — partial campaigns are expected while
    # schemes finish on different instances. Exit non-zero only if nothing at
    # all was produced, which usually means --input points somewhere wrong.
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
