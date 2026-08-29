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
class ExperimentSpec:
    number: int
    folder: str
    filename: str
    xlabel: str
    ylabel: str
    log_x: bool = False
    log_y: bool = False


EXPERIMENTS: Tuple[ExperimentSpec, ...] = (
    ExperimentSpec(1, "exp1_trapdoor_generation", "fig_exp1_trapdoor.pdf",
                   "Queried keywords $q$", "Trapdoor generation latency (ms)"),
    ExperimentSpec(2, "exp2_search_latency", "fig_exp2_search.pdf",
                   "Index size $N$ (records)", "Search latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(3, "exp3_crossdomain_scalability", "fig_exp3_crossdomain.pdf",
                   "Domains $d$", "Cross-domain search latency (ms)",
                   log_y=True),
    ExperimentSpec(4, "exp4_verification_overhead", "fig_exp4_verify.pdf",
                   "Returned results $r$", "Verification latency (ms)"),
    ExperimentSpec(5, "exp5_keyword_update", "fig_exp5_update.pdf",
                   "Updated (keyword, document) pairs $k$", "Update latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(6, "exp6_authorization_sync", "fig_exp6_sync.pdf",
                   "Authorization updates $\\delta$", "Synchronization latency (ms)",
                   log_x=True, log_y=True),
    ExperimentSpec(7, "exp7_search_throughput", "fig_exp7_throughput.pdf",
                   "Concurrent queries", "Throughput (queries/s)"),
    ExperimentSpec(8, "exp8_load_balance", "fig_exp8_balance.pdf",
                   "Concurrent queries", "FSN utilization std. dev."),
)

# Exp. 2's y-range spans ~6 orders of magnitude between the proposed scheme and
# a pairing-based baseline, so a linear y-axis would collapse every curve but
# the slowest into the x-axis. log_y is set above for the experiments where
# that is true; it is NOT a presentational choice made per-figure to flatter a
# result (AGENT_RULES "Bias Detection"), it is set once here for all runs.


# Display names. Anything not listed falls back to the directory name, so a
# newly added scheme still plots (with an uglier label) rather than vanishing.
SCHEME_LABELS: Dict[str, str] = {
    "ma_lb_pq_vdse": "Proposed (MA-LB-PQ-VDSE)",
    "guo_vdsse": "Guo et al. [35]",
    "thingom_pq_abse": "Thingom et al. [41]",
    "perera_lv_pqabse": "Perera & Fugkeaw [54]",
    "yue_ge": "Ge et al. [55]",
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


def style_for(scheme: str) -> Dict[str, object]:
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
                ci = _to_float(row.get("primary_ci95", "")) or 0.0
                n = _to_float(row.get("n_runs", "")) or 0
                series.x.append(x)
                series.y.append(y)
                series.yerr.append(ci)
                series.n_runs.append(int(n))
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


#: Exp. 7-8 are an ABLATION, not a cross-scheme comparison (README §5): the four
#: series on those two figures are scheduler variants of one scheme. Order is
#: fixed here so the legend reads weakest-to-proposed on every regeneration.
ABLATION_VARIANTS: Tuple[Tuple[str, str], ...] = (
    ("no_lb", "No load balancing"),
    ("round_robin", "Round robin"),
    ("least_loaded", "Least loaded"),
    ("aass", "AASS (proposed)"),
)


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
    suffix = exp_dir.name.rsplit("__", 1)[-1] if "__" in exp_dir.name else ""
    return suffix or None


def collect_ablation(input_root: Path, spec: ExperimentSpec) -> List[Series]:
    """One series per scheduler variant, for Exp. 7-8.

    ``collect`` takes the FIRST matching ``exp<N>_*`` directory per scheme and
    stops, which is right for a cross-scheme figure and wrong here: it would
    draw a single curve labelled with the scheme name where §V claims a
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
            if variant in dict(ABLATION_VARIANTS):
                by_variant.setdefault(variant, exp_dir)
    for variant, label in ABLATION_VARIANTS:
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
    if spec.number in (7, 8):
        return collect_ablation(input_root, spec)
    found: List[Series] = []
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


def render(spec: ExperimentSpec, series_list: Sequence[Series],
           out_path: Path, dpi: Optional[int] = None) -> Tuple[bool, List[str]]:
    """Draw one figure. Returns (written, warnings)."""
    warnings: List[str] = []
    # The furthest point any scheme reached, so a shorter series can be marked.
    _all_x = [v for s in series_list for v in s.x]
    max_x = max(_all_x) if _all_x else None
    if not series_list:
        return False, [f"exp{spec.number}: no results.csv found for any scheme"]

    fig, ax = plt.subplots()
    for series in sorted(series_list,
                         key=lambda s: STYLE_ORDER.index(s.scheme)
                         if s.scheme in STYLE_ORDER else 99):
        label = SCHEME_LABELS.get(series.scheme, series.scheme)
        # A series that stops short of the sweep is a DISCLOSED CAP, not missing
        # data -- guo_vdsse's Exp. 2 ends at N=2e5 because its forward index is
        # 51.7 GB at 10^6 on a 16 GiB host, and thingom_pq_abse ends at 10^4 for
        # the same class of reason. Unlabelled, a line that simply stops reads
        # as a failed run; the first question anyone asks of the figure is why
        # it vanishes. Say so on the curve itself.
        if series.x and max_x is not None and max(series.x) < max_x:
            label += f" (to {_axis_number(max(series.x))})"
        ax.errorbar(
            series.x, series.y, yerr=series.yerr,
            label=label, capsize=2, markersize=3.5, linewidth=1.1,
            elinewidth=0.8, **style_for(series.scheme),
        )
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

    ax.set_xlabel(spec.xlabel)
    ax.set_ylabel(spec.ylabel)
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
    if spec.log_y:
        # Only if every plotted value is strictly positive — a zero or negative
        # would be silently dropped by a log axis, which would hide data.
        all_y = [v for s in series_list for v in s.y]
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
    if ax.get_yscale() == "log":
        lo, hi = ax.get_ylim()
        if lo > 0 and hi > lo:
            ax.set_ylim(10 ** (math.log10(lo) - 0.25),
                        10 ** (math.log10(hi) + 0.25))
    else:
        ax.margins(y=0.12)

    # Legend ABOVE the axes, not inside them. With five series spanning six
    # decades there is no free corner: an in-axes legend lands on whichever
    # series is topmost (Ref[41] at ~150,000 ms in Exp. 3) and hides the very
    # curve it is labelling. Placing it outside costs a little height and keeps
    # the whole plot area for data.
    # Two columns, not three: the proposed scheme's label is the longest by far
    # ("Proposed (MA-LB-PQ-VDSE)") and at three columns it runs into the next
    # entry's marker. Two columns gives every entry room at any figure width.
    ncol = 2 if len(series_list) >= 3 else 1
    ax.legend(frameon=False, ncol=ncol,
              loc="lower left", bbox_to_anchor=(0.0, 1.01, 1.0, 0.18),
              mode="expand", borderaxespad=0.0,
              columnspacing=1.0, handlelength=1.6)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, **({'dpi': dpi} if dpi else {}))
    plt.close(fig)
    return True, warnings


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
