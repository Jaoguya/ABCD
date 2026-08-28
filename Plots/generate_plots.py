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
    "feng_bl_abse": "Feng et al. [57]",
}

# Marker AND linestyle both vary, so the figures survive grayscale (README §10).
# The proposed scheme is pinned to index 0 so it is visually consistent across
# all eight figures rather than shifting when a baseline is absent.
STYLE_ORDER: Tuple[str, ...] = (
    "ma_lb_pq_vdse", "guo_vdsse", "thingom_pq_abse",
    "perera_lv_pqabse", "feng_bl_abse",
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


def collect(input_root: Path, spec: ExperimentSpec) -> List[Series]:
    """Find every scheme's results for one experiment.

    Matches ``exp<N>_*`` rather than the exact folder name so a scheme that
    names its directory slightly differently is still picked up instead of
    silently contributing nothing.
    """
    found: List[Series] = []
    if not input_root.is_dir():
        return found
    for scheme_dir in sorted(p for p in input_root.iterdir() if p.is_dir()):
        matches = sorted(scheme_dir.glob(f"exp{spec.number}_*"))
        for exp_dir in matches:
            if not exp_dir.is_dir():
                continue
            series = read_results(exp_dir / "results.csv", scheme_dir.name)
            if series is not None:
                found.append(series)
                break  # first matching directory wins; duplicates reported below
        if len(matches) > 1:
            print(f"  NOTE {scheme_dir.name}: multiple exp{spec.number}_* dirs "
                  f"{[m.name for m in matches]}; used {matches[0].name}")
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


def render(spec: ExperimentSpec, series_list: Sequence[Series],
           out_path: Path) -> Tuple[bool, List[str]]:
    """Draw one figure. Returns (written, warnings)."""
    warnings: List[str] = []
    if not series_list:
        return False, [f"exp{spec.number}: no results.csv found for any scheme"]

    fig, ax = plt.subplots()
    for series in sorted(series_list,
                         key=lambda s: STYLE_ORDER.index(s.scheme)
                         if s.scheme in STYLE_ORDER else 99):
        label = SCHEME_LABELS.get(series.scheme, series.scheme)
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
        ax.set_xscale("log")
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
    ax.legend(frameon=False)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
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
                        help="output format (default pdf; README §10 wants vector)")
    args = parser.parse_args(argv)

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
        name = spec.filename
        if args.format != "pdf":
            name = re.sub(r"\.pdf$", f".{args.format}", name)
        ok, warns = render(spec, found, output_root / name)
        all_warnings.extend(warns)
        if ok:
            written.append(f"{name}  ({len(found)} scheme(s): "
                           f"{', '.join(sorted(s.scheme for s in found))})")
        else:
            skipped.append(f"exp{spec.number}")

    for warning in all_warnings:
        print(f"  WARNING {warning}")
    print()
    for line in written:
        print(f"  wrote {output_root / line.split('  ')[0]}"
              f"{line[len(line.split('  ')[0]):]}")
    if skipped:
        print(f"\n  no data, not written: {', '.join(skipped)}")
    print(f"\n{len(written)}/{len(wanted)} figure(s) written to {output_root}")

    # A missing figure is not an error — partial campaigns are expected while
    # schemes finish on different instances. Exit non-zero only if nothing at
    # all was produced, which usually means --input points somewhere wrong.
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
