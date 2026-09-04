"""GC-quiesced timing for short measured regions.

Why this exists
---------------
Exp. 4's ``measure`` verifies a pre-built, immutable bundle set and mutates
nothing, so all fifteen calls of a point (five warm-ups, ten retained) do
byte-identical work. Run 4 at r=1000 nonetheless measured 45.4 ms against the
other nine at 15.13-15.51 ms, and it did so at the SAME run index on two
independent hosts-and-days. Instrumenting ``gc.get_stats()`` across each call
put the spike on exactly the call where the gen-2 collection counter
incremented, and disabling collection across the timed region flattened all
fifteen calls to 15.44-15.52 ms.

So the outlier is the interpreter's collection schedule, not the scheme. It
inflated the reported mean 19% over the median (18.49 vs 15.44 ms) and gave the
point a 37% confidence interval, and which run absorbs it is decided by the
harness's own allocation history rather than by anything being measured.

Timing with collection disabled is what ``timeit`` does by default, for this
reason: its documentation calls it "make independent timings more comparable".

Scope, deliberately narrow
--------------------------
This is applied at Exp. 4's four call sites ONLY -- one per scheme -- and NOT
inside the baselines' shared ``measure_ns``, which every other experiment also
routes through. Changing that would silently re-time Exp. 1, 2, 3 and 5 as a
side effect of an Exp. 4 fix. Exp. 2/6/7/8 runs are long enough that a ~17 ms
pause is under 0.1% of the measurement and their banked numbers stand.

Memory
------
A disabled collector cannot reclaim cycles, so peak RSS rises with the length of
the region. Exp. 2 has already needed real work to fit its host (yue_ge's
forward index went 34 GB -> 10.5 GB), so the guard below DISARMS itself the
first time a region overruns ``max_seconds`` and every later region runs with
the collector on. A misapplication degrades to today's behaviour rather than to
an OOM.

``gc.freeze()`` moves everything already allocated -- the prepared fixture,
which for Exp. 4 at r=1000 is a thousand verification bundles -- into the
permanent generation, where collections no longer traverse it. That shrinks the
pause at its source rather than only deferring it.
"""

from __future__ import annotations

import gc
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Tuple

#: A region longer than this disarms quiescing for the rest of the process.
#: Exp. 4's slowest point is Scheme [54] at ~220 ms, so every legitimate use
#: sits an order of magnitude under it.
DEFAULT_MAX_SECONDS = 1.0


class _Quiescer:
    """Process-wide arm/disarm state for GC quiescing."""

    def __init__(self) -> None:
        self.armed = True
        self.frozen = False
        self.disarm_reason = ""

    def disarm(self, reason: str) -> None:
        self.armed = False
        self.disarm_reason = reason


_STATE = _Quiescer()


def reset_state() -> None:
    """Re-arm. For tests; a campaign process should never need it."""
    global _STATE
    if _STATE.frozen:
        gc.unfreeze()
    _STATE = _Quiescer()


@contextmanager
def gc_quiesced(max_seconds: float = DEFAULT_MAX_SECONDS) -> Iterator[None]:
    """Run the block with cyclic collection paused, if that is safe here.

    Yields with the collector disabled and the existing heap frozen. Re-enables
    on the way out, including on an exception, so a raising measurement cannot
    leave the collector off for the rest of the campaign.
    """
    if not _STATE.armed:
        yield
        return

    if not _STATE.frozen:
        # Everything allocated so far is fixture, not garbage under test.
        gc.freeze()
        _STATE.frozen = True

    was_enabled = gc.isenabled()
    gc.disable()
    started = time.perf_counter_ns()
    try:
        yield
    finally:
        elapsed = (time.perf_counter_ns() - started) / 1e9
        if was_enabled:
            gc.enable()
        if elapsed > max_seconds:
            _STATE.disarm(
                f"a timed region ran {elapsed:.2f}s (> {max_seconds:.2f}s); "
                f"quiescing is for short regions only, and holding the "
                f"collector off across a long one raises peak memory"
            )
            if _STATE.frozen:
                gc.unfreeze()
                _STATE.frozen = False


def measure_ns_quiesced(
    fn: Callable[[], Any], max_seconds: float = DEFAULT_MAX_SECONDS
) -> Tuple[float, Any]:
    """``measure_ns``, with the collector paused across the timed region.

    Returns ``(elapsed_ms, fn_return_value)`` — the same shape each scheme's
    ``measure_ns`` returns, so it drops into an Exp. 4 call site unchanged.
    """
    with gc_quiesced(max_seconds):
        start = time.perf_counter_ns()
        result = fn()
        elapsed_ns = time.perf_counter_ns() - start
    return elapsed_ns / 1_000_000.0, result


__all__ = [
    "DEFAULT_MAX_SECONDS",
    "gc_quiesced",
    "measure_ns_quiesced",
    "reset_state",
]
