"""GC quiescing must remove the pause without becoming a memory hazard.

The defect this guards: Exp. 4's measure does byte-identical work every run, yet
run 4 at r=1000 read 45.4 ms against 15.13-15.51 ms for the other nine -- at the
same run index, on two independent hosts and days. It was a gen-2 collection
landing inside the timed region.
"""

from __future__ import annotations

import gc
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from Common import timing  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_state():
    timing.reset_state()
    yield
    timing.reset_state()


def test_collection_is_off_inside_the_region_and_on_after():
    assert gc.isenabled()
    with timing.gc_quiesced():
        assert not gc.isenabled(), "the collector must be off while timing"
    assert gc.isenabled(), "the collector must come back on"


def test_collection_is_restored_even_when_the_region_raises():
    """A raising measurement must not leave the collector off for the campaign."""
    with pytest.raises(ValueError):
        with timing.gc_quiesced():
            raise ValueError("boom")
    assert gc.isenabled()


def test_measure_returns_elapsed_ms_and_the_value():
    elapsed_ms, value = timing.measure_ns_quiesced(lambda: 6 * 7)
    assert value == 42
    assert elapsed_ms >= 0.0


def test_a_long_region_disarms_quiescing_for_everything_after_it():
    """The memory guard.

    A disabled collector cannot reclaim cycles, so holding it off across a long
    region raises peak RSS -- and Exp. 2 has already needed real work to fit its
    host. One overrun turns quiescing off rather than letting it compound.
    """
    with timing.gc_quiesced(max_seconds=0.01):
        time.sleep(0.05)
    assert not timing._STATE.armed
    assert "quiescing is for short regions only" in timing._STATE.disarm_reason
    # And a later region really does leave the collector alone.
    with timing.gc_quiesced():
        assert gc.isenabled(), "disarmed quiescing must not disable collection"


def test_a_short_region_keeps_quiescing_armed():
    with timing.gc_quiesced(max_seconds=5.0):
        pass
    assert timing._STATE.armed


def test_the_heap_is_frozen_so_collections_stop_rescanning_the_fixture():
    """gc.freeze() shrinks the pause at its source rather than deferring it."""
    assert gc.get_freeze_count() == 0
    with timing.gc_quiesced():
        pass
    assert gc.get_freeze_count() > 0
    timing.reset_state()
    assert gc.get_freeze_count() == 0


def test_disarming_also_unfreezes():
    """A frozen heap that is never collected is the same hazard by another name."""
    with timing.gc_quiesced(max_seconds=0.01):
        time.sleep(0.05)
    assert gc.get_freeze_count() == 0


# ===========================================================================
# Scope — this must NOT have leaked into the shared measure_ns
# ===========================================================================
@pytest.mark.parametrize("module_path", [
    "Schemes/guo_vdsse/src/harness.py",
    "Schemes/yue_ge/src/harness.py",
    "Schemes/perera_lv_pqabse/src/harness.py",
])
def test_shared_measure_ns_is_untouched(module_path):
    """Exp. 1, 2, 3 and 5 route through measure_ns too.

    Quiescing there would silently re-time four other experiments as a side
    effect of an Exp. 4 fix, and their banked numbers were not measured that
    way. The fix is applied at Exp. 4's call sites only.
    """
    source = (REPO_ROOT / module_path).read_text(encoding="utf-8")
    start = source.index("def measure_ns(")
    body = source[start:start + 600]
    assert "gc" not in body, f"{module_path}'s measure_ns must stay GC-neutral"


@pytest.mark.parametrize("call_site", [
    "Schemes/guo_vdsse/src/exp4_verify.py",
    "Schemes/yue_ge/exp4_verification_overhead/runner.py",
    "Schemes/perera_lv_pqabse/exp4_verification_overhead/runner.py",
])
def test_every_baseline_exp4_uses_the_quiesced_timer(call_site):
    """All four arms of the figure must be measured the same way.

    One arm quiesced and three not is the same defect class as measuring one
    scheme on r6i.4xlarge and the rest on m6i.xlarge.
    """
    source = (REPO_ROOT / call_site).read_text(encoding="utf-8")
    assert "measure_ns_quiesced(" in source


def test_proposed_scheme_exp4_uses_the_quiesced_timer():
    source = (REPO_ROOT / "Schemes/ma_lb_pq_vdse/src/harness/experiments.py"
              ).read_text(encoding="utf-8")
    start = source.index("class Exp4Verification")
    body = source[start:source.index("class Exp5KeywordUpdate")]
    assert "with gc_quiesced():" in body
