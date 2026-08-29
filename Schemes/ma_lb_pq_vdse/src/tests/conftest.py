"""Test-suite defaults for the proposed scheme.

The 30 s ramp README §7 requires for Exp. 7-8 is a property of a *reported*
measurement, not of the harness's structure. Paying it in the unit tests took
the suite from 3 s to 202 s -- 129 s of that in one test that builds all four
variants -- while testing nothing the tests assert. The campaign path is
unaffected: `main.py` imports the module and gets `RAMP_SECONDS = 30.0`.

`test_scheduler_ablation_ramps_before_measuring` covers the ramp itself, so
zeroing it here removes cost without removing coverage.
"""

import pytest

from ..harness import experiments as experiments_mod


@pytest.fixture(autouse=True)
def _no_ramp(monkeypatch):
    monkeypatch.setattr(experiments_mod, "RAMP_SECONDS", 0.0)
