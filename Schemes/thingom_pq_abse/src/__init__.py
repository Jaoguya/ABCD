"""Ref[41] — Thingom et al., PQ-ABSE (IEEE TCE 2026).

Implementation of the published construction. See ``scheme.py`` for the
construction and the two places where the paper's notation is not
self-consistent, and ``experiments.py`` for the two readings the benchmark
had to fix.
"""

from . import experiments, harness, lsss, scheme

__all__ = ["experiments", "harness", "lsss", "scheme"]
