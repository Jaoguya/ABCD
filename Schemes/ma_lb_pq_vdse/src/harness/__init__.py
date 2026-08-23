"""The measurement layer — README §7 (methodology) and §9 (output format).

* ``stats.py`` — mean and 95% CI from the sample, with no trimming anywhere.
* ``provenance.py`` — ``run_meta.json``, and the reportability gate.
* ``runner.py`` — warm-ups, 30 retained runs, failure retry, CSV output.
* ``experiments.py`` — the eight experiments of README §5.

Separated from the protocol code because the measurement boundary is itself a
claim: what ``measure`` touches is what the reported number covers.
"""
