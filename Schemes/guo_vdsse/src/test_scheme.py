"""Unit tests for Guo VDSSE core scheme (Ref[35]).

Verifies:
  1. Setup → Update → Search round-trip correctness
  2. Conjunctive query filtering
  3. Verification acceptance for honest execution
  4. Verification rejection for tampered results
  5. Forward privacy: version advancement prevents replay
  6. PuncturedKey serialization round-trip
  7. Delete operation correctness
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is importable
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest

from Schemes.guo_vdsse.src.scheme import (
    GuoVDSSE,
    SearchResult,
    _deserialize_punctured_key,
    _serialize_punctured_key,
)


@pytest.fixture
def scheme():
    return GuoVDSSE()


@pytest.fixture
def populated_scheme(scheme):
    """A scheme with a small test corpus."""
    state, edb = scheme.setup()

    # 5 documents with overlapping keywords
    docs = [
        (0, ["alpha", "beta", "gamma", "delta", "epsilon"]),
        (1, ["alpha", "beta", "zeta", "eta", "theta"]),
        (2, ["alpha", "gamma", "iota", "kappa", "lambda"]),
        (3, ["beta", "delta", "mu", "nu", "xi"]),
        (4, ["alpha", "beta", "gamma", "omicron", "pi"]),
    ]
    for rid, kws in docs:
        scheme.update(state, edb, "add", rid, kws)

    return state, edb, docs


class TestSetupAndUpdate:
    def test_setup_creates_empty_edb(self, scheme):
        state, edb = scheme.setup()
        assert edb.inverted_entry_count == 0
        assert edb.forward_entry_count == 0

    def test_update_adds_entries(self, scheme):
        state, edb = scheme.setup()
        entries = scheme.update(state, edb, "add", 0, ["a", "b", "c"])
        # 3 inverted + 1 forward = 4
        assert entries == 4
        assert edb.inverted_entry_count == 3
        assert edb.forward_entry_count == 1


class TestSingleKeywordSearch:
    def test_single_keyword_returns_correct_docs(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # "alpha" appears in docs 0, 1, 2, 4
        result = scheme.search(state, edb, ["alpha"])
        assert result.result_ids == {0, 1, 2, 4}

    def test_missing_keyword_returns_empty(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        result = scheme.search(state, edb, ["nonexistent"])
        assert result.result_ids == set()

    def test_unique_keyword_returns_single_doc(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # "omicron" appears only in doc 4
        result = scheme.search(state, edb, ["omicron"])
        assert result.result_ids == {4}


class TestConjunctiveSearch:
    def test_two_keyword_conjunctive(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # "alpha" AND "beta" → docs 0, 1, 4
        result = scheme.search(state, edb, ["alpha", "beta"])
        assert result.result_ids == {0, 1, 4}

    def test_three_keyword_conjunctive(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # "alpha" AND "beta" AND "gamma" → docs 0, 4
        result = scheme.search(state, edb, ["alpha", "beta", "gamma"])
        assert result.result_ids == {0, 4}

    def test_disjoint_keywords_return_empty(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # "zeta" only in doc 1, "mu" only in doc 3 → no overlap
        result = scheme.search(state, edb, ["zeta", "mu"])
        assert result.result_ids == set()

    def test_entries_traversed_is_positive(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        result = scheme.search(state, edb, ["alpha", "beta"])
        assert result.entries_traversed > 0


class TestVerification:
    def test_honest_verification_accepts(self, scheme):
        state, edb = scheme.setup()
        scheme.update(state, edb, "add", 0, ["cat", "dog", "bird", "fish", "ant"])
        scheme.update(state, edb, "add", 1, ["cat", "fish", "fly", "bee", "cow"])

        result = scheme.search(state, edb, ["cat"])
        assert scheme.verify(state, result.least_frequent_keyword, result)

    def test_tampered_proof_rejects(self, scheme):
        state, edb = scheme.setup()
        scheme.update(state, edb, "add", 0, ["red", "green", "blue", "pink", "grey"])

        result = scheme.search(state, edb, ["red"])
        # Tamper with the proof
        result.proof_inverted = b"\xff" * len(result.proof_inverted)
        assert not scheme.verify(state, result.least_frequent_keyword, result)


class TestDeleteOperation:
    def test_delete_removes_from_results(self, scheme):
        state, edb = scheme.setup()
        scheme.update(state, edb, "add", 0, ["sun", "moon", "star", "sky", "cloud"])
        scheme.update(state, edb, "add", 1, ["sun", "rain", "snow", "wind", "fog"])

        # Verify both are found
        result = scheme.search(state, edb, ["sun"])
        assert 0 in result.result_ids
        assert 1 in result.result_ids

        # Delete doc 0
        scheme.update(state, edb, "del", 0, ["sun", "moon", "star", "sky", "cloud"])

        # Now only doc 1 should be found
        result = scheme.search(state, edb, ["sun"])
        assert result.result_ids == {1}


class TestForwardPrivacy:
    def test_version_advances_after_search(self, scheme):
        state, edb = scheme.setup()
        scheme.update(state, edb, "add", 0, ["x", "y", "z", "w", "v"])

        kw_state_before = state.get("x")
        v_before = kw_state_before.v_w

        scheme.search(state, edb, ["x"])

        kw_state_after = state.get("x")
        assert kw_state_after.v_w == v_before + 1


class TestPuncturedKeySerialization:
    def test_round_trip(self, scheme):
        from Common.crypto.prf import PuncturablePRF
        from Common.crypto import config as crypto_config

        params = crypto_config.scheme_params("guo_vdsse")
        prf_params = params["puncturable_prf"]
        lambda_bytes = params["security_parameter_lambda"] // 8

        prf = PuncturablePRF.setup(
            domain_bits=prf_params["domain_bits"],
            output_bytes=prf_params["output_bits"] // 8,
            key_bytes=lambda_bytes,
        )

        points = [prf.encode(f"kw{i}".encode()) for i in range(5)]
        pk = prf.puncture(points)

        serialized = _serialize_punctured_key(pk)
        deserialized = _deserialize_punctured_key(serialized)

        assert deserialized.domain_bits == pk.domain_bits
        assert deserialized.output_bytes == pk.output_bytes
        assert deserialized.key_bytes == pk.key_bytes
        assert deserialized.nodes == pk.nodes
        assert deserialized.punctured == pk.punctured


class TestSearchToken:
    def test_token_size_is_deterministic(self, scheme, populated_scheme):
        state, edb, docs = populated_scheme

        # First search — no cache, k_x_{v-1} absent
        token = scheme.generate_search_token(state, ["alpha"])
        size1 = token.size_bytes

        # The size should be: lambda_bytes (k_x_v) + 4 (lcnt) + 1 (st2)
        # k_x_{v-1} is absent on first search (v_w == 1)
        expected = state.lambda_bytes + 4 + 1
        assert size1 == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
