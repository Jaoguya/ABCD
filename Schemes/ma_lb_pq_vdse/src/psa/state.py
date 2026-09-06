"""D2/D3 — policy-relevant authority state, and the two digests over it.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`, Phase IV Steps 1, 2 and 5:

    V_{P_i}     = {(ID_k, v_k)      : AA_k ∈ AA(PID_i)}   eq:policy-version-state
    PV_i        = H(Encode(V_{P_i}))                      eq:policy-version-digest
    AuthState_i = H(Encode({(ID_k, C_k^auth) : AA_k ∈ AA(PID_i)}))
                                                          eq:policy-auth-state

**Both are restricted to the governing authorities, and that restriction is the
whole mechanism.** The scheme this replaces carries a single integer ``VID``
(``types.py``, ~980 references), which cannot express "the state of these three
authorities and not the fourth" — so under it, any authority's update either
invalidates everything or nothing. The vector is what makes Policy-State
Non-Interference a theorem rather than a wish, and ``PolicyVersionState`` is
therefore a **sorted tuple of pairs**, not a mapping: ``canonical()`` rejects
``dict`` precisely so that an ordering decision cannot be made silently at the
point where a commitment depends on it.

WHAT IS AND IS NOT DOMAIN-SEPARATED
-----------------------------------
The manuscript writes both digests as a bare ``H(Encode(·))``. Here each is a
:class:`~..types.Record` with its own ``DOMAIN`` tag, so a ``PV_i`` can never be
presented as an ``AuthState_i`` or as any other 32-byte value in the scheme.
That is strictly stronger than the published form and matches what every other
record in ``types.py`` already does; it changes no security claim, only closes a
type confusion the paper's notation leaves open.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Mapping, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..types import Record, _check_digest, _check_identifier  # noqa: E402


class PolicyStateError(RuntimeError):
    """Raised when a policy-relevant state cannot be formed."""


@dataclass(frozen=True)
class PolicyVersionState(Record):
    """``V_{P_i}`` — eq:policy-version-state.

    :attr:`digest` is ``PV_i`` of eq:policy-version-digest.
    """

    DOMAIN: ClassVar[bytes] = b"psa-policy-version-state/v1"

    #: ``(authority_id, version)`` pairs, sorted by authority id.
    versions: Tuple[Tuple[str, int], ...]

    def __post_init__(self) -> None:
        if not self.versions:
            raise PolicyStateError(
                "V_P must cover at least one governing authority; an empty "
                "AA(PID_i) would make PV_i a constant shared by every policy"
            )
        ids = [authority for authority, _ in self.versions]
        if ids != sorted(ids):
            raise PolicyStateError(
                "V_P must be sorted by authority id so PV_i does not depend on "
                "the order AA(PID_i) was enumerated in"
            )
        if len(set(ids)) != len(ids):
            raise PolicyStateError("duplicate authority in V_P")
        for authority, version in self.versions:
            _check_identifier("authority_id", authority)
            if version < 0:
                raise PolicyStateError(
                    f"authority {authority!r} has version {version}; versions "
                    f"are monotone counters (Phase II Step 4)"
                )

    @classmethod
    def build(
        cls, versions: Mapping[str, int], governing: Sequence[str]
    ) -> "PolicyVersionState":
        """Project the global version state onto ``AA(PID_i)``.

        A governing authority missing from ``versions`` is an error rather than
        a default of 0: silently treating an unknown authority as fresh would
        let a stale FSN produce a ``PV_i`` that matches the current one.
        """
        missing = [a for a in governing if a not in versions]
        if missing:
            raise PolicyStateError(
                f"no version known for governing authorities {sorted(missing)}; "
                f"PV_i cannot be derived from a partial V^cur"
            )
        return cls(versions=tuple(sorted((a, int(versions[a])) for a in governing)))

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (tuple([authority, version] for authority, version in self.versions),)

    @property
    def authority_ids(self) -> Tuple[str, ...]:
        return tuple(authority for authority, _ in self.versions)

    def advanced(self, authority_id: str) -> "PolicyVersionState":
        """This state with one authority's version incremented (Phase VII Step 2).

        Returns ``self`` unchanged when the authority does not govern the
        policy — which is eq:unaffected-policy, ``AA_k ∉ AA(PID_i) ⟹ PV_i' =
        PV_i``, expressed as code rather than asserted in prose.
        """
        if authority_id not in self.authority_ids:
            return self
        return PolicyVersionState(
            versions=tuple(
                (a, v + 1 if a == authority_id else v) for a, v in self.versions
            )
        )


@dataclass(frozen=True)
class PolicyAuthorityState(Record):
    """``{(ID_k, C_k^auth) : AA_k ∈ AA(PID_i)}`` — eq:policy-auth-state.

    :attr:`digest` is ``AuthState_i``, the value Phase IV Step 5 folds into
    ``Commit_i`` and Phase VIII Step 2 re-derives before accepting a result.
    """

    DOMAIN: ClassVar[bytes] = b"psa-policy-auth-state/v1"

    #: ``(authority_id, C_k^auth)`` pairs, sorted by authority id.
    commitments: Tuple[Tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        if not self.commitments:
            raise PolicyStateError("AuthState_i must cover at least one authority")
        ids = [authority for authority, _ in self.commitments]
        if ids != sorted(ids):
            raise PolicyStateError("AuthState_i pairs must be sorted by authority id")
        if len(set(ids)) != len(ids):
            raise PolicyStateError("duplicate authority in AuthState_i")
        for authority, commitment in self.commitments:
            _check_identifier("authority_id", authority)
            _check_digest("C_auth", commitment)

    @classmethod
    def build(
        cls, commitments: Mapping[str, bytes], governing: Sequence[str]
    ) -> "PolicyAuthorityState":
        missing = [a for a in governing if a not in commitments]
        if missing:
            raise PolicyStateError(
                f"no authorization commitment for {sorted(missing)}; "
                f"AuthState_i cannot be derived from a partial C^cur"
            )
        return cls(
            commitments=tuple(sorted((a, commitments[a]) for a in governing))
        )

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (
            tuple([authority, commitment] for authority, commitment in self.commitments),
        )

    @property
    def authority_ids(self) -> Tuple[str, ...]:
        return tuple(authority for authority, _ in self.commitments)


def policy_state_digest(state: PolicyVersionState) -> bytes:
    """``PV_i`` — eq:policy-version-digest."""
    return state.digest()


def policy_auth_state_digest(state: PolicyAuthorityState) -> bytes:
    """``AuthState_i`` — eq:policy-auth-state."""
    return state.digest()


__all__ = [
    "PolicyAuthorityState",
    "PolicyStateError",
    "PolicyVersionState",
    "policy_auth_state_digest",
    "policy_state_digest",
]
