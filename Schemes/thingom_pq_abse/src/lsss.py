"""Linear Secret Sharing over F_w, per Ref[41] §II-A.

The paper defines an LSSS by an ``e x n`` matrix ``N`` whose j-th row carries
attribute ``mu(j)``, and a column vector ``o = (s, o_2, ..., o_n)^T`` whose
product ``No`` is the share vector (References/Ref[41].md:66-71).

Ref[41] never states which Boolean formula its access policies encode, only
that the DO "converts the access policy into a Linear Secret Sharing Scheme
(LSSS) access matrix N_{l x n}" (:284). This module therefore implements the
general machinery — arbitrary matrix, generic reconstruction — and supplies
an l-way AND gate as the default policy shape. An AND gate is the
conservative reading: it is the policy under which *every* row must be
satisfied, so it maximises the number of pairings the search algorithm
performs and cannot flatter the baseline.

All arithmetic is on plain ints mod the group order. Only the final
exponentiation in scheme.py touches backend element types, which keeps the
share algebra identical between charm (Type-I) and petrelic (Type-III).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple


@dataclass(frozen=True)
class AccessStructure:
    """An LSSS access structure ``(N, phi)``.

    ``matrix`` is ``N`` (e rows x n columns). ``row_attributes[j]`` is the
    attribute CATEGORY that row j maps to, i.e. Ref[41]'s ``phi(j) -> t_j``.

    Ref[41] :286 is explicit that phi maps only the category and never the
    value: "phi maps only the attribute category (not the attribute value),
    preventing malicious users from learning sensitive attribute values
    directly from the matrix N and the function phi". The values live only
    inside the hash ``O_2({phi(j) : v(j)})``, so they are recorded separately
    in ``row_values`` and are never part of the public structure.
    """

    matrix: Sequence[Sequence[int]]
    row_attributes: Sequence[str]
    row_values: Sequence[str]
    # Built once in __post_init__. A scan of N ciphertexts under one policy
    # would otherwise re-format 2u strings per entry — 2x10^7 allocations at
    # N=10^6 — for a value that never changes.
    labels: Tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "labels",
            tuple(
                f"{category}:{value}"
                for category, value in zip(self.row_attributes, self.row_values)
            ),
        )

    @property
    def rows(self) -> int:
        return len(self.matrix)

    @property
    def columns(self) -> int:
        return len(self.matrix[0]) if self.matrix else 0

    def labelled_row(self, j: int) -> str:
        """The ``{Cate_z : Value_z}`` string that ``O_2`` is evaluated on."""
        return self.labels[j]


def and_gate_policy(attributes: Sequence[tuple[str, str]]) -> AccessStructure:
    """Build the LSSS matrix for an l-way AND over ``(category, value)`` pairs.

    Additive sharing expressed as an LSSS: with ``o = (s, o_2, ..., o_l)``,

        row 1 = (1, -1, -1, ..., -1)   ->  delta_1 = s - sum_{k>=2} o_k
        row j = e_j        (j >= 2)    ->  delta_j = o_j

    so ``sum_j delta_j = s`` and every row is needed to recover the secret.
    This is a valid LSSS matrix in the sense of Ref[41] §II-A: each share is a
    vector over F_w and row j is associated with attribute mu(j).
    """
    count = len(attributes)
    if count == 0:
        raise ValueError("access policy needs at least one attribute")

    matrix: List[List[int]] = []
    first = [1] + [-1] * (count - 1)
    matrix.append(first)
    for j in range(1, count):
        row = [0] * count
        row[j] = 1
        matrix.append(row)

    return AccessStructure(
        matrix=matrix,
        row_attributes=[category for category, _ in attributes],
        row_values=[value for _, value in attributes],
    )


def share(
    structure: AccessStructure,
    secret: int,
    randomness: Sequence[int],
    order: int,
) -> List[int]:
    """Compute ``delta = N o`` where ``o = (s, o_2, ..., o_n)``.

    ``randomness`` supplies ``o_2 ... o_n`` and must have ``columns - 1``
    entries — the caller draws them so that the measured cost of sampling
    lands inside the encryption timer rather than here.
    """
    if len(randomness) != structure.columns - 1:
        raise ValueError(
            f"expected {structure.columns - 1} random values for an "
            f"{structure.rows}x{structure.columns} matrix, got {len(randomness)}"
        )

    vector = [secret, *randomness]
    shares: List[int] = []
    for row in structure.matrix:
        acc = 0
        for coefficient, component in zip(row, vector):
            acc += coefficient * component
        shares.append(acc % order)
    return shares


def reconstruction_coefficients(
    structure: AccessStructure,
    satisfied_rows: Sequence[int],
    order: int,
) -> Dict[int, int]:
    """Find ``{w_j}`` with ``sum_j w_j N_j = (1, 0, ..., 0)``.

    This is the ``w_j`` exponent in Ref[41]'s search equation (:340). The
    server must solve for it at query time — it depends on which rows the
    querying user actually satisfies — so the cost belongs inside the search
    timer, which is where scheme.py calls it.

    Gaussian elimination over F_w on the transpose. Raises ValueError when the
    supplied rows do not span the target, i.e. the attribute set does not
    satisfy the policy.
    """
    if not satisfied_rows:
        raise ValueError("no rows supplied; attribute set cannot satisfy policy")

    columns = structure.columns
    # Transpose: one equation per column of N, one unknown per satisfied row.
    # Augmented with the target vector (1, 0, ..., 0).
    augmented: List[List[int]] = []
    for column in range(columns):
        equation = [structure.matrix[j][column] % order for j in satisfied_rows]
        equation.append(1 if column == 0 else 0)
        augmented.append(equation)

    unknowns = len(satisfied_rows)
    pivot_of_column: Dict[int, int] = {}
    pivot_row = 0

    for column in range(unknowns):
        selected = None
        for row in range(pivot_row, len(augmented)):
            if augmented[row][column] % order != 0:
                selected = row
                break
        if selected is None:
            continue

        augmented[pivot_row], augmented[selected] = (
            augmented[selected],
            augmented[pivot_row],
        )
        inverse = pow(augmented[pivot_row][column], -1, order)
        augmented[pivot_row] = [
            (value * inverse) % order for value in augmented[pivot_row]
        ]

        for row in range(len(augmented)):
            if row == pivot_row:
                continue
            factor = augmented[row][column] % order
            if factor:
                augmented[row] = [
                    (value - factor * pivot_value) % order
                    for value, pivot_value in zip(augmented[row], augmented[pivot_row])
                ]

        pivot_of_column[column] = pivot_row
        pivot_row += 1

    # Any row that is all-zero in the unknowns but non-zero in the target
    # means the system is inconsistent: the policy is not satisfied.
    for row in augmented:
        if all(value % order == 0 for value in row[:unknowns]):
            if row[unknowns] % order != 0:
                raise ValueError("attribute set does not satisfy the access policy")

    coefficients: Dict[int, int] = {}
    for column, row in pivot_of_column.items():
        coefficients[satisfied_rows[column]] = augmented[row][unknowns] % order
    for index in satisfied_rows:
        coefficients.setdefault(index, 0)
    return coefficients
