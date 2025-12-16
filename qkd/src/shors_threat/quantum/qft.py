"""
Quantum Fourier Transform (QFT) Implementation

The Quantum Fourier Transform is a key component of Shor's algorithm.
It transforms computational basis states into frequency (phase) basis,
enabling efficient period extraction.

Mathematical Definition:
    QFT|x⟩ = (1/√N) Σ_k e^(2πixk/N)|k⟩

The QFT is the quantum analog of the Discrete Fourier Transform,
but operates on quantum superpositions, providing exponential speedup.

Circuit Structure:
    For n qubits, QFT consists of:
    - n Hadamard gates
    - n(n-1)/2 controlled phase rotation gates
    - n/2 SWAP gates (for bit reversal)

Complexity: O(n²) gates for n qubits
"""

import cirq
import numpy as np
from typing import List, Sequence


def qft_rotations(qubits: Sequence[cirq.Qid], start_idx: int = 0) -> cirq.OP_TREE:
    """
    Generate QFT rotation gates for a subset of qubits.

    Implements the core rotation pattern:
    - Hadamard on target qubit
    - Controlled phase rotations from other qubits

    Args:
        qubits: Sequence of qubits
        start_idx: Starting index for this stage

    Yields:
        Cirq operations for QFT
    """
    n = len(qubits)
    if start_idx >= n:
        return

    # Hadamard on current qubit
    yield cirq.H(qubits[start_idx])

    # Controlled phase rotations
    for i in range(start_idx + 1, n):
        # Rotation angle: π/2^(i - start_idx)
        k = i - start_idx
        angle = np.pi / (2 ** k)
        yield cirq.CZPowGate(exponent=angle / np.pi)(qubits[i], qubits[start_idx])

    # Recurse for remaining qubits
    yield from qft_rotations(qubits, start_idx + 1)


def qft_swap(qubits: Sequence[cirq.Qid]) -> cirq.OP_TREE:
    """
    Generate SWAP gates for QFT bit reversal.

    The standard QFT convention requires reversing the output order.

    Args:
        qubits: Sequence of qubits to swap

    Yields:
        SWAP operations
    """
    n = len(qubits)
    for i in range(n // 2):
        yield cirq.SWAP(qubits[i], qubits[n - 1 - i])


def qft_circuit(qubits: List[cirq.Qid]) -> cirq.Circuit:
    """
    Create Quantum Fourier Transform circuit.

    The QFT maps computational basis states to frequency basis:
        |x⟩ → (1/√N) Σ_y e^(2πixy/N)|y⟩

    This is essential for Shor's algorithm as it extracts
    periodicity information encoded in quantum phases.

    Example for 3 qubits:
    ```
    q0: ─H─R2─R3─────────×─
           │  │          │
    q1: ───●──│──H─R2────│─
              │     │    │
    q2: ──────●─────●──H─×─
    ```

    Args:
        qubits: List of qubits to transform

    Returns:
        Cirq circuit implementing QFT
    """
    circuit = cirq.Circuit()

    # Apply rotation gates
    circuit.append(qft_rotations(qubits))

    # Apply swap gates for bit reversal
    circuit.append(qft_swap(qubits))

    return circuit


def inverse_qft_circuit(qubits: List[cirq.Qid]) -> cirq.Circuit:
    """
    Create inverse Quantum Fourier Transform circuit.

    The inverse QFT is used after modular exponentiation
    in Shor's algorithm to extract the period.

    QFT†|ψ⟩ maps frequency basis back to computational basis,
    collapsing the superposition to reveal period information.

    The inverse is obtained by:
    1. Reversing the order of gates
    2. Conjugating all phase rotations (negating angles)

    Args:
        qubits: List of qubits to transform

    Returns:
        Cirq circuit implementing inverse QFT
    """
    # Get the forward QFT circuit
    forward = qft_circuit(qubits)

    # Return the inverse (adjoint)
    return cirq.inverse(forward)


def qft_on_register(
    qubits: List[cirq.Qid],
    inverse: bool = False,
    with_swaps: bool = True
) -> cirq.Circuit:
    """
    Apply QFT to a quantum register with options.

    Args:
        qubits: List of qubits forming the register
        inverse: If True, apply inverse QFT
        with_swaps: If True, include final SWAP gates

    Returns:
        QFT circuit
    """
    circuit = cirq.Circuit()

    n = len(qubits)

    if inverse:
        # Inverse QFT: reverse operations, negate phases

        # Swaps first (reversed order)
        if with_swaps:
            for i in range(n // 2):
                circuit.append(cirq.SWAP(qubits[i], qubits[n - 1 - i]))

        # Rotations in reverse
        for i in range(n - 1, -1, -1):
            # Controlled rotations first (reversed)
            for j in range(n - 1, i, -1):
                k = j - i
                angle = -np.pi / (2 ** k)  # Negated for inverse
                circuit.append(
                    cirq.CZPowGate(exponent=angle / np.pi)(qubits[j], qubits[i])
                )
            # Then Hadamard
            circuit.append(cirq.H(qubits[i]))
    else:
        # Forward QFT
        for i in range(n):
            circuit.append(cirq.H(qubits[i]))
            for j in range(i + 1, n):
                k = j - i
                angle = np.pi / (2 ** k)
                circuit.append(
                    cirq.CZPowGate(exponent=angle / np.pi)(qubits[j], qubits[i])
                )

        if with_swaps:
            for i in range(n // 2):
                circuit.append(cirq.SWAP(qubits[i], qubits[n - 1 - i]))

    return circuit


class QuantumFourierTransform:
    """
    Class-based QFT implementation with utilities.

    Provides methods for creating, analyzing, and testing QFT circuits.
    """

    def __init__(self, n_qubits: int):
        """
        Initialize QFT for n qubits.

        Args:
            n_qubits: Number of qubits
        """
        self.n_qubits = n_qubits
        self.qubits = cirq.LineQubit.range(n_qubits)

    def circuit(self, inverse: bool = False) -> cirq.Circuit:
        """Get QFT circuit."""
        if inverse:
            return inverse_qft_circuit(list(self.qubits))
        return qft_circuit(list(self.qubits))

    def gate_count(self) -> dict:
        """
        Count gates in the QFT circuit.

        Returns:
            Dictionary with gate counts
        """
        circuit = self.circuit()
        counts = {"H": 0, "CZ": 0, "SWAP": 0, "total": 0}

        for op in circuit.all_operations():
            gate_name = type(op.gate).__name__
            if "H" in str(op.gate):
                counts["H"] += 1
            elif "CZ" in str(op.gate):
                counts["CZ"] += 1
            elif "SWAP" in str(op.gate):
                counts["SWAP"] += 1
            counts["total"] += 1

        return counts

    def depth(self) -> int:
        """Get circuit depth."""
        return len(self.circuit())

    def verify(self, simulator: cirq.Simulator = None) -> bool:
        """
        Verify QFT implementation by checking QFT†·QFT = I.

        Args:
            simulator: Cirq simulator (created if None)

        Returns:
            True if verification passes
        """
        if simulator is None:
            simulator = cirq.Simulator()

        # Create QFT followed by inverse QFT
        circuit = cirq.Circuit()
        circuit.append(qft_circuit(list(self.qubits)))
        circuit.append(inverse_qft_circuit(list(self.qubits)))

        # Should return to initial state |0...0⟩
        circuit.append(cirq.measure(*self.qubits, key='result'))

        result = simulator.run(circuit, repetitions=100)
        measurements = result.measurements['result']

        # All measurements should be 0
        return np.all(measurements == 0)

    def __repr__(self) -> str:
        return f"QuantumFourierTransform(n_qubits={self.n_qubits})"


# Demonstration function
def demonstrate_qft():
    """Demonstrate QFT circuit construction and properties."""
    print("Quantum Fourier Transform Demonstration")
    print("=" * 50)

    for n in [2, 3, 4]:
        qft = QuantumFourierTransform(n)
        circuit = qft.circuit()

        print(f"\nQFT on {n} qubits:")
        print(f"  Gate count: {qft.gate_count()}")
        print(f"  Circuit depth: {qft.depth()}")
        print(f"  Verification (QFT†·QFT = I): {qft.verify()}")
        print(f"\nCircuit:\n{circuit}")


if __name__ == "__main__":
    demonstrate_qft()
