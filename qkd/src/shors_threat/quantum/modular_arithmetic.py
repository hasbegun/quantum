"""
Quantum Modular Arithmetic Circuits

This module implements quantum circuits for modular arithmetic operations
required by Shor's algorithm:

1. Controlled Modular Multiplication: |x⟩ → |ax mod N⟩
2. Modular Exponentiation: |x⟩|1⟩ → |x⟩|a^x mod N⟩

These are the computationally intensive parts of Shor's algorithm.
The quantum speedup comes from computing a^x mod N for ALL values
of x simultaneously using quantum parallelism.

Implementation Notes:
- For small N, we use direct unitary matrices (lookup table approach)
- For large N, reversible arithmetic circuits would be needed
- Real implementations use techniques like:
  - Quantum adders (Draper, VBE, etc.)
  - Modular addition via controlled phase rotations
  - Montgomery multiplication for efficiency
"""

import cirq
import numpy as np
from typing import List, Tuple, Optional
import math


def gcd(a: int, b: int) -> int:
    """Greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, n: int) -> Optional[int]:
    """
    Compute modular multiplicative inverse of a mod n.

    Returns x such that (a * x) mod n = 1, or None if not exists.
    """
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1

    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        return None
    return (x % n + n) % n


class QuantumModularArithmetic:
    """
    Quantum circuits for modular arithmetic operations.

    This class provides methods to create quantum circuits that perform
    modular multiplication and exponentiation - the core of Shor's algorithm.
    """

    def __init__(self, N: int, n_qubits: int = None):
        """
        Initialize modular arithmetic circuits for modulus N.

        Args:
            N: The modulus for all operations
            n_qubits: Number of qubits (auto-calculated if None)
        """
        self.N = N
        self.n_qubits = n_qubits or N.bit_length()

    def multiplication_matrix(self, a: int) -> np.ndarray:
        """
        Create unitary matrix for multiplication by a mod N.

        For x < N: |x⟩ → |ax mod N⟩
        For x ≥ N: |x⟩ → |x⟩ (unchanged, shouldn't occur)

        Args:
            a: Multiplier (must be coprime to N)

        Returns:
            Unitary matrix implementing the multiplication
        """
        if gcd(a, self.N) != 1:
            raise ValueError(f"a={a} must be coprime to N={self.N}")

        dim = 2 ** self.n_qubits
        U = np.zeros((dim, dim), dtype=complex)

        for x in range(dim):
            if x < self.N:
                # Compute (a * x) mod N
                y = (a * x) % self.N
                U[y, x] = 1.0
            else:
                # Values >= N map to themselves
                U[x, x] = 1.0

        return U

    def inverse_multiplication_matrix(self, a: int) -> np.ndarray:
        """
        Create unitary matrix for multiplication by a^(-1) mod N.

        This is the inverse operation, needed for uncomputation.

        Args:
            a: Original multiplier

        Returns:
            Unitary matrix implementing inverse multiplication
        """
        a_inv = mod_inverse(a, self.N)
        if a_inv is None:
            raise ValueError(f"a={a} has no inverse mod N={self.N}")
        return self.multiplication_matrix(a_inv)

    def controlled_multiplication_gate(
        self,
        a: int,
        control: cirq.Qid,
        target_qubits: List[cirq.Qid]
    ) -> cirq.Operation:
        """
        Create controlled multiplication gate.

        When control is |1⟩: |x⟩ → |ax mod N⟩
        When control is |0⟩: |x⟩ → |x⟩

        Args:
            a: Multiplier
            control: Control qubit
            target_qubits: Target register qubits

        Returns:
            Cirq operation
        """
        # Get the multiplication matrix
        U = self.multiplication_matrix(a)

        # Create controlled version
        dim = U.shape[0]
        CU = np.eye(2 * dim, dtype=complex)
        CU[dim:, dim:] = U

        # Create gate
        all_qubits = [control] + list(target_qubits)
        gate = cirq.MatrixGate(CU, name=f'C-×{a}')
        return gate.on(*all_qubits)


def controlled_modular_multiplication(
    control: cirq.Qid,
    target_qubits: List[cirq.Qid],
    a: int,
    N: int
) -> cirq.Operation:
    """
    Create controlled modular multiplication operation.

    Implements: if control=1, then |x⟩ → |ax mod N⟩

    Args:
        control: Control qubit
        target_qubits: Target register
        a: Multiplier
        N: Modulus

    Returns:
        Cirq operation
    """
    qma = QuantumModularArithmetic(N, len(target_qubits))
    return qma.controlled_multiplication_gate(a, control, target_qubits)


def modular_exponentiation_circuit(
    control_qubits: List[cirq.Qid],
    work_qubits: List[cirq.Qid],
    a: int,
    N: int
) -> cirq.Circuit:
    """
    Create quantum circuit for modular exponentiation.

    Computes: |x⟩|1⟩ → |x⟩|a^x mod N⟩

    This is the key quantum speedup in Shor's algorithm - computing
    a^x mod N for ALL x values simultaneously.

    The circuit uses repeated squaring:
    a^x = a^(x_0 * 2^0) * a^(x_1 * 2^1) * ... * a^(x_n * 2^n)

    Each control qubit i controls multiplication by a^(2^i) mod N.

    Args:
        control_qubits: Qubits encoding exponent x
        work_qubits: Register to hold result a^x mod N
        a: Base
        N: Modulus

    Returns:
        Cirq circuit
    """
    circuit = cirq.Circuit()
    n_work = len(work_qubits)

    # Initialize work register to |1⟩
    circuit.append(cirq.X(work_qubits[0]))

    # For each control qubit, apply controlled multiplication
    for i, control in enumerate(control_qubits):
        # Compute a^(2^i) mod N using repeated squaring
        power = pow(a, 2 ** i, N)

        if power == 1:
            # Multiplication by 1 is identity, skip
            continue

        # Create controlled multiplication by 'power'
        qma = QuantumModularArithmetic(N, n_work)
        op = qma.controlled_multiplication_gate(power, control, work_qubits)
        circuit.append(op)

    return circuit


class ModularExponentiationCircuit:
    """
    Builder class for modular exponentiation circuits.

    Provides detailed control over circuit construction and
    analysis utilities.
    """

    def __init__(self, a: int, N: int, n_control: int = None, n_work: int = None):
        """
        Initialize modular exponentiation circuit.

        Args:
            a: Base for exponentiation
            N: Modulus
            n_control: Number of control qubits (precision)
            n_work: Number of work qubits
        """
        self.a = a
        self.N = N
        self.n_bits = N.bit_length()
        self.n_control = n_control or 2 * self.n_bits
        self.n_work = n_work or self.n_bits

        # Verify a is coprime to N
        if gcd(a, N) != 1:
            raise ValueError(f"a={a} must be coprime to N={N}")

        # Create qubits
        self.control_qubits = cirq.LineQubit.range(self.n_control)
        self.work_qubits = cirq.LineQubit.range(
            self.n_control, self.n_control + self.n_work
        )

    def build(self) -> cirq.Circuit:
        """
        Build the modular exponentiation circuit.

        Returns:
            Complete circuit
        """
        return modular_exponentiation_circuit(
            list(self.control_qubits),
            list(self.work_qubits),
            self.a,
            self.N
        )

    def get_powers(self) -> List[int]:
        """
        Get the sequence of powers used in the circuit.

        Returns:
            List of a^(2^i) mod N values
        """
        return [pow(self.a, 2 ** i, self.N) for i in range(self.n_control)]

    def analyze(self) -> dict:
        """
        Analyze the circuit properties.

        Returns:
            Dictionary with analysis results
        """
        circuit = self.build()
        powers = self.get_powers()

        # Count non-trivial multiplications (power != 1)
        non_trivial = sum(1 for p in powers if p != 1)

        return {
            "a": self.a,
            "N": self.N,
            "n_control_qubits": self.n_control,
            "n_work_qubits": self.n_work,
            "total_qubits": self.n_control + self.n_work,
            "powers": powers,
            "non_trivial_multiplications": non_trivial,
            "circuit_depth": len(circuit),
        }

    def __repr__(self) -> str:
        return f"ModularExponentiationCircuit(a={self.a}, N={self.N})"


# Additional helper functions for building blocks

def quantum_adder_draper(
    qubits_a: List[cirq.Qid],
    qubits_b: List[cirq.Qid]
) -> cirq.Circuit:
    """
    Draper adder: Add register A to register B using QFT.

    |a⟩|b⟩ → |a⟩|a+b⟩

    This is one approach to quantum addition used in some
    modular arithmetic implementations.

    Args:
        qubits_a: First operand (unchanged)
        qubits_b: Second operand (stores result)

    Returns:
        Addition circuit
    """
    from .qft import qft_circuit, inverse_qft_circuit

    circuit = cirq.Circuit()
    n = len(qubits_b)

    # Apply QFT to register B
    circuit.append(qft_circuit(qubits_b))

    # Add phases based on register A
    for i, qa in enumerate(qubits_a):
        for j, qb in enumerate(qubits_b):
            if i + j < n:
                # Controlled phase rotation
                angle = np.pi / (2 ** (j - i)) if j >= i else np.pi * (2 ** (i - j))
                if j >= i:
                    circuit.append(
                        cirq.CZPowGate(exponent=1 / (2 ** (j - i + 1)))(qa, qb)
                    )

    # Apply inverse QFT
    circuit.append(inverse_qft_circuit(qubits_b))

    return circuit


def demonstrate_modular_arithmetic():
    """Demonstrate modular arithmetic circuits."""
    print("Quantum Modular Arithmetic Demonstration")
    print("=" * 50)

    N = 15  # Factor this
    a = 7   # Coprime to N

    print(f"\nModular arithmetic mod N={N} with base a={a}")

    # Create modular exponentiation circuit
    mod_exp = ModularExponentiationCircuit(a, N, n_control=8)

    print(f"\nCircuit analysis:")
    analysis = mod_exp.analyze()
    for key, value in analysis.items():
        if key != "powers":
            print(f"  {key}: {value}")

    print(f"\nPowers a^(2^i) mod N:")
    for i, p in enumerate(analysis["powers"]):
        print(f"  {a}^{2**i} mod {N} = {p}")

    # Build and show circuit
    circuit = mod_exp.build()
    print(f"\nCircuit (simplified view):")
    print(circuit[:5] if len(circuit) > 5 else circuit)


if __name__ == "__main__":
    demonstrate_modular_arithmetic()
