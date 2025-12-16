"""
Shor's Algorithm Implementation using Google Cirq

This module implements Shor's algorithm for integer factorization using
actual quantum circuits simulated with Cirq.

The algorithm consists of:
1. Classical preprocessing (check trivial cases, choose random a)
2. Quantum period finding (QFT-based)
3. Classical postprocessing (continued fractions, extract factors)

Key Quantum Components:
- Quantum Fourier Transform (QFT)
- Controlled modular exponentiation
- Measurement and period extraction
"""

import cirq
import numpy as np
from typing import List, Tuple, Optional
from fractions import Fraction
import random
import math


def qft_circuit(qubits: List[cirq.Qid], inverse: bool = False) -> cirq.Circuit:
    """
    Create Quantum Fourier Transform circuit.

    The QFT transforms computational basis states to frequency basis,
    allowing period extraction through measurement.

    QFT|x⟩ = (1/√N) Σ_k e^(2πixk/N)|k⟩

    Args:
        qubits: List of qubits to apply QFT to
        inverse: If True, create inverse QFT (for uncomputing)

    Returns:
        Cirq circuit implementing QFT
    """
    n = len(qubits)
    circuit = cirq.Circuit()

    if inverse:
        # Inverse QFT: reverse order of operations
        qubits = qubits[::-1]

    for i in range(n):
        # Hadamard on qubit i
        circuit.append(cirq.H(qubits[i]))

        # Controlled rotations
        for j in range(i + 1, n):
            # Controlled phase rotation by 2π/2^(j-i+1)
            angle = np.pi / (2 ** (j - i))
            if inverse:
                angle = -angle
            circuit.append(cirq.CZPowGate(exponent=angle / np.pi)(qubits[j], qubits[i]))

    # Swap qubits to reverse order (standard QFT convention)
    for i in range(n // 2):
        circuit.append(cirq.SWAP(qubits[i], qubits[n - 1 - i]))

    return circuit


def controlled_modular_multiplication(
    control: cirq.Qid,
    target_qubits: List[cirq.Qid],
    a: int,
    N: int
) -> cirq.Circuit:
    """
    Controlled modular multiplication: |x⟩ → |ax mod N⟩ if control is |1⟩

    For educational purposes, this uses a simplified approach suitable
    for small N. A full implementation would use reversible arithmetic.

    Note: For production use, this would need quantum arithmetic circuits
    (adders, multipliers) which grow as O(n²) gates for n-bit numbers.
    """
    n = len(target_qubits)
    circuit = cirq.Circuit()

    # For small N, we can use a lookup-table approach
    # Build the permutation matrix for multiplication by a mod N
    if N <= 2 ** n:
        # Create controlled permutation
        # This is a simplified approach for demonstration
        for i in range(n):
            # Apply controlled operations based on a's binary representation
            # This is a simplified model - real impl uses quantum arithmetic
            if (a >> i) & 1:
                for j in range(i + 1, n):
                    circuit.append(cirq.CCNOT(control, target_qubits[i], target_qubits[j]))

    return circuit


def modular_exponentiation_circuit(
    control_qubits: List[cirq.Qid],
    work_qubits: List[cirq.Qid],
    a: int,
    N: int
) -> cirq.Circuit:
    """
    Quantum modular exponentiation: computes a^x mod N in superposition.

    Given control register in superposition |x⟩ and work register |1⟩,
    produces |x⟩|a^x mod N⟩.

    This is the core of Shor's algorithm - computing f(x) = a^x mod N
    for all x simultaneously using quantum parallelism.

    Args:
        control_qubits: Qubits encoding the exponent x
        work_qubits: Qubits to hold the result a^x mod N
        a: Base for exponentiation
        N: Modulus

    Returns:
        Circuit implementing controlled modular exponentiation
    """
    circuit = cirq.Circuit()
    n_control = len(control_qubits)

    # Initialize work register to |1⟩
    circuit.append(cirq.X(work_qubits[0]))

    # For each control qubit i, apply controlled multiplication by a^(2^i) mod N
    # If control qubit i is |1⟩, multiply work register by a^(2^i)
    for i, control in enumerate(control_qubits):
        # Compute a^(2^i) mod N
        power = pow(a, 2 ** i, N)

        # Apply controlled multiplication by 'power'
        # Simplified: use controlled swap network for small N
        circuit.append(
            controlled_modular_mult_unitary(control, work_qubits, power, N)
        )

    return circuit


def controlled_modular_mult_unitary(
    control: cirq.Qid,
    target_qubits: List[cirq.Qid],
    multiplier: int,
    N: int
) -> cirq.Operation:
    """
    Create a controlled unitary that multiplies by 'multiplier' mod N.

    For small N, we construct the explicit unitary matrix.
    """
    n = len(target_qubits)
    dim = 2 ** n

    # Build permutation matrix for multiplication by 'multiplier' mod N
    matrix = np.zeros((dim, dim), dtype=complex)

    for x in range(dim):
        if x < N:
            # Compute (x * multiplier) mod N
            y = (x * multiplier) % N
            matrix[y, x] = 1.0
        else:
            # Values >= N are unchanged (shouldn't occur in proper use)
            matrix[x, x] = 1.0

    # Create controlled version
    controlled_matrix = np.eye(2 * dim, dtype=complex)
    controlled_matrix[dim:, dim:] = matrix

    # Return as a matrix gate
    all_qubits = [control] + list(target_qubits)
    return cirq.MatrixGate(controlled_matrix).on(*all_qubits)


class ShorsAlgorithmCircuit:
    """
    Shor's Algorithm implementation using Cirq quantum circuits.

    This class implements the quantum period-finding subroutine that
    is the heart of Shor's factoring algorithm.
    """

    def __init__(self, N: int, a: int = None, n_count_qubits: int = None):
        """
        Initialize Shor's algorithm for factoring N.

        Args:
            N: Number to factor
            a: Base for modular exponentiation (random if None)
            n_count_qubits: Number of counting qubits (auto if None)
        """
        self.N = N
        self.n_bits = N.bit_length()

        # Number of qubits for the counting register
        # Need 2n bits for precision in period finding
        self.n_count = n_count_qubits or 2 * self.n_bits

        # Number of qubits for work register (holds a^x mod N)
        self.n_work = self.n_bits

        # Choose random a coprime to N
        if a is None:
            while True:
                a = random.randint(2, N - 1)
                if math.gcd(a, N) == 1:
                    break
        self.a = a

        # Create qubits
        self.count_qubits = cirq.LineQubit.range(self.n_count)
        self.work_qubits = cirq.LineQubit.range(self.n_count, self.n_count + self.n_work)

        self.circuit = None
        self.simulator = cirq.Simulator()

    def build_circuit(self) -> cirq.Circuit:
        """
        Build the complete Shor's algorithm quantum circuit.

        The circuit structure:
        1. Initialize counting register to superposition (Hadamards)
        2. Initialize work register to |1⟩
        3. Apply controlled modular exponentiation
        4. Apply inverse QFT to counting register
        5. Measure counting register
        """
        circuit = cirq.Circuit()

        # Step 1: Put counting qubits in superposition
        circuit.append(cirq.H.on_each(*self.count_qubits))

        # Step 2: Initialize work register to |1⟩
        circuit.append(cirq.X(self.work_qubits[0]))

        # Step 3: Controlled modular exponentiation
        # |x⟩|1⟩ → |x⟩|a^x mod N⟩
        for i, control in enumerate(self.count_qubits):
            power = pow(self.a, 2 ** i, self.N)
            if power != 1:  # Skip identity operations
                circuit.append(
                    self._controlled_multiply(control, power)
                )

        # Step 4: Inverse QFT on counting register
        circuit.append(qft_circuit(list(self.count_qubits), inverse=True))

        # Step 5: Measure counting register
        circuit.append(cirq.measure(*self.count_qubits, key='result'))

        self.circuit = circuit
        return circuit

    def _controlled_multiply(self, control: cirq.Qid, multiplier: int) -> cirq.Operation:
        """Create controlled multiplication operation for small N."""
        dim = 2 ** self.n_work

        # Build unitary for multiplication by 'multiplier' mod N
        U = np.zeros((dim, dim), dtype=complex)
        for x in range(dim):
            if x < self.N and x > 0:
                y = (x * multiplier) % self.N
                if y == 0:
                    y = self.N  # Handle wrap-around
                U[y, x] = 1.0
            elif x == 0:
                U[0, 0] = 1.0
            else:
                U[x, x] = 1.0

        # Create controlled version (2x size)
        controlled_dim = 2 * dim
        CU = np.eye(controlled_dim, dtype=complex)
        CU[dim:, dim:] = U

        all_qubits = [control] + list(self.work_qubits)
        return cirq.MatrixGate(CU, name=f'×{multiplier}').on(*all_qubits)

    def run(self, repetitions: int = 100) -> List[int]:
        """
        Run the quantum circuit and return measurement results.

        Args:
            repetitions: Number of times to run the circuit

        Returns:
            List of measured values from counting register
        """
        if self.circuit is None:
            self.build_circuit()

        result = self.simulator.run(self.circuit, repetitions=repetitions)
        measurements = result.measurements['result']

        # Convert binary arrays to integers
        values = []
        for row in measurements:
            val = sum(bit << i for i, bit in enumerate(row))
            values.append(val)

        return values

    def extract_period(self, measurements: List[int]) -> Optional[int]:
        """
        Extract the period r from quantum measurements using continued fractions.

        The QFT gives us s/r where s is random. Using continued fractions,
        we can extract r from multiple measurements.

        Args:
            measurements: List of measurement outcomes

        Returns:
            Estimated period r, or None if extraction fails
        """
        Q = 2 ** self.n_count  # Total number of possible outcomes

        candidates = set()

        for m in measurements:
            if m == 0:
                continue

            # The measurement gives us approximately s*Q/r for some s
            # Use continued fraction expansion to find r
            phase = m / Q

            # Get convergents of the continued fraction
            frac = Fraction(phase).limit_denominator(self.N)

            r_candidate = frac.denominator

            # Verify: check if a^r ≡ 1 (mod N)
            if r_candidate > 0 and pow(self.a, r_candidate, self.N) == 1:
                candidates.add(r_candidate)

        # Return the smallest valid period found
        valid_periods = [r for r in candidates if r > 0 and pow(self.a, r, self.N) == 1]

        if valid_periods:
            return min(valid_periods)
        return None

    def find_factors(self, verbose: bool = True) -> Optional[Tuple[int, int]]:
        """
        Run the complete Shor's algorithm to find factors of N.

        Args:
            verbose: Print progress information

        Returns:
            Tuple of factors (p, q), or None if factoring fails
        """
        if verbose:
            print(f"\n{'='*60}")
            print(f"SHOR'S ALGORITHM (Cirq Implementation)")
            print(f"{'='*60}")
            print(f"Target: N = {self.N}")
            print(f"Chosen: a = {self.a}")
            print(f"Qubits: {self.n_count} counting + {self.n_work} work = {self.n_count + self.n_work} total")

        # Check if a shares a factor with N (lucky case)
        g = math.gcd(self.a, self.N)
        if g > 1:
            if verbose:
                print(f"\n[Lucky!] gcd({self.a}, {self.N}) = {g}")
            return (g, self.N // g)

        # Build and run quantum circuit
        if verbose:
            print(f"\n[Quantum] Building circuit...")

        self.build_circuit()

        if verbose:
            print(f"[Quantum] Circuit depth: {len(self.circuit)}")
            print(f"[Quantum] Running {100} shots...")

        measurements = self.run(repetitions=100)

        if verbose:
            # Show measurement distribution
            from collections import Counter
            counts = Counter(measurements)
            print(f"[Quantum] Top measurements:")
            for val, count in counts.most_common(5):
                phase = val / (2 ** self.n_count)
                print(f"          {val:4d} (phase ≈ {phase:.4f}) : {count} times")

        # Extract period from measurements
        if verbose:
            print(f"\n[Classical] Extracting period using continued fractions...")

        r = self.extract_period(measurements)

        if r is None:
            if verbose:
                print(f"[Failed] Could not determine period")
            return None

        if verbose:
            print(f"[Classical] Found period r = {r}")
            print(f"[Classical] Verification: {self.a}^{r} mod {self.N} = {pow(self.a, r, self.N)}")

        # Use period to find factors
        if r % 2 != 0:
            if verbose:
                print(f"[Failed] Period is odd, cannot extract factors")
            return None

        # Compute a^(r/2) mod N
        x = pow(self.a, r // 2, self.N)

        if x == self.N - 1:
            if verbose:
                print(f"[Failed] a^(r/2) ≡ -1 (mod N), cannot extract factors")
            return None

        # Compute factors
        p = math.gcd(x - 1, self.N)
        q = math.gcd(x + 1, self.N)

        if verbose:
            print(f"\n[Success] Computing factors:")
            print(f"          a^(r/2) mod N = {x}")
            print(f"          gcd({x}-1, {self.N}) = {p}")
            print(f"          gcd({x}+1, {self.N}) = {q}")

        if p > 1 and p < self.N:
            return (p, self.N // p)
        if q > 1 and q < self.N:
            return (q, self.N // q)

        return None


def shors_factor_cirq(N: int, verbose: bool = True) -> Optional[Tuple[int, int]]:
    """
    Factor N using Shor's algorithm with Cirq quantum simulation.

    Args:
        N: Number to factor (should be product of two primes)
        verbose: Print progress

    Returns:
        Tuple of factors (p, q) or None if failed
    """
    # Trivial checks
    if N % 2 == 0:
        return (2, N // 2)

    # Check if N is a prime power
    for k in range(2, int(np.log2(N)) + 1):
        root = int(round(N ** (1/k)))
        for candidate in [root - 1, root, root + 1]:
            if candidate > 1 and candidate ** k == N:
                return (candidate, N // candidate)

    # Run Shor's algorithm with different random a values
    max_attempts = 5
    for attempt in range(max_attempts):
        if verbose and attempt > 0:
            print(f"\n[Retry] Attempt {attempt + 1}/{max_attempts}")

        shor = ShorsAlgorithmCircuit(N)
        result = shor.find_factors(verbose=verbose)

        if result:
            return result

    return None


def demonstrate_shors_cirq():
    """
    Demonstrate Shor's algorithm using Cirq quantum circuits.
    """
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║        SHOR'S ALGORITHM - QUANTUM CIRCUIT IMPLEMENTATION          ║
    ║                                                                   ║
    ║  Using Google Cirq to simulate quantum period finding             ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Factor small numbers for demonstration
    test_cases = [15, 21, 35]

    for N in test_cases:
        print(f"\n{'='*60}")
        print(f"FACTORING N = {N}")
        print(f"{'='*60}")

        result = shors_factor_cirq(N, verbose=True)

        if result:
            p, q = result
            print(f"\n✓ SUCCESS: {N} = {p} × {q}")
        else:
            print(f"\n✗ FAILED to factor {N}")

        input("\nPress Enter to continue...")

    print("\n" + "="*60)
    print("DEMONSTRATION COMPLETE")
    print("="*60)
    print("""
    Key Observations:
    1. The quantum circuit puts counting qubits in superposition
    2. Modular exponentiation computes a^x mod N for all x simultaneously
    3. The QFT extracts periodicity from the quantum state
    4. Classical post-processing uses continued fractions
    5. The period r reveals factors via gcd(a^(r/2) ± 1, N)

    Circuit Complexity:
    - Qubits needed: O(n) where n = log(N)
    - Gates needed: O(n³) for modular exponentiation
    - This makes factoring tractable for quantum computers

    Real-world implications:
    - Current quantum computers: ~1000 noisy qubits
    - To break RSA-2048: ~4000 logical qubits needed
    - Timeline: Estimated 10-20 years for cryptographic threat
    """)


if __name__ == "__main__":
    demonstrate_shors_cirq()
