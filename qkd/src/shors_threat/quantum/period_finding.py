"""
Quantum Period Finding

The period finding subroutine is the quantum heart of Shor's algorithm.
Given a function f(x) = a^x mod N, it finds the period r such that
a^r ≡ 1 (mod N).

Classical complexity: O(exp(n^(1/3))) - exponential
Quantum complexity: O(n³) - polynomial

The Algorithm:
1. Create superposition: |0⟩ → Σ|x⟩
2. Compute f(x) in superposition: Σ|x⟩|0⟩ → Σ|x⟩|a^x mod N⟩
3. Apply inverse QFT to first register
4. Measure to get s/r (for random s)
5. Use continued fractions to extract r

The quantum advantage comes from:
- Quantum parallelism: compute f(x) for all x simultaneously
- QFT: efficiently extract periodicity from phases
- Interference: amplify correct periods
"""

import cirq
import numpy as np
from typing import List, Optional, Tuple
from fractions import Fraction
import math

from .qft import qft_circuit, inverse_qft_circuit
from .modular_arithmetic import modular_exponentiation_circuit


def extract_period_from_measurements(
    measurements: List[int],
    Q: int,
    N: int,
    a: int
) -> Optional[int]:
    """
    Extract period r from quantum measurements using continued fractions.

    The QFT measurement gives us s/r for random integer s.
    Using continued fractions, we can determine r from multiple
    measurements with high probability.

    Theory:
    - Measurement m ≈ s·Q/r for some s ∈ {0,1,...,r-1}
    - m/Q ≈ s/r
    - Continued fraction expansion of m/Q gives convergents
    - Denominator of convergent closest to m/Q is candidate for r

    Args:
        measurements: List of measurement outcomes
        Q: Size of counting register (2^n)
        N: The modulus we're factoring
        a: The base used in modular exponentiation

    Returns:
        Period r, or None if extraction fails
    """
    candidates = set()

    for m in measurements:
        if m == 0:
            continue

        # Phase estimate
        phase = m / Q

        # Use continued fraction to find r
        # The denominator should be the period (or a divisor of it)
        frac = Fraction(phase).limit_denominator(N)
        r_candidate = frac.denominator

        # Verify candidate
        if r_candidate > 0 and r_candidate < N:
            if pow(a, r_candidate, N) == 1:
                candidates.add(r_candidate)

            # Also try multiples (in case we got a divisor of r)
            for mult in [2, 3, 4, 5, 6]:
                r_mult = r_candidate * mult
                if r_mult < N and pow(a, r_mult, N) == 1:
                    candidates.add(r_mult)

    # Return smallest valid period
    valid = [r for r in candidates if pow(a, r, N) == 1]
    return min(valid) if valid else None


def continued_fraction_convergents(x: float, max_denom: int) -> List[Tuple[int, int]]:
    """
    Compute convergents of continued fraction expansion.

    Convergents are successive rational approximations that
    get progressively closer to x.

    Args:
        x: Number to expand
        max_denom: Maximum denominator to consider

    Returns:
        List of (numerator, denominator) pairs
    """
    convergents = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0

    remaining = x
    for _ in range(50):  # Max iterations
        a_n = int(remaining)

        # Update convergent
        h_next = a_n * h_curr + h_prev
        k_next = a_n * k_curr + k_prev

        if k_next > max_denom:
            break

        convergents.append((h_next, k_next))

        h_prev, h_curr = h_curr, h_next
        k_prev, k_curr = k_curr, k_next

        # Update remaining
        frac = remaining - a_n
        if abs(frac) < 1e-10:
            break
        remaining = 1.0 / frac

    return convergents


class QuantumPeriodFinding:
    """
    Quantum Period Finding implementation using Cirq.

    Finds the period r of f(x) = a^x mod N such that a^r ≡ 1 (mod N).
    """

    def __init__(
        self,
        a: int,
        N: int,
        n_count: int = None,
        n_work: int = None
    ):
        """
        Initialize period finding circuit.

        Args:
            a: Base for f(x) = a^x mod N
            N: Modulus
            n_count: Number of counting qubits (precision)
            n_work: Number of work qubits
        """
        self.a = a
        self.N = N
        self.n_bits = N.bit_length()

        # Counting register needs 2n bits for O(1/N) precision
        self.n_count = n_count or 2 * self.n_bits
        self.n_work = n_work or self.n_bits

        # Total register size
        self.Q = 2 ** self.n_count

        # Create qubits
        self.count_qubits = cirq.LineQubit.range(self.n_count)
        self.work_qubits = cirq.LineQubit.range(
            self.n_count, self.n_count + self.n_work
        )

        self.circuit = None
        self.simulator = cirq.Simulator()

    def build_circuit(self) -> cirq.Circuit:
        """
        Build the quantum period finding circuit.

        Circuit structure:
        1. Hadamard all counting qubits (create superposition)
        2. Modular exponentiation: |x⟩|1⟩ → |x⟩|a^x mod N⟩
        3. Inverse QFT on counting register
        4. Measure counting register

        Returns:
            The complete circuit
        """
        circuit = cirq.Circuit()

        # Step 1: Create superposition in counting register
        # |0...0⟩ → (1/√Q) Σ|x⟩
        circuit.append(cirq.H.on_each(*self.count_qubits))

        # Step 2: Modular exponentiation
        # |x⟩|0...0⟩ → |x⟩|a^x mod N⟩
        circuit.append(
            modular_exponentiation_circuit(
                list(self.count_qubits),
                list(self.work_qubits),
                self.a,
                self.N
            )
        )

        # Step 3: Inverse QFT on counting register
        # Transforms to frequency basis, revealing period
        circuit.append(inverse_qft_circuit(list(self.count_qubits)))

        # Step 4: Measure counting register
        circuit.append(cirq.measure(*self.count_qubits, key='phase'))

        self.circuit = circuit
        return circuit

    def run(self, repetitions: int = 100) -> List[int]:
        """
        Run the period finding circuit.

        Args:
            repetitions: Number of shots

        Returns:
            List of measurement outcomes
        """
        if self.circuit is None:
            self.build_circuit()

        result = self.simulator.run(self.circuit, repetitions=repetitions)
        measurements = result.measurements['phase']

        # Convert binary to integers
        values = []
        for row in measurements:
            val = sum(int(bit) << i for i, bit in enumerate(row))
            values.append(val)

        return values

    def find_period(self, repetitions: int = 100, verbose: bool = False) -> Optional[int]:
        """
        Find the period r such that a^r ≡ 1 (mod N).

        Args:
            repetitions: Number of circuit executions
            verbose: Print progress information

        Returns:
            Period r, or None if not found
        """
        if verbose:
            print(f"Period Finding: a={self.a}, N={self.N}")
            print(f"Qubits: {self.n_count} counting + {self.n_work} work")

        # Build and run circuit
        if verbose:
            print("Building circuit...")
        self.build_circuit()

        if verbose:
            print(f"Running {repetitions} shots...")
        measurements = self.run(repetitions)

        if verbose:
            from collections import Counter
            counts = Counter(measurements)
            print("Top measurement outcomes:")
            for val, count in counts.most_common(5):
                phase = val / self.Q
                print(f"  {val}: {count} times (phase ≈ {phase:.4f})")

        # Extract period
        if verbose:
            print("Extracting period using continued fractions...")

        r = extract_period_from_measurements(
            measurements, self.Q, self.N, self.a
        )

        if verbose:
            if r:
                print(f"Found period r = {r}")
                print(f"Verification: {self.a}^{r} mod {self.N} = {pow(self.a, r, self.N)}")
            else:
                print("Failed to extract period")

        return r

    def circuit_stats(self) -> dict:
        """Get circuit statistics."""
        if self.circuit is None:
            self.build_circuit()

        return {
            "n_count_qubits": self.n_count,
            "n_work_qubits": self.n_work,
            "total_qubits": self.n_count + self.n_work,
            "circuit_depth": len(self.circuit),
            "Q": self.Q,
        }


def verify_period(a: int, r: int, N: int) -> bool:
    """Check if r is a valid period for a mod N."""
    return r > 0 and pow(a, r, N) == 1


def period_to_factors(a: int, r: int, N: int) -> Optional[Tuple[int, int]]:
    """
    Use period r to find factors of N.

    If r is even and a^(r/2) ≢ -1 (mod N), then:
    - gcd(a^(r/2) - 1, N) is a factor
    - gcd(a^(r/2) + 1, N) is a factor

    Args:
        a: Base used in period finding
        r: Period found
        N: Number to factor

    Returns:
        Tuple of factors (p, q), or None if can't extract
    """
    if r % 2 != 0:
        return None  # Period is odd

    x = pow(a, r // 2, N)

    if x == N - 1:
        return None  # x ≡ -1 (mod N)

    p = math.gcd(x - 1, N)
    q = math.gcd(x + 1, N)

    if 1 < p < N:
        return (p, N // p)
    if 1 < q < N:
        return (q, N // q)

    return None


def demonstrate_period_finding():
    """Demonstrate quantum period finding."""
    print("Quantum Period Finding Demonstration")
    print("=" * 50)

    # Test cases
    test_cases = [
        (7, 15),   # Period of 7 mod 15 is 4
        (2, 15),   # Period of 2 mod 15 is 4
        (11, 21),  # Period of 11 mod 21 is 6
    ]

    for a, N in test_cases:
        print(f"\n{'─'*50}")
        print(f"Finding period of a={a} mod N={N}")
        print(f"{'─'*50}")

        # Classical computation of period (for verification)
        true_r = 1
        while pow(a, true_r, N) != 1:
            true_r += 1
        print(f"True period (computed classically): r = {true_r}")

        # Quantum period finding
        qpf = QuantumPeriodFinding(a, N)
        found_r = qpf.find_period(repetitions=50, verbose=True)

        if found_r:
            print(f"\nQuantum result: r = {found_r}")
            print(f"Match: {found_r == true_r or true_r % found_r == 0}")

            # Try to extract factors
            factors = period_to_factors(a, found_r, N)
            if factors:
                p, q = factors
                print(f"Factors of {N}: {p} × {q}")


if __name__ == "__main__":
    demonstrate_period_finding()
