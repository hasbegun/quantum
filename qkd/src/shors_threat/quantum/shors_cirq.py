"""
Shor's Algorithm - Complete Implementation using Google Cirq

This module provides a complete implementation of Shor's algorithm
for integer factorization using quantum circuits simulated with Cirq.

Shor's Algorithm Overview:
=========================
1. CLASSICAL: Check trivial cases (even, prime power)
2. CLASSICAL: Choose random a coprime to N
3. QUANTUM:   Find period r where a^r ≡ 1 (mod N)
4. CLASSICAL: Use r to compute factors via gcd

The quantum speedup is in step 3:
- Classical period finding: O(exp(n^(1/3))) - exponential
- Quantum period finding: O(n³) - polynomial

This exponential speedup is what makes Shor's algorithm a threat
to RSA and other cryptosystems based on factoring.

Usage:
    from shors_threat.quantum import ShorsAlgorithmCirq, shors_factor_cirq

    # High-level interface
    factors = shors_factor_cirq(15)  # Returns (3, 5)

    # Object-oriented interface
    shor = ShorsAlgorithmCirq(15)
    shor.run(verbose=True)
"""

import cirq
import numpy as np
from typing import Optional, Tuple, List
import math
import random

from .period_finding import QuantumPeriodFinding, period_to_factors


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def is_prime_power(n: int) -> Optional[Tuple[int, int]]:
    """
    Check if n is a prime power (p^k for prime p, k ≥ 2).

    Args:
        n: Number to check

    Returns:
        (p, k) if n = p^k, None otherwise
    """
    for k in range(2, int(np.log2(n)) + 1):
        root = int(round(n ** (1/k)))
        for candidate in [root - 1, root, root + 1]:
            if candidate > 1 and candidate ** k == n:
                return (candidate, k)
    return None


class ShorsAlgorithmCirq:
    """
    Shor's Algorithm implementation using Google Cirq.

    This class implements the complete algorithm for factoring integers,
    using quantum period finding as the core subroutine.

    Example:
        >>> shor = ShorsAlgorithmCirq(15)
        >>> factors = shor.run(verbose=True)
        >>> print(factors)  # (3, 5) or (5, 3)
    """

    def __init__(self, N: int, a: int = None):
        """
        Initialize Shor's algorithm for factoring N.

        Args:
            N: The integer to factor (must be composite, not prime power)
            a: Base for modular exponentiation (random if None)
        """
        self.N = N
        self.n_bits = N.bit_length()

        # Validate N
        if N < 4:
            raise ValueError("N must be >= 4")
        if N % 2 == 0:
            raise ValueError("N must be odd (even numbers are trivial)")

        # Check for prime power
        pp = is_prime_power(N)
        if pp:
            raise ValueError(f"N = {pp[0]}^{pp[1]} is a prime power")

        # Choose or validate a
        if a is None:
            self.a = self._choose_random_a()
        else:
            if gcd(a, N) != 1:
                raise ValueError(f"a={a} must be coprime to N={N}")
            self.a = a

        self.period_finder = None
        self.measurements = None
        self.period = None
        self.factors = None

    def _choose_random_a(self) -> int:
        """Choose random a coprime to N."""
        while True:
            a = random.randint(2, self.N - 1)
            g = gcd(a, self.N)
            if g == 1:
                return a
            # Lucky case: found a factor!
            # Store it but still return a valid a
            if g > 1 and g < self.N:
                self._lucky_factor = g

    def run(
        self,
        max_attempts: int = 5,
        shots_per_attempt: int = 100,
        verbose: bool = False
    ) -> Optional[Tuple[int, int]]:
        """
        Run Shor's algorithm to factor N.

        Args:
            max_attempts: Maximum number of attempts with different a values
            shots_per_attempt: Number of quantum circuit runs per attempt
            verbose: Print detailed progress

        Returns:
            Tuple (p, q) where N = p * q, or None if factoring fails
        """
        if verbose:
            self._print_header()

        # Check for lucky factor from gcd
        if hasattr(self, '_lucky_factor'):
            g = self._lucky_factor
            if verbose:
                print(f"\n[Lucky!] gcd(a, N) = {g} is a factor!")
            return (g, self.N // g)

        for attempt in range(max_attempts):
            if attempt > 0:
                # Try new random a
                self.a = self._choose_random_a()
                if verbose:
                    print(f"\n{'─'*60}")
                    print(f"Attempt {attempt + 1}/{max_attempts}: trying a = {self.a}")

            # Check gcd again
            g = gcd(self.a, self.N)
            if g > 1:
                if verbose:
                    print(f"[Lucky!] gcd({self.a}, {self.N}) = {g}")
                return (g, self.N // g)

            # Quantum period finding
            if verbose:
                print(f"\n[Quantum] Period finding with a={self.a}, N={self.N}")

            self.period_finder = QuantumPeriodFinding(self.a, self.N)

            if verbose:
                stats = self.period_finder.circuit_stats()
                print(f"[Quantum] Circuit: {stats['total_qubits']} qubits, "
                      f"depth {stats['circuit_depth']}")
                print(f"[Quantum] Running {shots_per_attempt} shots...")

            # Find period
            self.period = self.period_finder.find_period(
                repetitions=shots_per_attempt,
                verbose=verbose
            )

            if self.period is None:
                if verbose:
                    print("[Failed] Could not determine period")
                continue

            if verbose:
                print(f"\n[Classical] Period r = {self.period}")
                print(f"[Classical] Verification: {self.a}^{self.period} mod {self.N} = "
                      f"{pow(self.a, self.period, self.N)}")

            # Extract factors from period
            self.factors = period_to_factors(self.a, self.period, self.N)

            if self.factors:
                if verbose:
                    p, q = self.factors
                    print(f"\n[Success!] {self.N} = {p} × {q}")
                return self.factors
            else:
                if verbose:
                    print("[Failed] Could not extract factors from period")
                    if self.period % 2 != 0:
                        print("         Reason: period is odd")
                    else:
                        x = pow(self.a, self.period // 2, self.N)
                        if x == self.N - 1:
                            print(f"         Reason: a^(r/2) ≡ -1 (mod N)")

        if verbose:
            print(f"\n[Failed] Could not factor {self.N} after {max_attempts} attempts")

        return None

    def _print_header(self):
        """Print algorithm header."""
        print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║              SHOR'S ALGORITHM (Cirq Implementation)               ║
╚═══════════════════════════════════════════════════════════════════╝

Target:     N = {self.N}
Bit size:   {self.n_bits} bits
Base:       a = {self.a}
""")

    def get_circuit(self) -> Optional[cirq.Circuit]:
        """Get the quantum circuit used for period finding."""
        if self.period_finder is None:
            self.period_finder = QuantumPeriodFinding(self.a, self.N)
        return self.period_finder.build_circuit()

    def circuit_diagram(self) -> str:
        """Get a string representation of the circuit."""
        circuit = self.get_circuit()
        return str(circuit)


def shors_factor_cirq(
    N: int,
    verbose: bool = True,
    max_attempts: int = 5
) -> Optional[Tuple[int, int]]:
    """
    Factor N using Shor's algorithm with Cirq quantum simulation.

    This is the main entry point for Shor's algorithm.

    Args:
        N: Number to factor (should be product of two primes)
        verbose: Print progress information
        max_attempts: Maximum factoring attempts

    Returns:
        Tuple (p, q) where N = p * q, or None if factoring fails

    Example:
        >>> shors_factor_cirq(15)
        (3, 5)

        >>> shors_factor_cirq(21)
        (3, 7)
    """
    # Handle trivial cases
    if N % 2 == 0:
        if verbose:
            print(f"[Trivial] {N} is even, factor is 2")
        return (2, N // 2)

    # Check prime power
    pp = is_prime_power(N)
    if pp:
        base, exp = pp
        if verbose:
            print(f"[Trivial] {N} = {base}^{exp}")
        return (base, N // base)

    # Run Shor's algorithm
    try:
        shor = ShorsAlgorithmCirq(N)
        return shor.run(max_attempts=max_attempts, verbose=verbose)
    except ValueError as e:
        if verbose:
            print(f"[Error] {e}")
        return None


def demonstrate_shors_cirq():
    """
    Demonstrate Shor's algorithm using Cirq quantum circuits.

    This function shows the algorithm factoring several small numbers,
    explaining each step of the process.
    """
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║        SHOR'S ALGORITHM DEMONSTRATION (Google Cirq)               ║
    ║                                                                   ║
    ║  Quantum Integer Factorization                                    ║
    ║  Breaking RSA by factoring N = p × q                              ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    print("""
    How Shor's Algorithm Works:
    ═══════════════════════════

    1. PROBLEM: Given N = p × q, find p and q

    2. REDUCTION: Factoring reduces to PERIOD FINDING
       - Choose random a < N
       - Find r such that a^r ≡ 1 (mod N)
       - Use r to compute factors: gcd(a^(r/2) ± 1, N)

    3. QUANTUM SPEEDUP:
       - Classical period finding: O(exp(n^(1/3))) - INFEASIBLE
       - Quantum period finding: O(n³) - EFFICIENT

    4. QUANTUM CIRCUIT:
       |0⟩──[H⊗n]──[Mod Exp]──[QFT†]──[Measure]
                      │
       |1⟩────────────┘

    """)

    input("Press Enter to see factorization examples...\n")

    # Factorization examples
    numbers_to_factor = [15, 21, 35]

    for N in numbers_to_factor:
        print(f"\n{'═'*60}")
        print(f"  FACTORING N = {N}")
        print(f"{'═'*60}")

        result = shors_factor_cirq(N, verbose=True)

        if result:
            p, q = result
            print(f"\n  ✓ SUCCESS: {N} = {p} × {q}")
            print(f"  Verification: {p} × {q} = {p * q}")
        else:
            print(f"\n  ✗ FAILED to factor {N}")

        input("\nPress Enter to continue...\n")

    # Summary
    print(f"""
{'═'*60}
                    SUMMARY
{'═'*60}

What we demonstrated:
1. Quantum circuits can find periods exponentially faster
2. Period finding breaks factoring problem
3. RSA relies on difficulty of factoring N = p × q
4. Quantum computers make this factoring efficient

Real-world implications:
- RSA-2048: Would need ~4000 logical qubits
- Current quantum computers: ~1000 noisy qubits
- Estimated timeline: 10-20 years for cryptographic threat

Recommendation:
Migrate to post-quantum cryptography:
- ML-KEM (key exchange) - FIPS 203
- ML-DSA (signatures) - FIPS 204
- SLH-DSA (signatures) - FIPS 205
""")


if __name__ == "__main__":
    demonstrate_shors_cirq()
