"""
Shor's Algorithm - Core Implementation

This module demonstrates how Shor's algorithm works to:
1. Factor large integers (breaks RSA)
2. Solve discrete logarithms (breaks ECDSA/DH)

Note: This is a classical simulation for educational purposes.
A real quantum computer would use quantum Fourier transform for
exponential speedup in the order-finding step.

Algorithm Overview:
==================
Shor's algorithm reduces factoring to ORDER FINDING:
- Given N = p * q, find r such that a^r ≡ 1 (mod N)
- Classical: O(exp(n^(1/3))) - exponential time
- Quantum: O(n^3) - polynomial time using QFT

The quantum advantage comes from quantum parallelism:
- Superposition allows testing all values simultaneously
- Quantum Fourier Transform extracts the period efficiently
"""

import random
import math
from typing import Tuple, Optional, List
from fractions import Fraction


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation: base^exp mod mod."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def classical_order_finding(a: int, N: int, max_iterations: int = 1000000) -> Optional[int]:
    """
    Classical order finding - O(N) time complexity.

    Find the smallest r such that a^r ≡ 1 (mod N)

    This is the BOTTLENECK that Shor's algorithm solves with quantum computing.
    Classical computers must check each value sequentially.
    Quantum computers use superposition to check all values at once.

    Args:
        a: Base value (must be coprime to N)
        N: Modulus
        max_iterations: Limit for demonstration

    Returns:
        Order r, or None if not found within limit
    """
    if gcd(a, N) != 1:
        return None  # a must be coprime to N

    value = a
    for r in range(1, max_iterations + 1):
        if value == 1:
            return r
        value = (value * a) % N

    return None  # Order too large for classical search


def quantum_order_finding_simulation(a: int, N: int) -> int:
    """
    Simulates quantum order finding (the key quantum step in Shor's algorithm).

    In a real quantum computer, this would:
    1. Create superposition of all possible exponents: |0⟩ + |1⟩ + |2⟩ + ... + |2^n-1⟩
    2. Compute a^x mod N in superposition (quantum parallelism)
    3. Apply Quantum Fourier Transform to extract period
    4. Measure to get period r with high probability

    The quantum speedup comes from:
    - Testing O(2^n) values simultaneously via superposition
    - QFT efficiently finds periodicity in O(n^2) gates

    This simulation uses classical computation but demonstrates the concept.

    Args:
        a: Base value
        N: Modulus to factor

    Returns:
        The order r such that a^r ≡ 1 (mod N)
    """
    # In reality, quantum computer would do this in polynomial time
    # We simulate the result classically for small numbers

    # Phase 1: Would create quantum superposition |x⟩|a^x mod N⟩
    # Phase 2: Would apply QFT to first register
    # Phase 3: Would measure to get s/r where r is the period

    # Classical fallback for simulation
    value = 1
    for r in range(1, N + 1):
        value = (value * a) % N
        if value == 1:
            return r

    return N  # Should not reach here for valid inputs


def continued_fraction_expansion(x: float, max_terms: int = 20) -> List[int]:
    """
    Compute continued fraction expansion of x.

    Used to extract period from quantum measurement results.
    The QFT gives us s/r; continued fractions help find r.
    """
    terms = []
    for _ in range(max_terms):
        term = int(x)
        terms.append(term)
        frac = x - term
        if frac < 1e-10:
            break
        x = 1.0 / frac
    return terms


def convergents(cf_terms: List[int]) -> List[Tuple[int, int]]:
    """
    Compute convergents from continued fraction terms.
    Returns list of (numerator, denominator) pairs.
    """
    if not cf_terms:
        return []

    result = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0

    for term in cf_terms:
        h_next = term * h_curr + h_prev
        k_next = term * k_curr + k_prev
        result.append((h_next, k_next))
        h_prev, h_curr = h_curr, h_next
        k_prev, k_curr = k_curr, k_next

    return result


def shors_factor(N: int, verbose: bool = False) -> Tuple[int, int]:
    """
    Shor's Algorithm for Integer Factorization.

    Given N = p * q, finds p and q.

    This is what breaks RSA:
    - RSA security relies on difficulty of factoring N = p * q
    - Classical: Takes O(exp(n^(1/3))) time - infeasible for large N
    - Quantum: Takes O(n^3) time - polynomial, feasible for any N

    Algorithm Steps:
    1. Check if N is even or a prime power (trivial cases)
    2. Pick random a < N
    3. Check if gcd(a, N) > 1 (lucky factor)
    4. Find order r of a mod N (QUANTUM STEP)
    5. If r is even and a^(r/2) ≢ -1 (mod N):
       - gcd(a^(r/2) - 1, N) and gcd(a^(r/2) + 1, N) give factors
    6. Repeat if needed

    Args:
        N: Number to factor (product of two primes)
        verbose: Print step-by-step progress

    Returns:
        Tuple of (p, q) factors
    """
    if verbose:
        print(f"\n{'='*60}")
        print(f"SHOR'S ALGORITHM: Factoring N = {N}")
        print(f"{'='*60}")

    # Step 1: Trivial checks
    if N % 2 == 0:
        if verbose:
            print(f"[Trivial] N is even, factor is 2")
        return (2, N // 2)

    # Check for prime power
    for k in range(2, int(math.log2(N)) + 1):
        root = int(round(N ** (1/k)))
        for candidate in [root - 1, root, root + 1]:
            if candidate > 1 and candidate ** k == N:
                if verbose:
                    print(f"[Trivial] N is {candidate}^{k}")
                return (candidate, N // candidate)

    # Step 2-6: Main algorithm loop
    max_attempts = 10
    for attempt in range(max_attempts):
        # Step 2: Pick random a
        a = random.randint(2, N - 1)
        if verbose:
            print(f"\n[Attempt {attempt + 1}] Chose random a = {a}")

        # Step 3: Check for lucky factor
        g = gcd(a, N)
        if g > 1:
            if verbose:
                print(f"[Lucky!] gcd({a}, {N}) = {g} is a factor!")
            return (g, N // g)

        # Step 4: QUANTUM STEP - Find order r
        if verbose:
            print(f"[Quantum] Finding order of {a} mod {N}...")
            print(f"          (On quantum computer: superposition + QFT)")

        r = quantum_order_finding_simulation(a, N)

        if verbose:
            print(f"[Quantum] Order r = {r}")
            print(f"          Meaning: {a}^{r} ≡ 1 (mod {N})")

        # Step 5: Check if r is useful
        if r % 2 != 0:
            if verbose:
                print(f"[Retry] Order r = {r} is odd, trying again...")
            continue

        half_power = mod_pow(a, r // 2, N)
        if half_power == N - 1:  # ≡ -1 (mod N)
            if verbose:
                print(f"[Retry] a^(r/2) ≡ -1 (mod N), trying again...")
            continue

        # Step 6: Extract factors
        factor1 = gcd(half_power - 1, N)
        factor2 = gcd(half_power + 1, N)

        if verbose:
            print(f"\n[Success!] Found factors using:")
            print(f"           a^(r/2) mod N = {half_power}")
            print(f"           gcd({half_power} - 1, {N}) = {factor1}")
            print(f"           gcd({half_power} + 1, {N}) = {factor2}")

        if factor1 > 1 and factor1 < N:
            return (factor1, N // factor1)
        if factor2 > 1 and factor2 < N:
            return (factor2, N // factor2)

    raise ValueError(f"Failed to factor {N} after {max_attempts} attempts")


def shors_discrete_log(g: int, h: int, p: int, verbose: bool = False) -> int:
    """
    Shor's Algorithm for Discrete Logarithm Problem.

    Given g, h, p where h = g^x mod p, finds x.

    This is what breaks ECDSA and Diffie-Hellman:
    - ECDSA security relies on difficulty of finding x from g^x
    - Classical: Takes O(sqrt(p)) time using baby-step giant-step
    - Quantum: Takes O((log p)^3) time - exponentially faster

    Algorithm Overview:
    1. Use quantum period finding on f(a,b) = g^a * h^b mod p
    2. Find period (r, s) where g^r * h^s ≡ 1 (mod p)
    3. This gives us: g^r ≡ g^(-sx) (mod p)
    4. Therefore: x ≡ -r/s (mod order of g)

    Args:
        g: Generator
        h: h = g^x mod p (we want to find x)
        p: Prime modulus
        verbose: Print progress

    Returns:
        x such that g^x ≡ h (mod p)
    """
    if verbose:
        print(f"\n{'='*60}")
        print(f"SHOR'S DISCRETE LOG: Finding x where {g}^x ≡ {h} (mod {p})")
        print(f"{'='*60}")

    # For demonstration, we use classical search for small numbers
    # Real quantum computer would use 2D quantum Fourier transform

    if verbose:
        print(f"\n[Quantum] Creating superposition over all (a,b) pairs...")
        print(f"[Quantum] Computing g^a * h^b mod p in superposition...")
        print(f"[Quantum] Applying 2D Quantum Fourier Transform...")

    # Classical simulation of the result
    order = p - 1  # For prime p, order of group is p-1

    # Find x by classical search (quantum would be exponentially faster)
    value = 1
    for x in range(order):
        if value == h:
            if verbose:
                print(f"\n[Success!] Found x = {x}")
                print(f"           Verification: {g}^{x} mod {p} = {mod_pow(g, x, p)} = {h}")
            return x
        value = (value * g) % p

    raise ValueError(f"Discrete log not found")


def demonstrate_quantum_speedup():
    """
    Demonstrate the computational complexity difference.

    Shows why quantum computers are a threat:
    - For n-bit numbers
    - Classical factoring: O(exp(n^(1/3) * (log n)^(2/3))) operations
    - Quantum factoring: O(n^3) operations

    Example for 2048-bit RSA:
    - Classical: ~10^30 operations (universe age in seconds: ~10^17)
    - Quantum: ~10^10 operations (seconds on quantum computer)
    """
    print("\n" + "="*70)
    print("QUANTUM vs CLASSICAL COMPLEXITY COMPARISON")
    print("="*70)

    bit_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]

    print(f"\n{'Bits':>6} | {'Classical Operations':>25} | {'Quantum Operations':>20}")
    print("-" * 60)

    for n in bit_sizes:
        # Classical: General Number Field Sieve complexity
        # O(exp(1.9 * n^(1/3) * (log n)^(2/3)))
        classical = math.exp(1.9 * (n ** (1/3)) * (math.log(n) ** (2/3)))

        # Quantum: Shor's algorithm O(n^3)
        quantum = n ** 3

        # Format large numbers
        if classical > 1e100:
            classical_str = f"10^{int(math.log10(classical))}"
        elif classical > 1e15:
            classical_str = f"{classical:.2e}"
        else:
            classical_str = f"{classical:,.0f}"

        quantum_str = f"{quantum:,}"

        print(f"{n:>6} | {classical_str:>25} | {quantum_str:>20}")

    print("\n" + "-" * 60)
    print("Note: 2048-bit RSA keys are standard today.")
    print("Classical attack: Would take longer than age of universe")
    print("Quantum attack: Would take hours to days on large quantum computer")
    print("="*70)
