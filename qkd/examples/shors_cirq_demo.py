#!/usr/bin/env python3
"""
Shor's Algorithm - Quantum Circuit Implementation Demo

This example demonstrates Shor's algorithm using actual quantum circuits
simulated with Google Cirq. Unlike the conceptual demo, this shows:

1. Real quantum circuit construction (QFT, modular exponentiation)
2. Quantum state evolution and measurement
3. Classical post-processing with continued fractions
4. Complete factorization workflow

Run: python examples/shors_cirq_demo.py
     or
     make demo-shors-cirq
"""

import sys
sys.path.insert(0, 'src')

import cirq
from shors_threat.quantum import (
    ShorsAlgorithmCirq,
    shors_factor_cirq,
    QuantumPeriodFinding,
    qft_circuit,
)


def demonstrate_qft():
    """Show Quantum Fourier Transform circuit."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              QUANTUM FOURIER TRANSFORM (QFT)                      ║
    ╚═══════════════════════════════════════════════════════════════════╝

    The QFT is the quantum analog of the discrete Fourier transform.
    It transforms computational basis to frequency basis:

        QFT|x⟩ = (1/√N) Σ_k e^(2πixk/N)|k⟩

    This is essential for extracting period information in Shor's algorithm.
    """)

    # Create 4-qubit QFT circuit
    qubits = cirq.LineQubit.range(4)
    circuit = qft_circuit(list(qubits))

    print("4-qubit QFT Circuit:")
    print("=" * 50)
    print(circuit)
    print()

    # Analyze circuit
    print("Circuit Analysis:")
    print(f"  - Number of qubits: {len(qubits)}")
    print(f"  - Circuit depth: {len(circuit)}")
    print(f"  - Gate count: {sum(1 for _ in circuit.all_operations())}")


def demonstrate_period_finding():
    """Show quantum period finding."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              QUANTUM PERIOD FINDING                               ║
    ╚═══════════════════════════════════════════════════════════════════╝

    Period finding is the quantum heart of Shor's algorithm.

    Given f(x) = a^x mod N, find the period r such that:
        a^r ≡ 1 (mod N)

    The quantum circuit:
    1. Creates superposition: |0⟩ → Σ|x⟩
    2. Computes f(x) in parallel: Σ|x⟩|0⟩ → Σ|x⟩|a^x mod N⟩
    3. Applies inverse QFT to extract periodicity
    4. Measures to get information about r
    """)

    # Example: find period of 7 mod 15
    a, N = 7, 15

    # Classical computation of true period
    true_r = 1
    while pow(a, true_r, N) != 1:
        true_r += 1

    print(f"Finding period of a={a} mod N={N}")
    print(f"True period (classical): r = {true_r}")
    print(f"Verification: {a}^{true_r} mod {N} = {pow(a, true_r, N)}")
    print()

    # Quantum period finding
    qpf = QuantumPeriodFinding(a, N)

    print("Quantum Circuit Statistics:")
    stats = qpf.circuit_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print()

    print("Running quantum circuit (50 shots)...")
    found_r = qpf.find_period(repetitions=50, verbose=True)

    if found_r:
        print(f"\nQuantum result: r = {found_r}")
        print(f"Matches classical: {found_r == true_r}")


def demonstrate_full_algorithm():
    """Demonstrate complete Shor's algorithm."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              SHOR'S ALGORITHM - COMPLETE DEMO                     ║
    ╚═══════════════════════════════════════════════════════════════════╝

    Shor's Algorithm factors integers in polynomial time:

    CLASSICAL: Factor N = p × q
        - Try each number up to √N
        - Complexity: O(exp(n^(1/3))) - EXPONENTIAL

    QUANTUM: Factor N = p × q
        1. Choose random a coprime to N
        2. Find period r where a^r ≡ 1 (mod N) [QUANTUM SPEEDUP]
        3. Compute factors: gcd(a^(r/2) ± 1, N)
        - Complexity: O(n³) - POLYNOMIAL

    This polynomial speedup is what breaks RSA encryption.
    """)

    # Factor several numbers
    numbers = [15, 21, 35]

    for N in numbers:
        print(f"\n{'═'*60}")
        print(f"  FACTORING N = {N}")
        print(f"{'═'*60}")

        # Show what factors we expect
        print(f"\nExpected factors:")
        for i in range(2, int(N**0.5) + 1):
            if N % i == 0:
                print(f"  {N} = {i} × {N//i}")
                break

        print("\nRunning Shor's algorithm with quantum circuits...")
        result = shors_factor_cirq(N, verbose=True, max_attempts=3)

        if result:
            p, q = result
            print(f"\n✓ SUCCESS: {N} = {p} × {q}")
        else:
            print(f"\n✗ Failed to factor {N}")

        input("\nPress Enter to continue...")


def demonstrate_circuit_visualization():
    """Show the actual quantum circuits."""
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║              QUANTUM CIRCUIT VISUALIZATION                        ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Create a small Shor's circuit
    shor = ShorsAlgorithmCirq(15, a=7)

    print("Shor's Algorithm Circuit for N=15, a=7:")
    print("=" * 50)

    circuit = shor.get_circuit()

    # Show first few moments of the circuit
    print("\nCircuit (first 10 moments):")
    for i, moment in enumerate(circuit[:10]):
        print(f"Moment {i}: {moment}")

    print(f"\n... ({len(circuit)} total moments)")

    print(f"""
Circuit Components:
1. Hadamard gates on counting qubits (create superposition)
2. Controlled modular multiplications (compute a^x mod N)
3. Inverse QFT (extract period information)
4. Measurement (collapse to classical result)
""")


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║         SHOR'S ALGORITHM - QUANTUM CIRCUIT DEMONSTRATION          ║
    ║                                                                   ║
    ║         Implemented with Google Cirq Quantum Framework            ║
    ╚═══════════════════════════════════════════════════════════════════╝

    This demonstration shows Shor's algorithm using real quantum circuits,
    simulated with Google Cirq. You'll see:

    1. Quantum Fourier Transform (QFT) circuits
    2. Quantum period finding
    3. Complete factorization algorithm
    4. Circuit visualization

    Unlike classical simulations, this uses actual quantum gates and
    measurements, showing how the algorithm would run on a real
    quantum computer.
    """)

    sections = [
        ("1. Quantum Fourier Transform", demonstrate_qft),
        ("2. Quantum Period Finding", demonstrate_period_finding),
        ("3. Full Shor's Algorithm", demonstrate_full_algorithm),
        ("4. Circuit Visualization", demonstrate_circuit_visualization),
    ]

    for name, func in sections:
        input(f"\nPress Enter to see: {name}...")
        print("\n" + "=" * 70 + "\n")
        func()

    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                    DEMONSTRATION COMPLETE                         ║
    ╚═══════════════════════════════════════════════════════════════════╝

    Key Takeaways:
    ══════════════

    1. QUANTUM PARALLELISM
       - Superposition allows computing f(x) for ALL x simultaneously
       - This is impossible classically

    2. QFT EXTRACTS PERIODICITY
       - Transforms amplitudes to frequency domain
       - Period information becomes measurable

    3. POLYNOMIAL vs EXPONENTIAL
       - Classical factoring: O(exp(n^(1/3)))
       - Quantum factoring: O(n³)
       - This is an EXPONENTIAL speedup

    4. IMPLICATIONS FOR CRYPTOGRAPHY
       - RSA-2048 is secure classically
       - RSA-2048 falls to ~4000 logical qubits
       - Migration to post-quantum crypto is essential

    Resources:
    ══════════
    - Google Cirq: https://quantumai.google/cirq
    - NIST Post-Quantum: https://csrc.nist.gov/projects/post-quantum-cryptography
    - Our post-quantum DSA implementation: ../dsa/
    """)


if __name__ == "__main__":
    main()
