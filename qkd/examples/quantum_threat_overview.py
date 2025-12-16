#!/usr/bin/env python3
"""
Quantum Computing Threat Overview

This example provides a comprehensive overview of how quantum computers
threaten current cryptographic systems and what can be done about it.

Run: python examples/quantum_threat_overview.py
"""

import sys
sys.path.insert(0, 'src')

from shors_threat import (
    generate_rsa_keypair,
    break_rsa_with_shors,
    generate_ecdsa_keypair,
    break_ecdsa_with_shors,
)
from shors_threat.ecdsa_attack import DEMO_CURVE
from shors_threat.shors_algorithm import demonstrate_quantum_speedup
import time


def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║          ⚛️  QUANTUM COMPUTING CRYPTOGRAPHIC THREAT  ⚛️               ║
    ║                                                                       ║
    ║     How Shor's Algorithm Breaks RSA and ECDSA                         ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)


def explain_shors_algorithm():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    SHOR'S ALGORITHM EXPLAINED                       │
    └─────────────────────────────────────────────────────────────────────┘

    Published by Peter Shor in 1994, this algorithm efficiently solves
    two problems that are believed to be hard for classical computers:

    1. INTEGER FACTORIZATION
       ----------------------
       Given N = p × q (product of two primes), find p and q.

       Classical: Exponential time O(exp(n^(1/3)))
       Quantum:   Polynomial time O(n³)

       → Breaks RSA encryption

    2. DISCRETE LOGARITHM
       -------------------
       Given g and h = g^x, find x.

       Classical: Exponential time O(sqrt(n))
       Quantum:   Polynomial time O((log n)³)

       → Breaks ECDSA, Diffie-Hellman, ElGamal

    HOW IT WORKS (Simplified):
    ──────────────────────────
    ┌────────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │  Classical                    Quantum                              │
    │  ─────────                    ───────                              │
    │  Try k=1: compute f(1)        Create superposition: |1⟩+|2⟩+...   │
    │  Try k=2: compute f(2)        Compute f(k) for ALL k at once      │
    │  Try k=3: compute f(3)        Apply Quantum Fourier Transform     │
    │  ...                          Measure → get period/answer         │
    │  (one at a time)              (parallel computation)               │
    │                                                                    │
    └────────────────────────────────────────────────────────────────────┘

    The key insight: Quantum computers can test all possibilities
    simultaneously using superposition, then use interference to
    extract the answer with high probability.
    """)


def explain_rsa_vulnerability():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                      RSA VULNERABILITY                              │
    └─────────────────────────────────────────────────────────────────────┘

    RSA KEY GENERATION:
    ───────────────────
    1. Choose two large primes p, q (each ~1024 bits)
    2. Compute N = p × q (the modulus, ~2048 bits)
    3. Compute φ(N) = (p-1)(q-1)
    4. Choose public exponent e (usually 65537)
    5. Compute private exponent d = e⁻¹ mod φ(N)

    Public key:  (N, e)  ← Anyone can have this
    Private key: (N, d)  ← Must keep secret

    THE SECURITY RELIES ON:
    ───────────────────────
    Given only N (public), finding p and q should be infeasible.
    If you can factor N, you can compute φ(N), then d, then decrypt anything.

    QUANTUM ATTACK:
    ───────────────
    Shor's algorithm factors N efficiently:

    ┌──────────────────────────────────────────────────────────────────┐
    │ Public Key (N, e)                                                │
    │         │                                                        │
    │         ▼                                                        │
    │ ┌───────────────────┐                                            │
    │ │ Shor's Algorithm  │  ← Quantum computer                        │
    │ │ Factor N = p × q  │                                            │
    │ └───────────────────┘                                            │
    │         │                                                        │
    │         ▼                                                        │
    │ Compute φ(N) = (p-1)(q-1)                                        │
    │         │                                                        │
    │         ▼                                                        │
    │ Compute d = e⁻¹ mod φ(N)  ← Private key recovered!               │
    │         │                                                        │
    │         ▼                                                        │
    │ Decrypt any message, forge any signature                         │
    └──────────────────────────────────────────────────────────────────┘
    """)


def explain_ecdsa_vulnerability():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                     ECDSA VULNERABILITY                             │
    └─────────────────────────────────────────────────────────────────────┘

    ECDSA KEY GENERATION:
    ─────────────────────
    1. Choose elliptic curve with generator point G
    2. Choose random private key k (256-bit number)
    3. Compute public key P = k × G (point multiplication)

    Private key: k (scalar)  ← Must keep secret
    Public key:  P (point)   ← Published (on blockchain, in certificate)

    THE SECURITY RELIES ON:
    ───────────────────────
    Given G and P = k×G, finding k should be infeasible.
    This is the Elliptic Curve Discrete Logarithm Problem (ECDLP).

    QUANTUM ATTACK:
    ───────────────
    Shor's algorithm solves ECDLP efficiently:

    ┌──────────────────────────────────────────────────────────────────┐
    │ Public Key P (from blockchain)                                   │
    │ Generator G (curve parameter)                                    │
    │         │                                                        │
    │         ▼                                                        │
    │ ┌───────────────────┐                                            │
    │ │ Shor's Algorithm  │  ← Quantum computer                        │
    │ │ Find k: P = k×G   │                                            │
    │ └───────────────────┘                                            │
    │         │                                                        │
    │         ▼                                                        │
    │ Private key k recovered!                                         │
    │         │                                                        │
    │         ▼                                                        │
    │ Sign any transaction, steal any funds                            │
    └──────────────────────────────────────────────────────────────────┘

    CRYPTOCURRENCY IMPACT:
    ──────────────────────
    • Bitcoin: ~4 million BTC with exposed public keys (~$250B)
    • Ethereum: All addresses after first transaction
    • Every cryptocurrency using ECDSA is vulnerable
    """)


def run_attack_demo():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    LIVE ATTACK DEMONSTRATION                        │
    └─────────────────────────────────────────────────────────────────────┘
    """)

    # RSA Attack
    print("\n    [RSA ATTACK]")
    print("    " + "─" * 40)

    print("    Generating RSA-48 key pair...")
    rsa_pub, rsa_priv = generate_rsa_keypair(bits=24)
    N, e = rsa_pub
    _, d_real, p_real, q_real = rsa_priv

    print(f"    Public key N = {N} ({N.bit_length()} bits)")

    print("    Running Shor's algorithm to factor N...")
    start = time.time()
    d_recovered, p, q = break_rsa_with_shors(rsa_pub, verbose=False)
    elapsed = time.time() - start

    print(f"    ✓ Factored in {elapsed:.3f}s: N = {p} × {q}")
    print(f"    ✓ Recovered private key d = {d_recovered}")
    print(f"    ✓ Attack successful: {d_recovered == d_real}")

    # ECDSA Attack
    print("\n    [ECDSA ATTACK]")
    print("    " + "─" * 40)

    print("    Generating ECDSA key pair...")
    ec_pub, ec_priv = generate_ecdsa_keypair(DEMO_CURVE)

    print(f"    Public key P = {ec_pub}")

    print("    Running Shor's algorithm to solve discrete log...")
    start = time.time()
    k_recovered = break_ecdsa_with_shors(DEMO_CURVE, ec_pub, verbose=False)
    elapsed = time.time() - start

    print(f"    ✓ Solved in {elapsed:.3f}s: k = {k_recovered}")
    print(f"    ✓ Attack successful: {k_recovered == ec_priv}")


def show_complexity_comparison():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                   COMPLEXITY COMPARISON                             │
    └─────────────────────────────────────────────────────────────────────┘
    """)
    demonstrate_quantum_speedup()


def show_timeline():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    QUANTUM COMPUTING TIMELINE                       │
    └─────────────────────────────────────────────────────────────────────┘

    CURRENT STATE (2024):
    ─────────────────────
    • IBM Condor: 1,121 qubits
    • Google Sycamore: 70 qubits (high quality)
    • Error rates too high for cryptographic attacks
    • Estimated 4,000+ logical qubits needed to break RSA-2048

    ESTIMATED TIMELINE:
    ───────────────────
    ┌────────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │  2024      2028      2032      2036      2040      2044           │
    │    │         │         │         │         │         │            │
    │    ●─────────●─────────●─────────●─────────●─────────●            │
    │    │         │         │         │         │         │            │
    │    │         │         │         │         │         │            │
    │  1000     10,000   100,000    1M       10M     100M qubits        │
    │  qubits   qubits   qubits   qubits   qubits   qubits             │
    │    │         │         │         │         │         │            │
    │    │         │         ▼         │         │         │            │
    │    │         │    ┌─────────┐    │         │         │            │
    │    │         │    │ DANGER  │    │         │         │            │
    │    │         │    │  ZONE   │    │         │         │            │
    │    │         │    └─────────┘    │         │         │            │
    │    │         │                   │         │         │            │
    │  Current   Early              Full-scale attacks possible         │
    │  state    attacks              on RSA-2048 and ECDSA              │
    │                                                                    │
    └────────────────────────────────────────────────────────────────────┘

    HARVEST NOW, DECRYPT LATER:
    ───────────────────────────
    • Adversaries may store encrypted data today
    • Decrypt it once quantum computers arrive
    • Sensitive data with long lifetimes at risk NOW
    • Government secrets, medical records, financial data
    """)


def show_mitigations():
    print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    POST-QUANTUM SOLUTIONS                           │
    └─────────────────────────────────────────────────────────────────────┘

    NIST has standardized post-quantum algorithms (2024):

    ┌────────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │  DIGITAL SIGNATURES (replaces RSA, ECDSA):                         │
    │  ─────────────────────────────────────────                         │
    │  • ML-DSA (FIPS 204) - Lattice-based, fast                         │
    │  • SLH-DSA (FIPS 205) - Hash-based, conservative                   │
    │                                                                    │
    │  KEY ENCAPSULATION (replaces RSA, ECDH):                           │
    │  ────────────────────────────────────────                          │
    │  • ML-KEM (FIPS 203) - Lattice-based key exchange                  │
    │                                                                    │
    └────────────────────────────────────────────────────────────────────┘

    SECURITY COMPARISON:
    ────────────────────
    ┌─────────────────┬──────────────────┬──────────────────┐
    │ Algorithm       │ Classical Attack │ Quantum Attack   │
    ├─────────────────┼──────────────────┼──────────────────┤
    │ RSA-2048        │ Secure           │ BROKEN           │
    │ ECDSA-256       │ Secure           │ BROKEN           │
    │ ML-DSA-65       │ Secure           │ Secure           │
    │ SLH-DSA-256     │ Secure           │ Secure           │
    └─────────────────┴──────────────────┴──────────────────┘

    RECOMMENDED ACTIONS:
    ────────────────────
    For Developers:
    • Start testing post-quantum algorithms now
    • Use hybrid schemes during transition
    • Plan migration timeline

    For Organizations:
    • Inventory systems using RSA/ECDSA
    • Prioritize long-lived secrets
    • Budget for cryptographic migration

    For Individuals:
    • Don't reuse cryptocurrency addresses
    • Support post-quantum protocol upgrades
    • Move sensitive data to quantum-safe encryption
    """)


def main():
    print_banner()

    sections = [
        ("Shor's Algorithm Explanation", explain_shors_algorithm),
        ("RSA Vulnerability", explain_rsa_vulnerability),
        ("ECDSA Vulnerability", explain_ecdsa_vulnerability),
        ("Complexity Comparison", show_complexity_comparison),
        ("Live Attack Demo", run_attack_demo),
        ("Timeline", show_timeline),
        ("Post-Quantum Solutions", show_mitigations),
    ]

    for i, (name, func) in enumerate(sections):
        if i > 0:
            input(f"\nPress Enter to continue to: {name}...")
        func()

    print("\n" + "=" * 70)
    print("END OF DEMONSTRATION")
    print("=" * 70)
    print("""
    Key Takeaways:
    1. Shor's algorithm breaks RSA and ECDSA efficiently
    2. Current quantum computers are not yet powerful enough
    3. Cryptographically relevant quantum computers expected 2030s-2040s
    4. Post-quantum standards (ML-DSA, SLH-DSA) are ready NOW
    5. Migration should start immediately for sensitive systems

    Learn more:
    • NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
    • Our post-quantum DSA implementation: ../dsa/
    """)


if __name__ == "__main__":
    main()
