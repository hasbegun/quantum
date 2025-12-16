#!/usr/bin/env python3
"""
ECDSA Breaking Demonstration

This example shows how Shor's algorithm completely breaks ECDSA signatures.

What you'll see:
1. ECDSA key generation and normal signing/verification
2. Why classical computers can't solve discrete log
3. How quantum computers extract private keys
4. Attacker forging signatures

This directly threatens:
- Bitcoin and all cryptocurrencies
- TLS/HTTPS certificates
- SSH authentication
- Code signing

Run: python examples/break_ecdsa.py
"""

import sys
sys.path.insert(0, 'src')

from shors_threat import (
    generate_ecdsa_keypair,
    ecdsa_sign,
    ecdsa_verify,
    break_ecdsa_with_shors,
    classical_discrete_log_attempt,
)
from shors_threat.ecdsa_attack import (
    DEMO_CURVE,
    SECP256K1_INFO,
    demonstrate_ecdsa_attack,
    cryptocurrency_threat_analysis,
)


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║          SHOR'S ALGORITHM vs ECDSA DEMONSTRATION                  ║
    ║                                                                   ║
    ║  This demo shows how quantum computers break ECDSA signatures     ║
    ║  by solving the discrete logarithm problem                        ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Part 1: Explain the problem
    print("\n[PART 1] THE DISCRETE LOGARITHM PROBLEM")
    print("=" * 60)
    print("""
    ECDSA Security Assumption:
    --------------------------
    Given a generator point G and public key P = k × G on an elliptic curve,
    find the private key k.

    This is called the Elliptic Curve Discrete Logarithm Problem (ECDLP).

    Why it's hard classically:
    - Must try each possible k value
    - For 256-bit curves, there are ~2^256 possibilities
    - Best classical algorithm (Pollard's rho) needs ~2^128 operations
    - Would take billions of years with all computers on Earth

    Why quantum computers break it:
    - Shor's algorithm uses quantum parallelism
    - Tests all k values simultaneously via superposition
    - Extracts the answer using Quantum Fourier Transform
    - Runs in O((log n)^3) time - polynomial, not exponential
    """)

    input("Press Enter to see ECDSA attack demonstration...")

    # Part 2: Full demonstration
    print("\n[PART 2] ECDSA ATTACK DEMONSTRATION")
    print("=" * 60)
    demonstrate_ecdsa_attack()

    input("\nPress Enter to see cryptocurrency threat analysis...")

    # Part 3: Crypto threat
    print("\n[PART 3] CRYPTOCURRENCY THREAT ANALYSIS")
    print("=" * 60)
    cryptocurrency_threat_analysis()

    # Part 4: Interactive demo
    input("\nPress Enter for interactive attack demo...")

    print("\n[PART 4] INTERACTIVE ATTACK")
    print("=" * 60)

    curve = DEMO_CURVE

    # Generate victim's keys
    print("\n--- Victim's Wallet ---")
    public_key, private_key = generate_ecdsa_keypair(curve)
    print(f"Public key (on blockchain): {public_key}")
    print(f"Private key (victim's secret): {private_key}")

    # Victim signs transaction
    print("\n--- Victim Signs Legitimate Transaction ---")
    message = b"Send 1 BTC to merchant"
    signature = ecdsa_sign(curve, message, private_key)
    print(f"Transaction: {message.decode()}")
    print(f"Signature: (r={signature[0]}, s={signature[1]})")

    valid = ecdsa_verify(curve, message, signature, public_key)
    print(f"Valid signature: {valid}")

    # Attacker extracts key
    print("\n--- QUANTUM ATTACKER ---")
    print("Attacker sees public key on blockchain...")
    print("Running Shor's algorithm...")

    stolen_key = break_ecdsa_with_shors(curve, public_key, verbose=False)
    print(f"\nAttacker extracted private key: {stolen_key}")
    print(f"Matches victim's key: {stolen_key == private_key}")

    # Attacker forges transaction
    print("\n--- Attacker Forges Transaction ---")
    forged_tx = b"Send 1000 BTC to attacker_wallet"
    forged_sig = ecdsa_sign(curve, forged_tx, stolen_key)
    print(f"Forged transaction: {forged_tx.decode()}")
    print(f"Forged signature: (r={forged_sig[0]}, s={forged_sig[1]})")

    forged_valid = ecdsa_verify(curve, forged_tx, forged_sig, public_key)
    print(f"Signature validates with victim's public key: {forged_valid}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY: ECDSA IS COMPLETELY BROKEN BY QUANTUM COMPUTERS")
    print("=" * 60)
    print("""
    What we demonstrated:

    1. ECDSA relies on difficulty of discrete logarithm (finding k from k×G)
    2. Public keys are exposed on blockchains and in certificates
    3. Shor's algorithm extracts private key from public key
    4. Attacker can forge any signature, steal any funds

    Affected systems:
    - Bitcoin (~$1 trillion market cap)
    - Ethereum and all EVM chains
    - All cryptocurrencies using ECDSA
    - TLS certificates (website identity)
    - SSH keys (server access)
    - Code signing (software trust)

    Timeline:
    - Current (2024): ~1000 qubits, no threat yet
    - 2030s: Early cryptographic attacks possible
    - 2040s: Full-scale attacks on 256-bit ECDSA

    Mitigation:
    - Migrate to post-quantum signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
    - Never reuse cryptocurrency addresses
    - Support quantum-resistant protocol upgrades
    """)


if __name__ == "__main__":
    main()
