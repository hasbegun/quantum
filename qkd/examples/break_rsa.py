#!/usr/bin/env python3
"""
RSA Breaking Demonstration

This example shows how Shor's algorithm completely breaks RSA encryption.

What you'll see:
1. RSA key generation and normal encryption/decryption
2. Why classical computers can't break RSA
3. How quantum computers factor N to recover private key
4. Attacker decrypting secret messages

Run: python examples/break_rsa.py
"""

import sys
sys.path.insert(0, 'src')

from shors_threat import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    break_rsa_with_shors,
    classical_factor_attempt,
)
from shors_threat.shors_algorithm import demonstrate_quantum_speedup


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║           SHOR'S ALGORITHM vs RSA DEMONSTRATION                   ║
    ║                                                                   ║
    ║  This demo shows how quantum computers break RSA encryption       ║
    ║  by efficiently factoring large numbers                           ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Part 1: Show complexity difference
    print("\n[PART 1] WHY QUANTUM COMPUTERS ARE A THREAT")
    print("=" * 60)
    demonstrate_quantum_speedup()

    input("\nPress Enter to continue to RSA attack demonstration...")

    # Part 2: Full RSA attack
    print("\n[PART 2] BREAKING RSA ENCRYPTION")
    print("=" * 60)

    # Generate RSA keys
    print("\n--- Step 1: Generate RSA Keys ---")
    public_key, private_key = generate_rsa_keypair(bits=24)
    N, e = public_key
    _, d, p, q = private_key

    print(f"Generated {N.bit_length()}-bit RSA key")
    print(f"Public key: N = {N}, e = {e}")
    print(f"Private key: d = {d} (SECRET)")
    print(f"Factors: p = {p}, q = {q} (SECRET)")

    # Encrypt a message
    print("\n--- Step 2: Encrypt Secret Message ---")
    secret = 12345
    ciphertext = rsa_encrypt(secret, public_key)
    print(f"Secret message: {secret}")
    print(f"Ciphertext: {ciphertext}")
    print("(This ciphertext is transmitted over public network)")

    # Normal decryption
    print("\n--- Step 3: Normal Decryption (with private key) ---")
    decrypted = rsa_decrypt(ciphertext, private_key)
    print(f"Decrypted: {decrypted}")

    # Try classical attack
    print("\n--- Step 4: Classical Attack Attempt ---")
    classical_result = classical_factor_attempt(N, max_iterations=1000)
    if classical_result:
        print(f"Classical attack found factors: {classical_result}")
    else:
        print(f"Classical attack FAILED after 1000 iterations")
        print(f"Would need up to {int(N**0.5):,} iterations to guarantee success")

    # Quantum attack
    print("\n--- Step 5: QUANTUM ATTACK ---")
    d_recovered, p_recovered, q_recovered = break_rsa_with_shors(public_key, verbose=True)

    # Attacker decrypts
    print("\n--- Step 6: Attacker Decrypts Message ---")
    attacker_private_key = (N, d_recovered, p_recovered, q_recovered)
    stolen_secret = rsa_decrypt(ciphertext, attacker_private_key)
    print(f"Attacker recovered: {stolen_secret}")
    print(f"Original secret: {secret}")
    print(f"Attack successful: {stolen_secret == secret}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY: RSA IS COMPLETELY BROKEN BY QUANTUM COMPUTERS")
    print("=" * 60)
    print("""
    What we demonstrated:

    1. RSA relies on the difficulty of factoring N = p × q
    2. Classical computers cannot factor large N efficiently
    3. Shor's algorithm factors N in polynomial time
    4. With factors p, q, the private key is trivially computed
    5. Any encrypted message can be decrypted

    Real-world impact:
    - HTTPS/TLS using RSA key exchange
    - Email encryption (PGP/GPG)
    - Code signing certificates
    - VPN connections
    - Banking systems

    Mitigation: Use post-quantum cryptography (ML-KEM, ML-DSA)
    """)


if __name__ == "__main__":
    main()
