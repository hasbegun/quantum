"""
RSA Attack Demonstration using Shor's Algorithm

This module demonstrates how Shor's algorithm completely breaks RSA encryption.

RSA Security Assumption:
=======================
RSA relies on the computational hardness of factoring N = p * q
where p and q are large primes (typically 1024 bits each for 2048-bit RSA).

The Attack:
==========
1. Attacker intercepts public key (N, e)
2. Uses Shor's algorithm to factor N into p and q
3. Computes private key d from (p, q, e)
4. Can now decrypt any message or forge signatures

Why This Matters:
================
- RSA is used everywhere: HTTPS, email, code signing, VPNs
- Current RSA keys (2048-4096 bit) are secure against classical computers
- A sufficiently large quantum computer could break them in hours
- "Harvest now, decrypt later" - adversaries may store encrypted data today
"""

import random
import math
from typing import Tuple, Optional
from .shors_algorithm import shors_factor, gcd, mod_pow


def is_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime of specified bit length."""
    while True:
        # Generate odd number of correct bit length
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # Set high bit and low bit

        if is_prime(n):
            return n


def mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m


def generate_rsa_keypair(bits: int = 32) -> Tuple[Tuple[int, int], Tuple[int, int, int, int]]:
    """
    Generate RSA key pair.

    For demonstration, we use small primes. Real RSA uses 1024-2048 bit primes.

    Args:
        bits: Bit length of each prime (total key size is ~2*bits)

    Returns:
        public_key: (N, e)
        private_key: (N, d, p, q)
    """
    # Generate two distinct primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    N = p * q
    phi = (p - 1) * (q - 1)  # Euler's totient

    # Choose public exponent e
    e = 65537  # Standard choice
    if gcd(e, phi) != 1:
        # Find alternative e
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    # Compute private exponent d
    d = mod_inverse(e, phi)

    public_key = (N, e)
    private_key = (N, d, p, q)

    return public_key, private_key


def rsa_encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    RSA encryption: ciphertext = message^e mod N

    Args:
        message: Integer message (must be < N)
        public_key: (N, e)

    Returns:
        Encrypted ciphertext
    """
    N, e = public_key
    if message >= N:
        raise ValueError(f"Message {message} must be less than N={N}")
    return mod_pow(message, e, N)


def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int, int, int]) -> int:
    """
    RSA decryption: message = ciphertext^d mod N

    Args:
        ciphertext: Encrypted message
        private_key: (N, d, p, q)

    Returns:
        Decrypted message
    """
    N, d, _, _ = private_key
    return mod_pow(ciphertext, d, N)


def classical_factor_attempt(N: int, max_iterations: int = 100000) -> Optional[Tuple[int, int]]:
    """
    Attempt to factor N using classical trial division.

    This demonstrates why classical factoring is hard:
    - Must try potential factors up to sqrt(N)
    - For 2048-bit N, sqrt(N) has 1024 bits = ~10^308 possibilities
    - Even at 10^12 operations/second, would take 10^288 years

    Args:
        N: Number to factor
        max_iterations: Limit for demonstration

    Returns:
        Factors (p, q) if found, None otherwise
    """
    # Trial division up to sqrt(N)
    limit = min(int(math.sqrt(N)) + 1, max_iterations)

    for i in range(2, limit):
        if N % i == 0:
            return (i, N // i)

    return None  # Not found within limit


def recover_private_key(N: int, e: int, p: int, q: int) -> int:
    """
    Recover RSA private key from factors.

    Once we know p and q, computing d is trivial:
    1. Compute phi(N) = (p-1)(q-1)
    2. Compute d = e^(-1) mod phi(N)

    This is why factoring N breaks RSA completely.
    """
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return d


def break_rsa_with_shors(public_key: Tuple[int, int], verbose: bool = True) -> Tuple[int, int, int]:
    """
    Break RSA using Shor's algorithm.

    This is the complete attack:
    1. Extract N from public key
    2. Use Shor's algorithm to factor N
    3. Recover private key d
    4. Can now decrypt anything or forge signatures

    Args:
        public_key: RSA public key (N, e)
        verbose: Print attack progress

    Returns:
        (d, p, q) - Private exponent and factors
    """
    N, e = public_key

    if verbose:
        print("\n" + "="*70)
        print("RSA ATTACK USING SHOR'S ALGORITHM")
        print("="*70)
        print(f"\n[Target] Public key intercepted:")
        print(f"         N = {N}")
        print(f"         e = {e}")
        print(f"         Key size: {N.bit_length()} bits")

    # Step 1: Attempt classical factoring (will fail for large N)
    if verbose:
        print(f"\n[Classical Attack] Attempting trial division...")

    classical_result = classical_factor_attempt(N)

    if classical_result and verbose:
        print(f"[Classical] Found factors (small key): {classical_result}")
    elif verbose:
        print(f"[Classical] Failed - N is too large for trial division")
        print(f"            Would need ~{int(math.sqrt(N)):,} iterations")

    # Step 2: Use Shor's algorithm
    if verbose:
        print(f"\n[Quantum Attack] Deploying Shor's algorithm...")

    p, q = shors_factor(N, verbose=verbose)

    if verbose:
        print(f"\n[Quantum] Successfully factored N!")
        print(f"          p = {p}")
        print(f"          q = {q}")
        print(f"          p * q = {p * q} (verify: {p * q == N})")

    # Step 3: Recover private key
    d = recover_private_key(N, e, p, q)

    if verbose:
        print(f"\n[Key Recovery] Computing private exponent d...")
        print(f"               phi(N) = (p-1)(q-1) = {(p-1)*(q-1)}")
        print(f"               d = e^(-1) mod phi(N) = {d}")
        print(f"\n[ATTACK COMPLETE] RSA is broken!")
        print(f"                  Private key d = {d}")

    return (d, p, q)


def demonstrate_rsa_attack():
    """
    Full demonstration of RSA being broken by Shor's algorithm.

    Shows:
    1. Normal RSA usage (key generation, encryption, decryption)
    2. Quantum attack recovering private key
    3. Attacker decrypting messages
    """
    print("\n" + "="*70)
    print("COMPLETE RSA ATTACK DEMONSTRATION")
    print("="*70)

    # Step 1: Alice generates RSA keys
    print("\n[1] ALICE GENERATES RSA KEYS")
    print("-" * 40)

    public_key, private_key = generate_rsa_keypair(bits=20)
    N, e = public_key
    _, d_real, p_real, q_real = private_key

    print(f"    Public key (shared openly):")
    print(f"      N = {N}")
    print(f"      e = {e}")
    print(f"    Private key (kept secret):")
    print(f"      d = {d_real}")
    print(f"      p = {p_real}, q = {q_real}")

    # Step 2: Bob sends encrypted message
    print("\n[2] BOB ENCRYPTS A SECRET MESSAGE")
    print("-" * 40)

    secret_message = 42  # Could be a symmetric key, password hash, etc.
    ciphertext = rsa_encrypt(secret_message, public_key)

    print(f"    Secret message: {secret_message}")
    print(f"    Encrypted: {ciphertext}")
    print(f"    (Sent over public network)")

    # Step 3: Eve intercepts and attacks
    print("\n[3] EVE (ATTACKER) INTERCEPTS AND ATTACKS")
    print("-" * 40)

    print("    Eve has: public key (N, e) and ciphertext")
    print("    Eve wants: the secret message")
    print("\n    Launching Shor's algorithm attack...")

    d_recovered, p_recovered, q_recovered = break_rsa_with_shors(public_key, verbose=False)

    print(f"\n    Eve recovered:")
    print(f"      p = {p_recovered} (correct: {p_recovered == p_real})")
    print(f"      q = {q_recovered} (correct: {q_recovered == q_real or q_recovered == p_real})")
    print(f"      d = {d_recovered} (correct: {d_recovered == d_real})")

    # Step 4: Eve decrypts the message
    print("\n[4] EVE DECRYPTS THE SECRET")
    print("-" * 40)

    # Create fake private key with recovered values
    fake_private_key = (N, d_recovered, p_recovered, q_recovered)
    decrypted = rsa_decrypt(ciphertext, fake_private_key)

    print(f"    Eve decrypts ciphertext {ciphertext}...")
    print(f"    Recovered message: {decrypted}")
    print(f"    Original message:  {secret_message}")
    print(f"    Attack successful: {decrypted == secret_message}")

    # Summary
    print("\n" + "="*70)
    print("ATTACK SUMMARY")
    print("="*70)
    print("""
    What happened:
    1. Alice created RSA keys and shared public key
    2. Bob encrypted a secret message with Alice's public key
    3. Eve intercepted the public key and ciphertext
    4. Eve used Shor's algorithm to factor N into p and q
    5. Eve computed private key d from p, q, and e
    6. Eve decrypted Bob's secret message

    This attack works on ANY RSA key given a large enough quantum computer.

    Real-world implications:
    - All HTTPS connections using RSA key exchange
    - Encrypted emails (PGP/GPG with RSA)
    - Code signing certificates
    - VPN connections
    - SSH authentication
    - Banking and financial systems

    Timeline estimate:
    - Current: ~100 qubits (noisy), cannot break RSA
    - Future: ~4000 logical qubits needed for 2048-bit RSA
    - Estimated: 10-20 years until cryptographically relevant quantum computers
    """)
