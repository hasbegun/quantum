"""
ECDSA Attack Demonstration using Shor's Algorithm

This module demonstrates how Shor's algorithm breaks ECDSA (Elliptic Curve DSA).

ECDSA Security Assumption:
=========================
ECDSA relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
Given points G and P = k*G on an elliptic curve, find the scalar k.

This is believed to be computationally hard for classical computers,
but Shor's algorithm solves it efficiently on a quantum computer.

The Attack:
==========
1. Attacker obtains public key P = k*G (from blockchain, certificate, etc.)
2. Uses quantum discrete log to find private key k
3. Can now sign transactions, forge certificates, impersonate identity

Why This Matters:
================
- ECDSA is used in: Bitcoin, Ethereum, TLS/HTTPS, SSH, code signing
- Smaller keys than RSA for same security (256-bit vs 2048-bit)
- All cryptocurrency wallets with exposed public keys are vulnerable
- "Harvest now, break later" - collect public keys today, break tomorrow
"""

import random
import hashlib
from typing import Tuple, Optional
from dataclasses import dataclass
from .shors_algorithm import shors_discrete_log, mod_pow


@dataclass
class EllipticCurve:
    """
    Elliptic curve parameters for y^2 = x^3 + ax + b (mod p)

    For demonstration, we use a small curve.
    Real ECDSA uses curves like secp256k1 (Bitcoin) or P-256 (NIST).
    """
    name: str
    p: int      # Prime field modulus
    a: int      # Curve parameter a
    b: int      # Curve parameter b
    Gx: int     # Generator point x-coordinate
    Gy: int     # Generator point y-coordinate
    n: int      # Order of generator point (number of points in subgroup)


# Small curve for demonstration (NOT secure, just educational)
# Using secp112r1-like small curve with verified parameters
# Curve: y^2 = x^3 + ax + b (mod p)
# This is a carefully chosen small curve for demonstration
DEMO_CURVE = EllipticCurve(
    name="demo-curve",
    p=211,          # Small prime
    a=0,            # Curve: y^2 = x^3 + 7 (mod 211) - similar to secp256k1
    b=7,
    Gx=2,           # Generator point
    Gy=2,           # Verified: 2^2 = 4, 2^3 + 7 = 15; 4 != 15, need to find correct point
    n=199           # Order of curve (prime, good for crypto)
)


def _find_curve_point(p: int, a: int, b: int) -> tuple:
    """Find a valid point on the curve y^2 = x^3 + ax + b (mod p)."""
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        # Check if rhs is a quadratic residue
        for y in range(p):
            if (y * y) % p == rhs:
                return (x, y)
    return None


def _compute_curve_order(p: int, a: int, b: int, gx: int, gy: int) -> int:
    """Compute the order of the generator point by iteration."""
    from dataclasses import dataclass

    @dataclass
    class _Point:
        x: int
        y: int
        def is_inf(self): return self.x is None

    INF = _Point(None, None)

    def _add(P, Q):
        if P.is_inf(): return Q
        if Q.is_inf(): return P
        if P.x == Q.x and (P.y + Q.y) % p == 0: return INF
        if P.x == Q.x:
            lam = ((3 * P.x * P.x + a) * pow(2 * P.y, -1, p)) % p
        else:
            lam = ((Q.y - P.y) * pow(Q.x - P.x, -1, p)) % p
        x3 = (lam * lam - P.x - Q.x) % p
        y3 = (lam * (P.x - x3) - P.y) % p
        return _Point(x3, y3)

    G = _Point(gx, gy)
    P = G
    for k in range(1, p + p):
        if P.is_inf():
            return k
        P = _add(P, G)
    return p  # fallback


# Initialize the demo curve with verified parameters
def _init_demo_curve():
    """Initialize demo curve with verified generator and order."""
    # Use a small prime for fast demonstration (p=67 gives good balance)
    p, a, b = 67, 2, 3

    # Find a valid point on the curve
    point = _find_curve_point(p, a, b)
    if point is None:
        # Fallback to a known working curve
        return EllipticCurve(
            name="demo-curve",
            p=23, a=1, b=1, Gx=0, Gy=1, n=28
        )

    gx, gy = point

    # Compute the actual order
    n = _compute_curve_order(p, a, b, gx, gy)

    return EllipticCurve(
        name="demo-curve",
        p=p, a=a, b=b, Gx=gx, Gy=gy, n=n
    )


# Override DEMO_CURVE with verified parameters
DEMO_CURVE = _init_demo_curve()

# Simulated secp256k1 parameters (actual Bitcoin curve)
SECP256K1_INFO = {
    "name": "secp256k1 (Bitcoin)",
    "p_bits": 256,
    "n_bits": 256,
    "security_classical": "128-bit equivalent",
    "security_quantum": "BROKEN by Shor's algorithm",
}


@dataclass
class ECPoint:
    """Point on an elliptic curve, or the point at infinity."""
    x: Optional[int]
    y: Optional[int]

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __eq__(self, other) -> bool:
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_infinity():
            return "O (infinity)"
        return f"({self.x}, {self.y})"


# Point at infinity (identity element)
INFINITY = ECPoint(None, None)


def mod_inverse(a: int, p: int) -> int:
    """Modular multiplicative inverse using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1

    _, x, _ = extended_gcd(a % p, p)
    return (x % p + p) % p


def point_add(curve: EllipticCurve, P: ECPoint, Q: ECPoint) -> ECPoint:
    """Add two points on an elliptic curve."""
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    p = curve.p

    if P.x == Q.x:
        if (P.y + Q.y) % p == 0:
            return INFINITY  # P + (-P) = O
        # Point doubling
        lam = ((3 * P.x * P.x + curve.a) * mod_inverse(2 * P.y, p)) % p
    else:
        # Point addition
        lam = ((Q.y - P.y) * mod_inverse(Q.x - P.x, p)) % p

    x3 = (lam * lam - P.x - Q.x) % p
    y3 = (lam * (P.x - x3) - P.y) % p

    return ECPoint(x3, y3)


def scalar_mult(curve: EllipticCurve, k: int, P: ECPoint) -> ECPoint:
    """Multiply a point by a scalar: k * P."""
    if k == 0 or P.is_infinity():
        return INFINITY

    result = INFINITY
    addend = P
    k = k % curve.n

    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1

    return result


def generate_ecdsa_keypair(curve: EllipticCurve = DEMO_CURVE) -> Tuple[ECPoint, int]:
    """
    Generate ECDSA key pair.

    Private key: Random integer k in [1, n-1]
    Public key: P = k * G (point on curve)

    Args:
        curve: Elliptic curve parameters

    Returns:
        (public_key, private_key)
    """
    G = ECPoint(curve.Gx, curve.Gy)

    # Private key: random scalar
    private_key = random.randint(1, curve.n - 1)

    # Public key: P = k * G
    public_key = scalar_mult(curve, private_key, G)

    return public_key, private_key


def hash_message(message: bytes, n: int) -> int:
    """Hash message and reduce modulo n."""
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, 'big') % n


def ecdsa_sign(curve: EllipticCurve, message: bytes, private_key: int) -> Tuple[int, int]:
    """
    Sign a message using ECDSA.

    Args:
        curve: Elliptic curve parameters
        message: Message to sign
        private_key: Signer's private key k

    Returns:
        Signature (r, s)
    """
    G = ECPoint(curve.Gx, curve.Gy)
    n = curve.n
    z = hash_message(message, n)

    while True:
        # Generate random nonce
        k = random.randint(1, n - 1)

        # R = k * G
        R = scalar_mult(curve, k, G)
        r = R.x % n

        if r == 0:
            continue

        # s = k^(-1) * (z + r * private_key) mod n
        k_inv = mod_inverse(k, n)
        s = (k_inv * (z + r * private_key)) % n

        if s == 0:
            continue

        return (r, s)


def ecdsa_verify(curve: EllipticCurve, message: bytes, signature: Tuple[int, int],
                 public_key: ECPoint) -> bool:
    """
    Verify an ECDSA signature.

    Args:
        curve: Elliptic curve parameters
        message: Signed message
        signature: (r, s)
        public_key: Signer's public key

    Returns:
        True if valid, False otherwise
    """
    G = ECPoint(curve.Gx, curve.Gy)
    n = curve.n
    r, s = signature

    if not (1 <= r < n and 1 <= s < n):
        return False

    z = hash_message(message, n)
    s_inv = mod_inverse(s, n)

    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n

    # R' = u1*G + u2*P
    R1 = scalar_mult(curve, u1, G)
    R2 = scalar_mult(curve, u2, public_key)
    R_prime = point_add(curve, R1, R2)

    if R_prime.is_infinity():
        return False

    return R_prime.x % n == r


def classical_discrete_log_attempt(curve: EllipticCurve, public_key: ECPoint,
                                    max_iterations: int = 100000) -> Optional[int]:
    """
    Attempt to find private key using classical brute force.

    This demonstrates why ECDLP is hard classically:
    - Must try each possible k from 1 to n
    - For secp256k1, n ≈ 2^256 possibilities
    - Even at 10^12 ops/second, would take 10^60 years

    Better classical attacks (Pollard's rho) run in O(sqrt(n)) time,
    but still infeasible for 256-bit curves.

    Args:
        curve: Elliptic curve
        public_key: P = k * G (we want to find k)
        max_iterations: Limit for demonstration

    Returns:
        Private key k if found, None otherwise
    """
    G = ECPoint(curve.Gx, curve.Gy)
    point = G

    for k in range(1, min(curve.n, max_iterations)):
        if point == public_key:
            return k
        point = point_add(curve, point, G)

    return None


def quantum_discrete_log(curve: EllipticCurve, public_key: ECPoint) -> int:
    """
    Simulate quantum discrete log attack on ECDSA.

    Shor's algorithm solves ECDLP in polynomial time:
    - Classical: O(sqrt(n)) with Pollard's rho
    - Quantum: O((log n)^3) with Shor

    For 256-bit curve:
    - Classical: ~2^128 operations (infeasible)
    - Quantum: ~2^24 operations (very fast)

    This simulation uses classical search for small demo curve.

    Args:
        curve: Elliptic curve parameters
        public_key: P = k * G

    Returns:
        Private key k
    """
    G = ECPoint(curve.Gx, curve.Gy)

    # Quantum computer would use:
    # 1. Superposition over all possible k values
    # 2. Compute k*G in superposition
    # 3. Quantum Fourier Transform to extract k

    # Classical simulation for demonstration
    point = G
    for k in range(1, curve.n + 1):
        if point == public_key:
            return k
        point = point_add(curve, point, G)

    raise ValueError("Discrete log not found")


def break_ecdsa_with_shors(curve: EllipticCurve, public_key: ECPoint,
                           verbose: bool = True) -> int:
    """
    Break ECDSA using Shor's algorithm.

    This is the complete attack:
    1. Obtain public key P from target (blockchain, certificate, etc.)
    2. Use quantum discrete log to find k where P = k*G
    3. k is the private key - can now sign arbitrary messages

    Args:
        curve: Elliptic curve parameters
        public_key: Target's public key
        verbose: Print attack progress

    Returns:
        Recovered private key
    """
    if verbose:
        print("\n" + "="*70)
        print("ECDSA ATTACK USING SHOR'S ALGORITHM")
        print("="*70)
        print(f"\n[Target] Public key intercepted:")
        print(f"         Curve: {curve.name}")
        print(f"         P = {public_key}")
        print(f"         (From blockchain transaction, certificate, etc.)")

    # Step 1: Attempt classical attack
    if verbose:
        print(f"\n[Classical Attack] Attempting brute force...")

    classical_result = classical_discrete_log_attempt(curve, public_key, max_iterations=10000)

    if classical_result:
        if verbose:
            print(f"[Classical] Found k = {classical_result} (small key)")
    else:
        if verbose:
            print(f"[Classical] Failed - key space too large")
            print(f"            Would need ~{curve.n:,} iterations")

    # Step 2: Quantum attack
    if verbose:
        print(f"\n[Quantum Attack] Deploying Shor's algorithm...")
        print(f"[Quantum] Creating superposition over all k values...")
        print(f"[Quantum] Computing k*G in superposition...")
        print(f"[Quantum] Applying Quantum Fourier Transform...")

    private_key = quantum_discrete_log(curve, public_key)

    if verbose:
        # Verify
        G = ECPoint(curve.Gx, curve.Gy)
        recovered_public = scalar_mult(curve, private_key, G)

        print(f"\n[Quantum] Private key found: k = {private_key}")
        print(f"[Quantum] Verification: k*G = {recovered_public}")
        print(f"[Quantum] Matches public key: {recovered_public == public_key}")
        print(f"\n[ATTACK COMPLETE] ECDSA is broken!")

    return private_key


def demonstrate_ecdsa_attack():
    """
    Full demonstration of ECDSA being broken by Shor's algorithm.

    Shows:
    1. Normal ECDSA usage (key generation, signing, verification)
    2. Quantum attack recovering private key
    3. Attacker forging signatures
    """
    curve = DEMO_CURVE

    print("\n" + "="*70)
    print("COMPLETE ECDSA ATTACK DEMONSTRATION")
    print("="*70)

    # Step 1: Alice generates ECDSA keys
    print("\n[1] ALICE GENERATES ECDSA KEYS")
    print("-" * 40)

    public_key, private_key = generate_ecdsa_keypair(curve)

    print(f"    Curve: {curve.name}")
    print(f"    Generator G = ({curve.Gx}, {curve.Gy})")
    print(f"    Private key (secret): k = {private_key}")
    print(f"    Public key (shared):  P = {public_key}")

    # Step 2: Alice signs a transaction
    print("\n[2] ALICE SIGNS A TRANSACTION")
    print("-" * 40)

    message = b"Transfer 10 BTC to Bob"
    signature = ecdsa_sign(curve, message, private_key)

    print(f"    Message: {message.decode()}")
    print(f"    Signature: r={signature[0]}, s={signature[1]}")

    valid = ecdsa_verify(curve, message, signature, public_key)
    print(f"    Verification: {valid}")

    # Step 3: Eve attacks
    print("\n[3] EVE (ATTACKER) EXTRACTS PRIVATE KEY")
    print("-" * 40)

    print("    Eve has: Alice's public key P (from blockchain)")
    print("    Eve wants: Alice's private key k")
    print("\n    Launching Shor's algorithm attack...")

    recovered_key = break_ecdsa_with_shors(curve, public_key, verbose=False)

    print(f"\n    Eve recovered private key: {recovered_key}")
    print(f"    Matches Alice's key: {recovered_key == private_key}")

    # Step 4: Eve forges a transaction
    print("\n[4] EVE FORGES A TRANSACTION")
    print("-" * 40)

    forged_message = b"Transfer 100 BTC to Eve"
    forged_signature = ecdsa_sign(curve, forged_message, recovered_key)

    print(f"    Forged message: {forged_message.decode()}")
    print(f"    Forged signature: r={forged_signature[0]}, s={forged_signature[1]}")

    # Verify forged signature
    forged_valid = ecdsa_verify(curve, forged_message, forged_signature, public_key)
    print(f"    Signature valid with Alice's public key: {forged_valid}")

    # Summary
    print("\n" + "="*70)
    print("ATTACK SUMMARY")
    print("="*70)
    print("""
    What happened:
    1. Alice created ECDSA keys and published her public key
    2. Alice signed legitimate transactions
    3. Eve obtained Alice's public key (publicly available)
    4. Eve used Shor's algorithm to extract Alice's private key
    5. Eve can now forge Alice's signature on ANY message

    Real-world implications for cryptocurrency:

    Bitcoin (secp256k1):
    - ~$1 trillion in value protected by ECDSA
    - Public keys exposed when address is reused or revealed
    - Quantum computer could steal ALL Bitcoin with exposed keys

    Ethereum:
    - Same ECDSA vulnerability
    - Smart contracts with exposed addresses at risk

    Other affected systems:
    - TLS certificates (website authentication)
    - SSH keys (server access)
    - Code signing (software authenticity)
    - Government ID cards (digital identity)

    Estimated timeline:
    - 2024: ~1000 physical qubits, no cryptographic threat
    - 2030s: Possibly 10,000+ qubits, early cryptographic attacks
    - 2040s: Full-scale cryptographically relevant quantum computers

    Mitigation: Migrate to post-quantum signatures (ML-DSA, SLH-DSA)
    """)


def cryptocurrency_threat_analysis():
    """
    Analyze the specific threat to cryptocurrency from quantum computers.
    """
    print("\n" + "="*70)
    print("CRYPTOCURRENCY QUANTUM THREAT ANALYSIS")
    print("="*70)

    print("""
    BITCOIN VULNERABILITY ANALYSIS
    ==============================

    Bitcoin uses ECDSA with the secp256k1 curve:
    - Private key: 256-bit random number
    - Public key: Point on secp256k1 curve
    - Address: Hash of public key (provides some protection)

    Two types of Bitcoin addresses:

    1. PAY-TO-PUBLIC-KEY (P2PK) - FULLY VULNERABLE
       - Public key is directly exposed
       - ~2 million BTC in early P2PK outputs
       - Satoshi's coins are in this format!
       - Quantum attack: Extract private key directly

    2. PAY-TO-PUBLIC-KEY-HASH (P2PKH) - PARTIALLY PROTECTED
       - Address is hash of public key
       - Public key revealed ONLY when spending
       - If address reused: public key exposed, vulnerable
       - If address used once: protected until spending

    Attack scenarios:

    Scenario 1: "Harvest Now, Decrypt Later"
    - Adversaries record all blockchain transactions today
    - Store public keys from P2PK and reused addresses
    - When quantum computers arrive, extract all private keys
    - Steal all exposed Bitcoin instantly

    Scenario 2: "Transaction Race Attack"
    - Alice broadcasts transaction to spend her Bitcoin
    - Transaction is in mempool, not yet confirmed
    - Quantum attacker sees Alice's public key in transaction
    - Attacker quickly computes private key
    - Attacker creates conflicting transaction with higher fee
    - Attacker's transaction confirms, stealing Alice's funds

    Estimated vulnerable Bitcoin:
    - ~4 million BTC in addresses with exposed public keys
    - Current value: ~$250 billion
    - Includes Satoshi's ~1 million BTC

    ETHEREUM VULNERABILITY
    ======================

    Similar ECDSA vulnerability:
    - All ETH addresses have exposed public keys after first transaction
    - Smart contracts holding ETH are vulnerable
    - DeFi protocols worth billions at risk

    RECOMMENDED MITIGATIONS
    =======================

    For users:
    1. Never reuse Bitcoin addresses
    2. Move funds to fresh addresses before quantum threat
    3. Support post-quantum signature upgrades

    For protocols:
    1. Add post-quantum signature schemes (ML-DSA, SLH-DSA)
    2. Allow migration to quantum-resistant addresses
    3. Consider quantum-resistant consensus mechanisms
    """)
