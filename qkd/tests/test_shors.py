"""
Tests for Shor's Algorithm Threat Demonstration

These tests verify that the Shor's algorithm simulation correctly:
1. Factors composite numbers
2. Solves discrete logarithms
3. Breaks RSA encryption
4. Breaks ECDSA signatures
"""

import pytest
import sys
sys.path.insert(0, 'src')

from shors_threat.shors_algorithm import (
    gcd,
    mod_pow,
    classical_order_finding,
    quantum_order_finding_simulation,
    shors_factor,
    shors_discrete_log,
)

from shors_threat.rsa_attack import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    break_rsa_with_shors,
    recover_private_key,
    mod_inverse,
)

from shors_threat.ecdsa_attack import (
    DEMO_CURVE,
    ECPoint,
    generate_ecdsa_keypair,
    ecdsa_sign,
    ecdsa_verify,
    break_ecdsa_with_shors,
    scalar_mult,
    point_add,
)


class TestMathUtilities:
    """Test basic mathematical utilities."""

    def test_gcd(self):
        """Test greatest common divisor."""
        assert gcd(48, 18) == 6
        assert gcd(17, 13) == 1
        assert gcd(100, 25) == 25
        assert gcd(1, 100) == 1

    def test_mod_pow(self):
        """Test modular exponentiation."""
        assert mod_pow(2, 10, 1000) == 24  # 2^10 = 1024 mod 1000 = 24
        assert mod_pow(3, 5, 7) == 5       # 3^5 = 243 mod 7 = 5
        assert mod_pow(7, 0, 100) == 1     # any^0 = 1

    def test_mod_inverse(self):
        """Test modular multiplicative inverse."""
        # 3 * 7 = 21 ≡ 1 (mod 10)
        assert (3 * mod_inverse(3, 10)) % 10 == 1
        # 17 * x ≡ 1 (mod 43)
        inv = mod_inverse(17, 43)
        assert (17 * inv) % 43 == 1


class TestOrderFinding:
    """Test order finding algorithms."""

    def test_classical_order_finding(self):
        """Test classical order finding."""
        # Order of 2 mod 7 is 3 (2^3 = 8 ≡ 1 mod 7)
        assert classical_order_finding(2, 7) == 3
        # Order of 3 mod 7 is 6
        assert classical_order_finding(3, 7) == 6

    def test_quantum_order_finding(self):
        """Test simulated quantum order finding."""
        # Same results as classical
        assert quantum_order_finding_simulation(2, 7) == 3
        assert quantum_order_finding_simulation(3, 7) == 6


class TestShorsFactoring:
    """Test Shor's algorithm for factoring."""

    def test_factor_small_semiprime(self):
        """Test factoring small semiprimes."""
        # 15 = 3 * 5
        p, q = shors_factor(15)
        assert p * q == 15
        assert {p, q} == {3, 5}

    def test_factor_medium_semiprime(self):
        """Test factoring medium semiprimes."""
        # 77 = 7 * 11
        p, q = shors_factor(77)
        assert p * q == 77
        assert {p, q} == {7, 11}

    def test_factor_larger_semiprime(self):
        """Test factoring larger semiprimes."""
        # 221 = 13 * 17
        p, q = shors_factor(221)
        assert p * q == 221
        assert {p, q} == {13, 17}

    def test_factor_even_number(self):
        """Test factoring even numbers (trivial case)."""
        p, q = shors_factor(100)
        assert p * q == 100
        assert p == 2 or q == 2


class TestDiscreteLog:
    """Test Shor's algorithm for discrete logarithm."""

    def test_discrete_log_small(self):
        """Test discrete log for small cases."""
        # g=2, p=11: find x where 2^x ≡ 8 (mod 11)
        # 2^3 = 8
        x = shors_discrete_log(2, 8, 11)
        assert mod_pow(2, x, 11) == 8

    def test_discrete_log_medium(self):
        """Test discrete log for medium cases."""
        # g=3, p=17: find x where 3^x ≡ 10 (mod 17)
        x = shors_discrete_log(3, 10, 17)
        assert mod_pow(3, x, 17) == 10


class TestRSAAttack:
    """Test RSA key generation and attack."""

    def test_rsa_keygen(self):
        """Test RSA key generation."""
        public_key, private_key = generate_rsa_keypair(bits=16)
        N, e = public_key
        _, d, p, q = private_key

        # Verify N = p * q
        assert N == p * q
        # Verify e * d ≡ 1 (mod φ(N))
        phi = (p - 1) * (q - 1)
        assert (e * d) % phi == 1

    def test_rsa_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        public_key, private_key = generate_rsa_keypair(bits=16)
        N, _ = public_key

        message = 42
        ciphertext = rsa_encrypt(message, public_key)
        decrypted = rsa_decrypt(ciphertext, private_key)

        assert decrypted == message

    def test_rsa_attack(self):
        """Test breaking RSA with Shor's algorithm."""
        public_key, private_key = generate_rsa_keypair(bits=16)
        N, e = public_key
        _, d_real, p_real, q_real = private_key

        # Attack
        d_recovered, p_recovered, q_recovered = break_rsa_with_shors(
            public_key, verbose=False
        )

        # Verify factors are correct
        assert p_recovered * q_recovered == N

        # Verify recovered private key works
        message = 123
        ciphertext = rsa_encrypt(message, public_key)
        fake_private_key = (N, d_recovered, p_recovered, q_recovered)
        decrypted = rsa_decrypt(ciphertext, fake_private_key)

        assert decrypted == message


class TestECDSAAttack:
    """Test ECDSA key generation and attack."""

    def test_point_operations(self):
        """Test elliptic curve point operations."""
        curve = DEMO_CURVE
        G = ECPoint(curve.Gx, curve.Gy)

        # Test scalar multiplication
        P2 = scalar_mult(curve, 2, G)
        assert not P2.is_infinity()

        # Test that n*G = infinity (order property)
        O = scalar_mult(curve, curve.n, G)
        assert O.is_infinity()

    def test_ecdsa_keygen(self):
        """Test ECDSA key generation."""
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        # Verify public key is on curve
        G = ECPoint(DEMO_CURVE.Gx, DEMO_CURVE.Gy)
        expected = scalar_mult(DEMO_CURVE, private_key, G)
        assert public_key == expected

    def test_ecdsa_sign_verify(self):
        """Test ECDSA signing and verification."""
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        message = b"Test message"
        signature = ecdsa_sign(DEMO_CURVE, message, private_key)

        assert ecdsa_verify(DEMO_CURVE, message, signature, public_key)

    def test_ecdsa_wrong_message(self):
        """Test that wrong message fails verification."""
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        message = b"Original message"
        signature = ecdsa_sign(DEMO_CURVE, message, private_key)

        wrong_message = b"Different message"
        assert not ecdsa_verify(DEMO_CURVE, wrong_message, signature, public_key)

    def test_ecdsa_attack(self):
        """Test breaking ECDSA with Shor's algorithm."""
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        # Attack - recover private key from public key
        recovered_key = break_ecdsa_with_shors(DEMO_CURVE, public_key, verbose=False)

        # Verify recovered key matches
        assert recovered_key == private_key

    def test_ecdsa_forge_signature(self):
        """Test forging signatures with recovered key."""
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        # Recover private key
        recovered_key = break_ecdsa_with_shors(DEMO_CURVE, public_key, verbose=False)

        # Forge a signature
        forged_message = b"Forged transaction"
        forged_signature = ecdsa_sign(DEMO_CURVE, forged_message, recovered_key)

        # Verify forged signature with victim's public key
        assert ecdsa_verify(DEMO_CURVE, forged_message, forged_signature, public_key)


class TestIntegration:
    """Integration tests for complete attack scenarios."""

    def test_full_rsa_attack_scenario(self):
        """Test complete RSA attack scenario."""
        # Victim generates keys
        public_key, private_key = generate_rsa_keypair(bits=20)

        # Victim encrypts sensitive data
        secret_data = 9999
        ciphertext = rsa_encrypt(secret_data, public_key)

        # Attacker only has public key and ciphertext
        d_recovered, p, q = break_rsa_with_shors(public_key, verbose=False)

        # Attacker decrypts
        N, e = public_key
        attacker_key = (N, d_recovered, p, q)
        stolen_data = rsa_decrypt(ciphertext, attacker_key)

        assert stolen_data == secret_data

    def test_full_ecdsa_attack_scenario(self):
        """Test complete ECDSA attack scenario."""
        # Victim generates wallet
        public_key, private_key = generate_ecdsa_keypair(DEMO_CURVE)

        # Victim signs legitimate transaction
        legitimate_tx = b"Pay 10 to merchant"
        legitimate_sig = ecdsa_sign(DEMO_CURVE, legitimate_tx, private_key)
        assert ecdsa_verify(DEMO_CURVE, legitimate_tx, legitimate_sig, public_key)

        # Attacker extracts private key from public key
        stolen_key = break_ecdsa_with_shors(DEMO_CURVE, public_key, verbose=False)

        # Attacker forges malicious transaction
        malicious_tx = b"Pay 10000 to attacker"
        forged_sig = ecdsa_sign(DEMO_CURVE, malicious_tx, stolen_key)

        # Malicious transaction validates with victim's public key!
        assert ecdsa_verify(DEMO_CURVE, malicious_tx, forged_sig, public_key)
