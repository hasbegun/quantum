"""Tests for BB84 protocol."""

import pytest

from qkd import BB84Protocol, Alice, Bob, Eve, Basis
from qkd.analysis import calculate_error_rate, check_for_eavesdropper


class TestAlice:
    """Tests for Alice participant."""

    def test_generate_bits(self, alice):
        """Test bit generation."""
        bits = alice.generate_bits()
        assert len(bits) == 50
        assert all(b in (0, 1) for b in bits)

    def test_choose_bases(self, alice):
        """Test basis selection."""
        bases = alice.choose_bases()
        assert len(bases) == 50
        assert all(b in (Basis.Z, Basis.X) for b in bases)

    def test_prepare_qubits(self, alice):
        """Test qubit preparation."""
        qubits = alice.prepare_qubits()
        assert len(qubits) == 50
        # Each should be (circuit, qubit) tuple
        for circuit, qubit in qubits:
            assert circuit is not None
            assert qubit is not None


class TestBob:
    """Tests for Bob participant."""

    def test_choose_bases(self, bob):
        """Test basis selection."""
        bases = bob.choose_bases()
        assert len(bases) == 50
        assert all(b in (Basis.Z, Basis.X) for b in bases)

    def test_receive_and_measure(self, alice, bob):
        """Test receiving and measuring qubits."""
        qubits = alice.prepare_qubits()
        measurements = bob.receive_and_measure(qubits)
        assert len(measurements) == 50
        assert all(m in (0, 1) for m in measurements)


class TestEve:
    """Tests for Eve eavesdropper."""

    def test_intercept(self, alice, eve):
        """Test interception of qubits."""
        qubits = alice.prepare_qubits()
        intercepted = eve.intercept_all(qubits)

        assert len(intercepted) == len(qubits)
        assert len(eve.intercepted_bits) == len(qubits)
        assert len(eve.guessed_bases) == len(qubits)


class TestBB84Protocol:
    """Tests for the full BB84 protocol."""

    def test_run_without_eve(self, protocol):
        """Test protocol without eavesdropper."""
        result = protocol.run(eavesdropper=False)

        assert result.initial_bits == 100
        assert result.sifted_key_length > 0
        assert result.sifted_key_length <= 100
        # Without Eve, error rate should be ~0%
        assert result.error_rate < 0.05
        assert not result.eve_present
        assert not result.eve_detected

    def test_run_with_eve(self, protocol):
        """Test protocol with eavesdropper."""
        result = protocol.run(eavesdropper=True)

        assert result.eve_present
        # With Eve, error rate should be ~25%
        assert result.error_rate > 0.1
        # Eve should typically be detected
        # (might occasionally not be due to random chance with small samples)

    def test_sifting_efficiency(self, protocol):
        """Test that sifting efficiency is around 50%."""
        result = protocol.run(eavesdropper=False)
        # Should be around 50% (within reasonable variance)
        assert 0.3 < result.sifting_efficiency < 0.7

    def test_eve_detection_rate(self):
        """Test that Eve is reliably detected over multiple runs."""
        detections = 0
        runs = 20

        for i in range(runs):
            protocol = BB84Protocol(num_bits=200, seed=i)
            result = protocol.run(eavesdropper=True)
            if result.eve_detected:
                detections += 1

        # Eve should be detected in most runs
        detection_rate = detections / runs
        assert detection_rate > 0.7, f"Detection rate too low: {detection_rate}"


class TestAnalysis:
    """Tests for analysis functions."""

    def test_calculate_error_rate_identical(self):
        """Test error rate with identical keys."""
        key = [0, 1, 0, 1, 0]
        assert calculate_error_rate(key, key) == 0.0

    def test_calculate_error_rate_all_different(self):
        """Test error rate with completely different keys."""
        key1 = [0, 0, 0, 0]
        key2 = [1, 1, 1, 1]
        assert calculate_error_rate(key1, key2) == 1.0

    def test_calculate_error_rate_half(self):
        """Test error rate with 50% errors."""
        key1 = [0, 0, 1, 1]
        key2 = [0, 1, 1, 0]
        assert calculate_error_rate(key1, key2) == 0.5

    def test_check_for_eavesdropper_no_errors(self):
        """Test eavesdropper check with no errors."""
        key = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1] * 10
        analysis = check_for_eavesdropper(key, key, seed=42)
        assert analysis.error_rate == 0.0
        assert not analysis.eve_detected

    def test_check_for_eavesdropper_high_errors(self):
        """Test eavesdropper check with high error rate."""
        key1 = [0] * 100
        key2 = [0] * 70 + [1] * 30  # 30% different
        analysis = check_for_eavesdropper(key1, key2, threshold=0.11, seed=42)
        # Should detect Eve (error rate > threshold)
        assert analysis.eve_detected
