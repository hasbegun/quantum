"""Tests for superdense coding protocol."""

import pytest
import cirq

from qkd import SuperdenseCoding, SuperdenseResult


@pytest.fixture
def superdense():
    """Create a SuperdenseCoding instance with fixed seed."""
    return SuperdenseCoding(seed=42)


class TestSuperdenseCoding:
    """Tests for SuperdenseCoding protocol."""

    def test_create_bell_pair(self, superdense):
        """Test Bell pair creation produces correct state."""
        q0 = cirq.LineQubit(0)
        q1 = cirq.LineQubit(1)

        circuit = superdense.create_bell_pair(q0, q1)

        # Verify circuit structure
        ops = list(circuit.all_operations())
        assert len(ops) == 2
        assert ops[0].gate == cirq.H
        assert ops[1].gate == cirq.CNOT

    def test_encode_message_00(self, superdense):
        """Test encoding message (0,0) - no gates."""
        qubit = cirq.LineQubit(0)
        ops = superdense.encode_message((0, 0), qubit)
        assert len(ops) == 0  # Identity = no operations

    def test_encode_message_01(self, superdense):
        """Test encoding message (0,1) - X gate."""
        qubit = cirq.LineQubit(0)
        ops = superdense.encode_message((0, 1), qubit)
        assert len(ops) == 1
        assert ops[0].gate == cirq.X

    def test_encode_message_10(self, superdense):
        """Test encoding message (1,0) - Z gate."""
        qubit = cirq.LineQubit(0)
        ops = superdense.encode_message((1, 0), qubit)
        assert len(ops) == 1
        assert ops[0].gate == cirq.Z

    def test_encode_message_11(self, superdense):
        """Test encoding message (1,1) - X then Z gates."""
        qubit = cirq.LineQubit(0)
        ops = superdense.encode_message((1, 1), qubit)
        assert len(ops) == 2
        assert ops[0].gate == cirq.X
        assert ops[1].gate == cirq.Z

    def test_decode_circuit(self, superdense):
        """Test decode circuit structure."""
        q0 = cirq.LineQubit(0)
        q1 = cirq.LineQubit(1)

        ops = superdense.decode_circuit(q0, q1)

        assert len(ops) == 4
        assert ops[0].gate == cirq.CNOT
        assert ops[1].gate == cirq.H
        assert cirq.is_measurement(ops[2])
        assert cirq.is_measurement(ops[3])

    @pytest.mark.parametrize("message", [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
    ])
    def test_send_all_messages(self, superdense, message):
        """Test that all four 2-bit messages are transmitted correctly."""
        result = superdense.send_message(message)

        assert result.num_transmissions == 1
        assert result.original_messages[0] == message
        assert result.decoded_messages[0] == message
        assert result.success_rate == 1.0

    def test_run_multiple_messages(self, superdense):
        """Test sending multiple messages."""
        messages = [(0, 0), (0, 1), (1, 0), (1, 1)] * 5  # 20 messages

        result = superdense.run(messages)

        assert result.num_transmissions == 20
        assert result.successful == 20
        assert result.success_rate == 1.0
        assert result.original_messages == messages
        assert result.decoded_messages == messages

    def test_run_random_messages(self, superdense):
        """Test running with random messages."""
        result = superdense.run(num_messages=50)

        assert result.num_transmissions == 50
        assert result.success_rate == 1.0  # Should be perfect in simulation
        assert len(result.original_messages) == 50
        assert len(result.decoded_messages) == 50

    def test_get_circuit(self, superdense):
        """Test getting the full circuit for visualization."""
        circuit = superdense.get_circuit((1, 1))

        # Should have: H, CNOT (bell), X, Z (encode), CNOT, H (decode), 2 measurements
        ops = list(circuit.all_operations())
        assert len(ops) == 8

    def test_result_str(self, superdense):
        """Test SuperdenseResult string representation."""
        result = superdense.run([(0, 0), (1, 1)])

        str_repr = str(result)
        assert "Superdense Coding Results" in str_repr
        assert "Messages transmitted: 2" in str_repr
        assert "Success rate: 100.0%" in str_repr


class TestSuperdenseResultDataclass:
    """Tests for SuperdenseResult dataclass."""

    def test_result_fields(self):
        """Test that result has all expected fields."""
        result = SuperdenseResult(
            original_messages=[(0, 0), (1, 1)],
            decoded_messages=[(0, 0), (1, 1)],
            num_transmissions=2,
            successful=2,
            success_rate=1.0
        )

        assert result.original_messages == [(0, 0), (1, 1)]
        assert result.decoded_messages == [(0, 0), (1, 1)]
        assert result.num_transmissions == 2
        assert result.successful == 2
        assert result.success_rate == 1.0


class TestSuperdenseReproducibility:
    """Tests for reproducibility with seeds."""

    def test_same_seed_same_results(self):
        """Test that same seed produces same random messages."""
        sd1 = SuperdenseCoding(seed=123)
        sd2 = SuperdenseCoding(seed=123)

        result1 = sd1.run(num_messages=10)
        result2 = sd2.run(num_messages=10)

        assert result1.original_messages == result2.original_messages

    def test_different_seed_different_results(self):
        """Test that different seeds produce different random messages."""
        sd1 = SuperdenseCoding(seed=123)
        sd2 = SuperdenseCoding(seed=456)

        result1 = sd1.run(num_messages=10)
        result2 = sd2.run(num_messages=10)

        # With high probability, should be different
        assert result1.original_messages != result2.original_messages
