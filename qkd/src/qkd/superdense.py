"""Superdense Coding Protocol implementation.

Superdense coding transmits 2 classical bits using 1 qubit,
leveraging pre-shared entanglement between Alice and Bob.
"""

from dataclasses import dataclass, field
import random

import cirq


@dataclass
class SuperdenseResult:
    """Results from a superdense coding protocol run."""
    original_messages: list[tuple[int, int]]
    decoded_messages: list[tuple[int, int]]
    num_transmissions: int
    successful: int
    success_rate: float

    def __str__(self) -> str:
        return (
            f"Superdense Coding Results\n"
            f"{'='*50}\n"
            f"Messages transmitted: {self.num_transmissions}\n"
            f"Successful decodes: {self.successful}\n"
            f"Success rate: {self.success_rate:.1%}\n"
            f"{'='*50}\n"
            f"First 5 messages: {self.original_messages[:5]}\n"
            f"First 5 decoded:  {self.decoded_messages[:5]}"
        )


@dataclass
class SuperdenseCoding:
    """
    Superdense Coding Protocol.

    Transmits 2 classical bits using 1 qubit by leveraging
    pre-shared entanglement.

    Protocol:
    1. Create Bell pair |Φ+⟩, give one qubit to Alice, one to Bob
    2. Alice encodes 2-bit message by applying gates to her qubit
    3. Alice sends her qubit to Bob
    4. Bob decodes by applying CNOT + H and measuring both qubits

    Example:
        >>> sd = SuperdenseCoding(seed=42)
        >>> result = sd.send_message((1, 0))
        >>> print(f"Decoded: {result.decoded_messages[0]}")

        >>> # Send multiple messages
        >>> result = sd.run([(0,0), (0,1), (1,0), (1,1)])
        >>> print(f"Success rate: {result.success_rate:.0%}")
    """
    seed: int | None = None

    _rng: random.Random = field(init=False, repr=False)
    _simulator: cirq.Simulator = field(init=False, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)
        self._simulator = cirq.Simulator(seed=self.seed)

    def create_bell_pair(
        self,
        alice_qubit: cirq.LineQubit,
        bob_qubit: cirq.LineQubit
    ) -> cirq.Circuit:
        """
        Create a Bell pair |Φ+⟩ = (|00⟩ + |11⟩)/√2.

        Args:
            alice_qubit: Qubit that will belong to Alice
            bob_qubit: Qubit that will belong to Bob

        Returns:
            Circuit that creates the Bell pair
        """
        return cirq.Circuit([
            cirq.H(alice_qubit),
            cirq.CNOT(alice_qubit, bob_qubit)
        ])

    def encode_message(
        self,
        message: tuple[int, int],
        qubit: cirq.LineQubit
    ) -> list[cirq.Operation]:
        """
        Encode a 2-bit message onto Alice's qubit.

        Encoding scheme:
        - (0, 0): I (do nothing)     → |Φ+⟩
        - (0, 1): X                   → |Ψ+⟩
        - (1, 0): Z                   → |Φ-⟩
        - (1, 1): X then Z            → |Ψ-⟩

        Args:
            message: Tuple of (bit1, bit0) to encode
            qubit: Alice's qubit from the Bell pair

        Returns:
            List of operations to apply
        """
        b1, b0 = message
        ops = []

        # Apply X if b0 = 1 (bit flip)
        if b0 == 1:
            ops.append(cirq.X(qubit))

        # Apply Z if b1 = 1 (phase flip)
        if b1 == 1:
            ops.append(cirq.Z(qubit))

        return ops

    def decode_circuit(
        self,
        alice_qubit: cirq.LineQubit,
        bob_qubit: cirq.LineQubit
    ) -> list[cirq.Operation]:
        """
        Create decoding operations for Bob.

        Bob applies CNOT and H to reverse the Bell state creation,
        then measures both qubits to recover the message.

        Args:
            alice_qubit: Alice's qubit (received from Alice)
            bob_qubit: Bob's qubit (kept from Bell pair creation)

        Returns:
            List of decoding operations
        """
        return [
            cirq.CNOT(alice_qubit, bob_qubit),
            cirq.H(alice_qubit),
            cirq.measure(alice_qubit, key='b1'),
            cirq.measure(bob_qubit, key='b0')
        ]

    def send_message(self, message: tuple[int, int]) -> SuperdenseResult:
        """
        Send a single 2-bit message using superdense coding.

        Args:
            message: Tuple of (bit1, bit0) to send

        Returns:
            SuperdenseResult with the transmission outcome
        """
        return self.run([message])

    def run(
        self,
        messages: list[tuple[int, int]] | None = None,
        num_messages: int = 10
    ) -> SuperdenseResult:
        """
        Run superdense coding protocol for multiple messages.

        Args:
            messages: List of 2-bit messages to send. If None, generates random messages.
            num_messages: Number of random messages to generate if messages is None.

        Returns:
            SuperdenseResult with all transmission outcomes
        """
        if messages is None:
            messages = [
                (self._rng.randint(0, 1), self._rng.randint(0, 1))
                for _ in range(num_messages)
            ]

        decoded_messages = []

        for message in messages:
            # Create qubits for this transmission
            alice_qubit = cirq.LineQubit(0)
            bob_qubit = cirq.LineQubit(1)

            # Build the full circuit
            circuit = cirq.Circuit()

            # Step 1: Create Bell pair
            circuit += self.create_bell_pair(alice_qubit, bob_qubit)

            # Step 2: Alice encodes her message
            circuit.append(self.encode_message(message, alice_qubit))

            # Step 3: (Transmission happens - implicit in simulation)

            # Step 4: Bob decodes
            circuit.append(self.decode_circuit(alice_qubit, bob_qubit))

            # Run the circuit
            result = self._simulator.run(circuit, repetitions=1)

            # Extract decoded message
            b1 = int(result.measurements['b1'][0, 0])
            b0 = int(result.measurements['b0'][0, 0])
            decoded_messages.append((b1, b0))

        # Calculate success rate
        successful = sum(
            1 for orig, decoded in zip(messages, decoded_messages)
            if orig == decoded
        )
        success_rate = successful / len(messages) if messages else 0.0

        return SuperdenseResult(
            original_messages=messages,
            decoded_messages=decoded_messages,
            num_transmissions=len(messages),
            successful=successful,
            success_rate=success_rate
        )

    def demonstrate(self) -> None:
        """
        Run a demonstration of superdense coding.

        Shows all four possible 2-bit messages being transmitted
        and decoded successfully.
        """
        print("=" * 60)
        print("SUPERDENSE CODING DEMONSTRATION")
        print("=" * 60)
        print("\nTransmitting 2 classical bits using 1 qubit!")
        print("Pre-shared entanglement: Bell pair |Φ+⟩ = (|00⟩ + |11⟩)/√2")

        print("\n" + "─" * 60)
        print("ENCODING SCHEME")
        print("─" * 60)
        print("Message  │ Alice's Gate │ Bell State")
        print("─────────┼──────────────┼────────────")
        print("  00     │      I       │    |Φ+⟩")
        print("  01     │      X       │    |Ψ+⟩")
        print("  10     │      Z       │    |Φ-⟩")
        print("  11     │     XZ       │    |Ψ-⟩")

        print("\n" + "─" * 60)
        print("TRANSMITTING ALL FOUR MESSAGES")
        print("─" * 60)

        all_messages = [(0, 0), (0, 1), (1, 0), (1, 1)]
        result = self.run(all_messages)

        for orig, decoded in zip(result.original_messages, result.decoded_messages):
            status = "✓" if orig == decoded else "✗"
            gate = self._get_gate_name(orig)
            print(f"  Sent: {orig[0]}{orig[1]}  │ Gate: {gate:>2} │ "
                  f"Received: {decoded[0]}{decoded[1]}  {status}")

        print("\n" + "─" * 60)
        print("MULTIPLE RANDOM MESSAGES")
        print("─" * 60)

        random_result = self.run(num_messages=20)
        print(f"Transmitted {random_result.num_transmissions} random 2-bit messages")
        print(f"Successful decodes: {random_result.successful}")
        print(f"Success rate: {random_result.success_rate:.0%}")

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print("• 1 qubit transmitted → 2 classical bits received")
        print("• This is the maximum allowed by quantum mechanics!")
        print("• Requires pre-shared entanglement (Bell pair)")
        print("=" * 60)

    def _get_gate_name(self, message: tuple[int, int]) -> str:
        """Get the gate name for a message."""
        b1, b0 = message
        if b1 == 0 and b0 == 0:
            return "I"
        elif b1 == 0 and b0 == 1:
            return "X"
        elif b1 == 1 and b0 == 0:
            return "Z"
        else:
            return "XZ"

    def get_circuit(self, message: tuple[int, int]) -> cirq.Circuit:
        """
        Get the full circuit for a given message (for visualization).

        Args:
            message: The 2-bit message to encode

        Returns:
            The complete superdense coding circuit
        """
        alice_qubit = cirq.LineQubit(0)
        bob_qubit = cirq.LineQubit(1)

        circuit = cirq.Circuit()
        circuit += self.create_bell_pair(alice_qubit, bob_qubit)
        circuit.append(self.encode_message(message, alice_qubit))
        circuit.append(self.decode_circuit(alice_qubit, bob_qubit))

        return circuit
