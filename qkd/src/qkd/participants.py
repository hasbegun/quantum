"""Participants in the BB84 protocol: Alice, Bob, and Eve."""

from enum import Enum
from dataclasses import dataclass, field
import random

import cirq
import numpy as np


class Basis(Enum):
    """Measurement basis for BB84 protocol."""
    Z = "Z"  # Computational basis: |0⟩, |1⟩
    X = "X"  # Hadamard basis: |+⟩, |−⟩


@dataclass
class Alice:
    """
    Alice: The sender in BB84 protocol.

    Alice generates random bits, chooses random bases, and encodes
    qubits to send to Bob through the quantum channel.
    """
    num_bits: int
    seed: int | None = None

    bits: list[int] = field(default_factory=list, init=False)
    bases: list[Basis] = field(default_factory=list, init=False)
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def generate_bits(self) -> list[int]:
        """Generate random bits to encode."""
        self.bits = [self._rng.randint(0, 1) for _ in range(self.num_bits)]
        return self.bits

    def choose_bases(self) -> list[Basis]:
        """Randomly choose basis (Z or X) for each bit."""
        self.bases = [self._rng.choice([Basis.Z, Basis.X]) for _ in range(self.num_bits)]
        return self.bases

    def encode_qubit(self, bit: int, basis: Basis, qubit: cirq.LineQubit) -> cirq.Circuit:
        """
        Encode a single bit in the given basis.

        Encoding scheme:
        - Z-basis: |0⟩ for 0, |1⟩ for 1
        - X-basis: |+⟩ for 0, |−⟩ for 1

        Args:
            bit: The bit value (0 or 1)
            basis: The basis to encode in (Z or X)
            qubit: The qubit to use

        Returns:
            Circuit that prepares the encoded state
        """
        circuit = cirq.Circuit()

        if basis == Basis.Z:
            # Z-basis: |0⟩ or |1⟩
            if bit == 1:
                circuit.append(cirq.X(qubit))
        else:
            # X-basis: |+⟩ or |−⟩
            if bit == 1:
                circuit.append(cirq.X(qubit))
            circuit.append(cirq.H(qubit))

        return circuit

    def prepare_qubits(self) -> list[tuple[cirq.Circuit, cirq.LineQubit]]:
        """
        Prepare all qubits for transmission.

        Returns:
            List of (circuit, qubit) tuples ready for transmission
        """
        if not self.bits:
            self.generate_bits()
        if not self.bases:
            self.choose_bases()

        qubits_to_send = []
        for i, (bit, basis) in enumerate(zip(self.bits, self.bases)):
            qubit = cirq.LineQubit(i)
            circuit = self.encode_qubit(bit, basis, qubit)
            qubits_to_send.append((circuit, qubit))

        return qubits_to_send

    def sift_key(self, bob_bases: list[Basis]) -> list[int]:
        """
        Sift the key by keeping only bits where bases matched.

        Args:
            bob_bases: The bases Bob used for measurement

        Returns:
            Sifted key (bits where Alice and Bob used same basis)
        """
        return [
            bit for bit, a_basis, b_basis in zip(self.bits, self.bases, bob_bases)
            if a_basis == b_basis
        ]


@dataclass
class Bob:
    """
    Bob: The receiver in BB84 protocol.

    Bob receives qubits from Alice, chooses random measurement bases,
    and measures the qubits.
    """
    num_bits: int
    seed: int | None = None

    bases: list[Basis] = field(default_factory=list, init=False)
    measurements: list[int] = field(default_factory=list, init=False)
    _rng: random.Random = field(init=False, repr=False)
    _simulator: cirq.Simulator = field(init=False, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)
        self._simulator = cirq.Simulator(seed=self.seed)

    def choose_bases(self) -> list[Basis]:
        """Randomly choose basis (Z or X) for each measurement."""
        self.bases = [self._rng.choice([Basis.Z, Basis.X]) for _ in range(self.num_bits)]
        return self.bases

    def measure_qubit(
        self,
        circuit: cirq.Circuit,
        qubit: cirq.LineQubit,
        basis: Basis
    ) -> int:
        """
        Measure a qubit in the specified basis.

        Args:
            circuit: The circuit preparing the qubit state
            qubit: The qubit to measure
            basis: The basis to measure in

        Returns:
            Measurement result (0 or 1)
        """
        measure_circuit = circuit.copy()

        # Apply H before measurement for X-basis
        if basis == Basis.X:
            measure_circuit.append(cirq.H(qubit))

        measure_circuit.append(cirq.measure(qubit, key="m"))

        result = self._simulator.run(measure_circuit, repetitions=1)
        return int(result.measurements["m"][0, 0])

    def receive_and_measure(
        self,
        qubits: list[tuple[cirq.Circuit, cirq.LineQubit]]
    ) -> list[int]:
        """
        Receive qubits and measure them.

        Args:
            qubits: List of (circuit, qubit) tuples from Alice

        Returns:
            List of measurement results
        """
        if not self.bases:
            self.choose_bases()

        self.measurements = []
        for (circuit, qubit), basis in zip(qubits, self.bases):
            result = self.measure_qubit(circuit, qubit, basis)
            self.measurements.append(result)

        return self.measurements

    def sift_key(self, alice_bases: list[Basis]) -> list[int]:
        """
        Sift the key by keeping only bits where bases matched.

        Args:
            alice_bases: The bases Alice used for encoding

        Returns:
            Sifted key (measurements where Alice and Bob used same basis)
        """
        return [
            measurement
            for measurement, a_basis, b_basis in zip(self.measurements, alice_bases, self.bases)
            if a_basis == b_basis
        ]


@dataclass
class Eve:
    """
    Eve: The eavesdropper in BB84 protocol.

    Eve intercepts qubits, measures them (guessing the basis),
    and re-sends new qubits based on her measurement results.
    This inevitably introduces errors that Alice and Bob can detect.
    """
    seed: int | None = None

    intercepted_bits: list[int] = field(default_factory=list, init=False)
    guessed_bases: list[Basis] = field(default_factory=list, init=False)
    _rng: random.Random = field(init=False, repr=False)
    _simulator: cirq.Simulator = field(init=False, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)
        self._simulator = cirq.Simulator(seed=self.seed)

    def intercept(
        self,
        circuit: cirq.Circuit,
        qubit: cirq.LineQubit
    ) -> tuple[cirq.Circuit, cirq.LineQubit]:
        """
        Intercept a qubit: measure it and re-send a new qubit.

        Eve's attack:
        1. Guess a random basis
        2. Measure in that basis
        3. Prepare a new qubit in the same state she measured

        This works perfectly if Eve guesses the correct basis,
        but introduces ~50% error rate when she guesses wrong.

        Args:
            circuit: The circuit preparing the qubit
            qubit: The qubit being transmitted

        Returns:
            New (circuit, qubit) tuple to forward to Bob
        """
        # Eve guesses a random basis
        eve_basis = self._rng.choice([Basis.Z, Basis.X])
        self.guessed_bases.append(eve_basis)

        # Measure in guessed basis
        measure_circuit = circuit.copy()
        if eve_basis == Basis.X:
            measure_circuit.append(cirq.H(qubit))
        measure_circuit.append(cirq.measure(qubit, key="eve"))

        result = self._simulator.run(measure_circuit, repetitions=1)
        eve_bit = int(result.measurements["eve"][0, 0])
        self.intercepted_bits.append(eve_bit)

        # Prepare new qubit with measured value in guessed basis
        new_qubit = cirq.LineQubit(qubit.x)  # Same qubit index
        new_circuit = cirq.Circuit()

        if eve_basis == Basis.Z:
            if eve_bit == 1:
                new_circuit.append(cirq.X(new_qubit))
        else:
            if eve_bit == 1:
                new_circuit.append(cirq.X(new_qubit))
            new_circuit.append(cirq.H(new_qubit))

        return new_circuit, new_qubit

    def intercept_all(
        self,
        qubits: list[tuple[cirq.Circuit, cirq.LineQubit]]
    ) -> list[tuple[cirq.Circuit, cirq.LineQubit]]:
        """
        Intercept all qubits in transmission.

        Args:
            qubits: List of (circuit, qubit) tuples from Alice

        Returns:
            List of intercepted/re-prepared (circuit, qubit) tuples
        """
        self.intercepted_bits = []
        self.guessed_bases = []

        return [self.intercept(circuit, qubit) for circuit, qubit in qubits]
