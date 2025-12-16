"""BB84 Quantum Key Distribution Protocol implementation."""

from dataclasses import dataclass, field
from typing import Optional

from qkd.participants import Alice, Bob, Eve, Basis
from qkd.analysis import (
    check_for_eavesdropper,
    calculate_error_rate,
    key_to_hex,
    KeyAnalysis
)


@dataclass
class BB84Result:
    """Results from a BB84 protocol run."""
    # Keys
    alice_sifted_key: list[int]
    bob_sifted_key: list[int]
    final_key: list[int]

    # Statistics
    initial_bits: int
    sifted_key_length: int
    final_key_length: int
    sifting_efficiency: float
    error_rate: float

    # Security
    eve_present: bool
    eve_detected: bool
    analysis: KeyAnalysis

    # Detailed data (optional)
    alice_bits: list[int] = field(default_factory=list)
    alice_bases: list[Basis] = field(default_factory=list)
    bob_bases: list[Basis] = field(default_factory=list)
    bob_measurements: list[int] = field(default_factory=list)

    def __str__(self) -> str:
        eve_status = "YES" if self.eve_present else "NO"
        detected_status = "YES" if self.eve_detected else "NO"

        return (
            f"BB84 Protocol Results\n"
            f"{'='*50}\n"
            f"Initial bits transmitted: {self.initial_bits}\n"
            f"Sifted key length: {self.sifted_key_length}\n"
            f"Sifting efficiency: {self.sifting_efficiency:.1%}\n"
            f"Final key length: {self.final_key_length}\n"
            f"Error rate: {self.error_rate:.2%}\n"
            f"{'='*50}\n"
            f"Eavesdropper present: {eve_status}\n"
            f"Eavesdropper detected: {detected_status}\n"
            f"{'='*50}\n"
            f"Final key (hex): {key_to_hex(self.final_key)[:32]}..."
        )

    @property
    def secure(self) -> bool:
        """Check if the key exchange was secure."""
        return not self.eve_detected


@dataclass
class BB84Protocol:
    """
    BB84 Quantum Key Distribution Protocol.

    This class orchestrates the full BB84 protocol between Alice and Bob,
    with optional eavesdropping by Eve.

    Example:
        >>> protocol = BB84Protocol(num_bits=1000)
        >>> result = protocol.run(eavesdropper=False)
        >>> print(f"Key length: {result.final_key_length}")
        >>> print(f"Error rate: {result.error_rate:.2%}")

        >>> # With eavesdropper
        >>> result_eve = protocol.run(eavesdropper=True)
        >>> print(f"Eve detected: {result_eve.eve_detected}")
    """
    num_bits: int
    sample_fraction: float = 0.1
    detection_threshold: float = 0.11
    seed: int | None = None

    def run(
        self,
        eavesdropper: bool = False,
        verbose: bool = False
    ) -> BB84Result:
        """
        Run the BB84 protocol.

        Args:
            eavesdropper: If True, Eve intercepts all qubits
            verbose: If True, print progress information

        Returns:
            BB84Result with all protocol data and analysis
        """
        # Initialize participants
        # Use different seeds for each participant for variety
        alice = Alice(self.num_bits, seed=self.seed)
        bob_seed = self.seed + 1 if self.seed else None
        bob = Bob(self.num_bits, seed=bob_seed)

        if eavesdropper:
            eve_seed = self.seed + 2 if self.seed else None
            eve = Eve(seed=eve_seed)

        if verbose:
            print(f"Starting BB84 with {self.num_bits} bits")
            print(f"Eavesdropper: {'YES' if eavesdropper else 'NO'}")

        # Step 1: Alice prepares qubits
        if verbose:
            print("\n[1] Alice generating random bits and bases...")
        alice.generate_bits()
        alice.choose_bases()
        qubits = alice.prepare_qubits()

        if verbose:
            print(f"    Generated {len(alice.bits)} bits")

        # Step 2: Eve intercepts (if present)
        if eavesdropper:
            if verbose:
                print("\n[2] Eve intercepting qubits...")
            qubits = eve.intercept_all(qubits)
            if verbose:
                print(f"    Eve intercepted {len(eve.intercepted_bits)} qubits")

        # Step 3: Bob measures qubits
        if verbose:
            print("\n[3] Bob choosing bases and measuring...")
        bob.choose_bases()
        bob.receive_and_measure(qubits)

        if verbose:
            print(f"    Bob measured {len(bob.measurements)} qubits")

        # Step 4: Basis reconciliation (sifting)
        if verbose:
            print("\n[4] Basis reconciliation (public channel)...")
        alice_sifted = alice.sift_key(bob.bases)
        bob_sifted = bob.sift_key(alice.bases)

        matching_bases = sum(
            1 for a, b in zip(alice.bases, bob.bases) if a == b
        )
        if verbose:
            print(f"    Matching bases: {matching_bases}/{self.num_bits}")
            print(f"    Sifted key length: {len(alice_sifted)}")

        # Step 5: Error checking
        if verbose:
            print("\n[5] Checking for eavesdropper...")

        analysis = check_for_eavesdropper(
            alice_sifted,
            bob_sifted,
            sample_fraction=self.sample_fraction,
            threshold=self.detection_threshold,
            seed=self.seed
        )

        if verbose:
            print(f"    Sample size: {analysis.sample_size}")
            print(f"    Errors found: {analysis.errors}")
            print(f"    Error rate: {analysis.error_rate:.2%}")
            print(f"    Threshold: {self.detection_threshold:.2%}")
            if analysis.eve_detected:
                print("    ⚠️  EAVESDROPPER DETECTED! Key compromised.")
            else:
                print("    ✓ No eavesdropper detected. Key is secure.")

        # Step 6: Extract final key (remove sampled bits)
        # For simplicity, we'll just remove the first sample_size bits
        final_key_length = len(alice_sifted) - analysis.sample_size
        final_key = alice_sifted[analysis.sample_size:]

        # Calculate statistics
        sifting_efficiency = len(alice_sifted) / self.num_bits if self.num_bits > 0 else 0
        error_rate = calculate_error_rate(alice_sifted, bob_sifted)

        return BB84Result(
            alice_sifted_key=alice_sifted,
            bob_sifted_key=bob_sifted,
            final_key=final_key,
            initial_bits=self.num_bits,
            sifted_key_length=len(alice_sifted),
            final_key_length=len(final_key),
            sifting_efficiency=sifting_efficiency,
            error_rate=error_rate,
            eve_present=eavesdropper,
            eve_detected=analysis.eve_detected,
            analysis=analysis,
            alice_bits=alice.bits,
            alice_bases=alice.bases,
            bob_bases=bob.bases,
            bob_measurements=bob.measurements
        )

    def demonstrate(self) -> None:
        """
        Run a demonstration comparing secure vs intercepted key exchange.

        This runs the protocol twice:
        1. Without Eve (should succeed)
        2. With Eve (should detect eavesdropping)
        """
        print("=" * 60)
        print("BB84 QUANTUM KEY DISTRIBUTION DEMONSTRATION")
        print("=" * 60)

        print("\n" + "─" * 60)
        print("SCENARIO 1: Secure Channel (No Eavesdropper)")
        print("─" * 60)
        result_secure = self.run(eavesdropper=False, verbose=True)

        print("\n" + "─" * 60)
        print("SCENARIO 2: Intercepted Channel (Eve Present)")
        print("─" * 60)
        result_eve = self.run(eavesdropper=True, verbose=True)

        print("\n" + "=" * 60)
        print("COMPARISON SUMMARY")
        print("=" * 60)
        print(f"{'Metric':<25} {'No Eve':>15} {'With Eve':>15}")
        print("-" * 60)
        print(f"{'Error Rate':<25} {result_secure.error_rate:>14.2%} {result_eve.error_rate:>14.2%}")
        print(f"{'Eve Detected':<25} {'NO':>15} {'YES' if result_eve.eve_detected else 'NO':>15}")
        print(f"{'Key Secure':<25} {'YES':>15} {'NO' if result_eve.eve_detected else 'YES':>15}")
        print("=" * 60)
