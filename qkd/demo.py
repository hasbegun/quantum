#!/usr/bin/env python3
"""
Quantum Communication Protocols Demo

This script demonstrates:
1. BB84 Quantum Key Distribution - secure key exchange with eavesdropper detection
2. Superdense Coding - transmitting 2 classical bits using 1 qubit

Run: python demo.py [bb84|superdense|all]
"""

import sys

from qkd import BB84Protocol, SuperdenseCoding
from qkd.analysis import key_to_hex


def demo_bb84():
    """Run BB84 Quantum Key Distribution demo."""
    print("\n" + "#" * 60)
    print("#" + " " * 20 + "BB84 QKD DEMO" + " " * 21 + "#")
    print("#" * 60 + "\n")

    # Create protocol with 500 bits
    protocol = BB84Protocol(
        num_bits=500,
        sample_fraction=0.15,
        detection_threshold=0.11,
        seed=42
    )

    # Run the full demonstration
    protocol.demonstrate()

    # Show detailed key information
    print("\n" + "=" * 60)
    print("DETAILED KEY INFORMATION")
    print("=" * 60)

    result = protocol.run(eavesdropper=False)

    print(f"\nAlice's first 20 bits: {result.alice_bits[:20]}")
    print(f"Alice's first 20 bases: {[b.value for b in result.alice_bases[:20]]}")
    print(f"Bob's first 20 bases:   {[b.value for b in result.bob_bases[:20]]}")
    print(f"Bob's first 20 results: {result.bob_measurements[:20]}")

    matches = [
        "✓" if a == b else "✗"
        for a, b in zip(result.alice_bases[:20], result.bob_bases[:20])
    ]
    print(f"Basis match:            {matches}")

    print(f"\nFinal shared key (first 64 bits as hex): ", end="")
    print(key_to_hex(result.final_key[:64]))


def demo_superdense():
    """Run Superdense Coding demo."""
    print("\n" + "#" * 60)
    print("#" + " " * 16 + "SUPERDENSE CODING DEMO" + " " * 16 + "#")
    print("#" * 60 + "\n")

    sd = SuperdenseCoding(seed=42)
    sd.demonstrate()

    # Show the quantum circuit for message "11"
    print("\n" + "=" * 60)
    print("QUANTUM CIRCUIT FOR MESSAGE (1,1)")
    print("=" * 60)
    circuit = sd.get_circuit((1, 1))
    print(circuit)


def main():
    """Main entry point."""
    # Parse command line argument
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    else:
        mode = "all"

    print("=" * 60)
    print("QUANTUM COMMUNICATION PROTOCOLS")
    print("=" * 60)
    print("\nAvailable demos:")
    print("  - bb84:      Quantum Key Distribution")
    print("  - superdense: Superdense Coding (2 bits via 1 qubit)")
    print("  - all:       Run all demos")
    print(f"\nRunning: {mode}")

    if mode == "bb84":
        demo_bb84()
    elif mode == "superdense":
        demo_superdense()
    elif mode == "all":
        demo_bb84()
        demo_superdense()
    else:
        print(f"\nUnknown mode: {mode}")
        print("Usage: python demo.py [bb84|superdense|all]")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
