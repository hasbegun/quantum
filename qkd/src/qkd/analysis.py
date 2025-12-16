"""Analysis tools for QKD protocols."""

from dataclasses import dataclass
import random


@dataclass
class KeyAnalysis:
    """Results of key analysis and error checking."""
    alice_sample: list[int]
    bob_sample: list[int]
    errors: int
    sample_size: int
    error_rate: float
    eve_detected: bool
    remaining_key_length: int

    def __str__(self) -> str:
        status = "DETECTED" if self.eve_detected else "NOT DETECTED"
        return (
            f"Key Analysis Results:\n"
            f"  Sample size: {self.sample_size}\n"
            f"  Errors found: {self.errors}\n"
            f"  Error rate: {self.error_rate:.2%}\n"
            f"  Eavesdropper: {status}\n"
            f"  Remaining key bits: {self.remaining_key_length}"
        )


def calculate_error_rate(alice_key: list[int], bob_key: list[int]) -> float:
    """
    Calculate the error rate between two keys.

    Args:
        alice_key: Alice's sifted key
        bob_key: Bob's sifted key

    Returns:
        Error rate as a float between 0 and 1
    """
    if len(alice_key) != len(bob_key):
        raise ValueError("Keys must be the same length")

    if len(alice_key) == 0:
        return 0.0

    errors = sum(a != b for a, b in zip(alice_key, bob_key))
    return errors / len(alice_key)


def check_for_eavesdropper(
    alice_key: list[int],
    bob_key: list[int],
    sample_fraction: float = 0.1,
    threshold: float = 0.11,
    seed: int | None = None
) -> KeyAnalysis:
    """
    Check for eavesdropper by comparing a sample of the keys.

    Alice and Bob sacrifice a portion of their sifted key to check
    for errors. High error rates indicate eavesdropping.

    Args:
        alice_key: Alice's sifted key
        bob_key: Bob's sifted key
        sample_fraction: Fraction of key to use for testing (default 10%)
        threshold: Error rate threshold for detecting Eve (default 11%)
        seed: Random seed for reproducible sampling

    Returns:
        KeyAnalysis with detection results
    """
    if len(alice_key) != len(bob_key):
        raise ValueError("Keys must be the same length")

    rng = random.Random(seed)
    key_length = len(alice_key)
    sample_size = max(1, int(key_length * sample_fraction))

    # Select random indices for sampling
    sample_indices = set(rng.sample(range(key_length), min(sample_size, key_length)))

    # Extract samples
    alice_sample = [alice_key[i] for i in sorted(sample_indices)]
    bob_sample = [bob_key[i] for i in sorted(sample_indices)]

    # Count errors
    errors = sum(a != b for a, b in zip(alice_sample, bob_sample))
    error_rate = errors / len(alice_sample) if alice_sample else 0.0

    # Check threshold
    eve_detected = error_rate > threshold

    # Remaining key (excluding sampled bits)
    remaining_key_length = key_length - len(sample_indices)

    return KeyAnalysis(
        alice_sample=alice_sample,
        bob_sample=bob_sample,
        errors=errors,
        sample_size=len(alice_sample),
        error_rate=error_rate,
        eve_detected=eve_detected,
        remaining_key_length=remaining_key_length
    )


def extract_final_key(
    key: list[int],
    sample_indices: set[int]
) -> list[int]:
    """
    Extract final key by removing sampled bits.

    Args:
        key: The sifted key
        sample_indices: Indices that were used for eavesdropper check

    Returns:
        Final key with sample bits removed
    """
    return [bit for i, bit in enumerate(key) if i not in sample_indices]


def key_to_bytes(key: list[int]) -> bytes:
    """
    Convert a bit list to bytes.

    Args:
        key: List of bits (0s and 1s)

    Returns:
        Bytes representation of the key
    """
    # Pad to multiple of 8
    padded = key + [0] * ((8 - len(key) % 8) % 8)

    result = []
    for i in range(0, len(padded), 8):
        byte_bits = padded[i:i+8]
        byte_val = sum(bit << (7 - j) for j, bit in enumerate(byte_bits))
        result.append(byte_val)

    return bytes(result)


def key_to_hex(key: list[int]) -> str:
    """
    Convert a bit list to hexadecimal string.

    Args:
        key: List of bits (0s and 1s)

    Returns:
        Hexadecimal string representation
    """
    return key_to_bytes(key).hex()
