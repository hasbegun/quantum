#!/usr/bin/env python3
"""
Post-Quantum Key Generation Script

Generates ML-DSA or SLH-DSA key pairs and saves them to files.

Usage:
    python generate_keys.py [algorithm] [output_dir]

Examples:
    python generate_keys.py mldsa44 /keys
    python generate_keys.py mldsa65 /keys
    python generate_keys.py slh-shake-128f /keys
"""

import os
import sys
import json
from datetime import datetime, timezone

# Output directory (can be overridden by command line)
OUTPUT_DIR = "/keys"


def generate_mldsa_keys(level: str, output_dir: str):
    """Generate ML-DSA key pair."""
    from dsa import MLDSA44, MLDSA65, MLDSA87

    algorithms = {
        "mldsa44": MLDSA44,
        "mldsa65": MLDSA65,
        "mldsa87": MLDSA87,
    }

    if level not in algorithms:
        print(f"Unknown ML-DSA level: {level}")
        print(f"Available: {', '.join(algorithms.keys())}")
        sys.exit(1)

    dsa = algorithms[level]()
    public_key, secret_key = dsa.keygen()

    # Save keys
    prefix = os.path.join(output_dir, level)

    with open(f"{prefix}_public.key", "wb") as f:
        f.write(public_key)

    with open(f"{prefix}_secret.key", "wb") as f:
        f.write(secret_key)

    # Save metadata
    metadata = {
        "algorithm": level.upper(),
        "type": "ML-DSA (FIPS 204)",
        "created": datetime.now(timezone.utc).isoformat(),
        "public_key_size": len(public_key),
        "secret_key_size": len(secret_key),
        "public_key_file": f"{level}_public.key",
        "secret_key_file": f"{level}_secret.key",
    }

    with open(f"{prefix}_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    return public_key, secret_key, metadata


def generate_slhdsa_keys(variant: str, output_dir: str):
    """Generate SLH-DSA key pair."""
    from dsa import slh_keygen
    from dsa.slhdsa.parameters import PARAMETER_SETS

    # Map friendly names to parameter sets
    variant_map = {
        "slh-shake-128f": "SLH-DSA-SHAKE-128f",
        "slh-shake-128s": "SLH-DSA-SHAKE-128s",
        "slh-shake-192f": "SLH-DSA-SHAKE-192f",
        "slh-shake-192s": "SLH-DSA-SHAKE-192s",
        "slh-shake-256f": "SLH-DSA-SHAKE-256f",
        "slh-shake-256s": "SLH-DSA-SHAKE-256s",
        "slh-sha2-128f": "SLH-DSA-SHA2-128f",
        "slh-sha2-128s": "SLH-DSA-SHA2-128s",
        "slh-sha2-192f": "SLH-DSA-SHA2-192f",
        "slh-sha2-192s": "SLH-DSA-SHA2-192s",
        "slh-sha2-256f": "SLH-DSA-SHA2-256f",
        "slh-sha2-256s": "SLH-DSA-SHA2-256s",
    }

    if variant not in variant_map:
        print(f"Unknown SLH-DSA variant: {variant}")
        print(f"Available: {', '.join(variant_map.keys())}")
        sys.exit(1)

    param_name = variant_map[variant]
    params = PARAMETER_SETS[param_name]

    secret_key, public_key = slh_keygen(params)

    # Save keys
    safe_name = variant.replace("-", "_")
    prefix = os.path.join(output_dir, safe_name)

    with open(f"{prefix}_public.key", "wb") as f:
        f.write(public_key)

    with open(f"{prefix}_secret.key", "wb") as f:
        f.write(secret_key)

    # Save metadata
    metadata = {
        "algorithm": param_name,
        "type": "SLH-DSA (FIPS 205)",
        "created": datetime.now(timezone.utc).isoformat(),
        "public_key_size": len(public_key),
        "secret_key_size": len(secret_key),
        "public_key_file": f"{safe_name}_public.key",
        "secret_key_file": f"{safe_name}_secret.key",
    }

    with open(f"{prefix}_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    return public_key, secret_key, metadata


def main():
    if len(sys.argv) < 2:
        print("Post-Quantum Key Generator")
        print("=" * 50)
        print("\nUsage: python generate_keys.py <algorithm> [output_dir]")
        print("\nML-DSA algorithms (fast, smaller signatures):")
        print("  mldsa44          - Category 1 (128-bit security)")
        print("  mldsa65          - Category 3 (192-bit security)")
        print("  mldsa87          - Category 5 (256-bit security)")
        print("\nSLH-DSA algorithms (hash-based, conservative):")
        print("  slh-shake-128f   - SHAKE, fast variant")
        print("  slh-shake-128s   - SHAKE, small signatures")
        print("  slh-shake-192f   - SHAKE, Category 3, fast")
        print("  slh-shake-256f   - SHAKE, Category 5, fast")
        print("  slh-sha2-128f    - SHA2, fast variant")
        print("  slh-sha2-128s    - SHA2, small signatures")
        print("\nExamples:")
        print("  python generate_keys.py mldsa44 /keys")
        print("  python generate_keys.py slh-shake-128f /keys")
        sys.exit(0)

    algorithm = sys.argv[1].lower()
    output_dir = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_DIR

    os.makedirs(output_dir, exist_ok=True)

    print(f"Generating {algorithm.upper()} keys...")
    print(f"Output directory: {output_dir}")
    print()

    if algorithm.startswith("mldsa"):
        pk, sk, meta = generate_mldsa_keys(algorithm, output_dir)
    elif algorithm.startswith("slh-"):
        pk, sk, meta = generate_slhdsa_keys(algorithm, output_dir)
    else:
        print(f"Unknown algorithm: {algorithm}")
        print("Use 'mldsa44', 'mldsa65', 'mldsa87', or 'slh-shake-128f', etc.")
        sys.exit(1)

    print("Keys generated successfully!")
    print()
    print(f"  Algorithm:    {meta['algorithm']}")
    print(f"  Type:         {meta['type']}")
    print(f"  Public Key:   {meta['public_key_size']} bytes -> {meta['public_key_file']}")
    print(f"  Secret Key:   {meta['secret_key_size']} bytes -> {meta['secret_key_file']}")
    print(f"  Metadata:     {meta['public_key_file'].replace('_public.key', '_metadata.json')}")
    print()
    print("WARNING: Keep your secret key secure!")


if __name__ == "__main__":
    main()
