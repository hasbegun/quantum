# Post-Quantum Digital Signature Algorithms (DSA)

## What This Project Does

This project provides a **pure Python implementation** of two NIST-standardized post-quantum digital signature algorithms:

- **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm
- **SLH-DSA (FIPS 205)** - Stateless Hash-Based Digital Signature Algorithm

### What is a Digital Signature?

A digital signature is the electronic equivalent of a handwritten signature. It provides:

1. **Authentication** - Proves who signed the message
2. **Integrity** - Proves the message wasn't altered
3. **Non-repudiation** - The signer cannot deny signing

```
Signing:    Message + Secret Key  →  Signature
Verifying:  Message + Signature + Public Key  →  Valid/Invalid
```

### Why "Post-Quantum"?

Current digital signatures (RSA, ECDSA) can be broken by quantum computers using Shor's algorithm. Post-quantum algorithms are designed to resist attacks from both classical and quantum computers.

| Algorithm | Basis | Quantum-Safe |
|-----------|-------|--------------|
| RSA | Integer factorization | No |
| ECDSA | Elliptic curves | No |
| **ML-DSA** | Lattice problems | **Yes** |
| **SLH-DSA** | Hash functions | **Yes** |

---

## What This Project Demonstrates

### 1. Two Different Security Approaches

**ML-DSA (Lattice-Based)**
- Security based on the hardness of lattice problems (Module-LWE)
- Fast signing and verification
- Smaller signatures (~2.4 KB)
- Larger public keys (~1.3 KB)

**SLH-DSA (Hash-Based)**
- Security based only on hash function properties
- Slower but mathematically simpler
- Larger signatures (~17 KB)
- Tiny public keys (32 bytes)

### 2. Complete NIST Standard Implementation

This project implements the full FIPS 204 and FIPS 205 specifications:

- All parameter sets (ML-DSA-44/65/87, SLH-DSA-128/192/256)
- Deterministic and randomized signing modes
- Context strings for domain separation
- Pre-hash mode for large messages

### 3. Practical Cryptographic Patterns

The examples show real-world usage patterns:
- API request authentication
- Document signing workflows
- Performance/size trade-offs

---

## Application Examples

### Example 1: API Authentication (ML-DSA)

**Use Case**: Authenticate API requests between services

**Why ML-DSA?** Fast signing, small signatures - ideal for high-frequency requests

```python
from dsa import MLDSA44

# Server generates keypair, shares public key
dsa = MLDSA44()
pk, sk = dsa.keygen()

# Client signs each API request
request_data = b"GET /api/users?id=123"
signature = dsa.sign(sk, request_data)

# Server verifies the request
if dsa.verify(pk, request_data, signature):
    print("Request authenticated")
```

**Run the full example:**
```bash
make demo-api
```

### Example 2: Document Signing (SLH-DSA)

**Use Case**: Sign legal documents, contracts, certificates

**Why SLH-DSA?** Maximum security confidence for long-term validity

```python
from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f

# Generate signing keys
params = SLH_DSA_SHAKE_128f
sk, pk = slh_keygen(params)

# Sign an important document
document = b"Contract: I agree to pay $1000..."
signature = slh_sign(params, document, sk)

# Anyone can verify with the public key
valid = slh_verify(params, document, signature, pk)
print(f"Signature valid: {valid}")
```

**Run the full example:**
```bash
make demo-document
```

### Example 3: Algorithm Comparison

**Use Case**: Understand the trade-offs between algorithms

```bash
make demo-compare
```

**Output:**
```
Algorithm Comparison Results
============================

                    ML-DSA-44    SLH-DSA-128f
Public Key Size     1,312 B      32 B
Secret Key Size     2,560 B      64 B
Signature Size      2,420 B      17,088 B
Sign Time           ~1 ms        ~50 ms
Verify Time         ~0.5 ms      ~5 ms
```

### When to Use Each Algorithm

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| API authentication | ML-DSA | Speed, small signatures |
| Real-time messaging | ML-DSA | Low latency |
| Blockchain transactions | ML-DSA | Bandwidth efficiency |
| Root CA certificates | SLH-DSA | Long-term security |
| Legal documents | SLH-DSA | Conservative security |
| Firmware signing | SLH-DSA | Decades of validity |

---

## How to Run Tests

### Prerequisites

- Docker installed and running
- Make (optional, for convenience commands)

### Run All Tests

```bash
cd /Users/innox/projects/q/dsa

# Using Make (recommended)
make test

# Or using Docker directly
docker build -t dsa .
docker run --rm dsa python -m pytest tests/ -v
```

**Expected output:**
```
tests/test_mldsa.py::test_keygen_deterministic PASSED
tests/test_mldsa.py::test_sign_verify_basic PASSED
...
tests/test_slhdsa.py::test_keygen_produces_valid_keys PASSED
tests/test_slhdsa.py::test_sign_verify_roundtrip PASSED
...

==================== 40 passed ====================
```

### Run ML-DSA Tests Only

```bash
make test-mldsa
```

Tests include:
- Key generation (deterministic and random)
- Sign/verify round-trip
- Context string handling
- Invalid signature rejection
- Wrong key rejection
- All parameter sets (ML-DSA-44, 65, 87)

### Run SLH-DSA Tests Only

```bash
make test-slhdsa
```

Tests include:
- Key generation validity
- Sign/verify for all parameter sets
- Deterministic vs randomized signing
- Message modification detection
- Signature size verification
- WOTS+, XMSS, FORS component tests

### Run Tests with Live Code Changes

```bash
make dev
```

This mounts your local source code into the container, so you can edit files and re-run tests without rebuilding.

### Interactive Python Shell

```bash
make shell
```

Then try:
```python
>>> from dsa import MLDSA44, slh_keygen, SLH_DSA_SHAKE_128f
>>> dsa = MLDSA44()
>>> pk, sk = dsa.keygen()
>>> len(pk)
1312
```

---

## Project Structure

```
dsa/
├── src/dsa/
│   ├── __init__.py          # Unified API exports
│   ├── mldsa/               # ML-DSA implementation
│   │   ├── mldsa.py         # Main MLDSA class
│   │   ├── params.py        # Parameter sets (44, 65, 87)
│   │   ├── ntt.py           # Number Theoretic Transform
│   │   ├── poly.py          # Polynomial operations
│   │   ├── encoding.py      # Bit packing/unpacking
│   │   └── sampling.py      # Rejection sampling
│   └── slhdsa/              # SLH-DSA implementation
│       ├── slh_dsa.py       # Main sign/verify functions
│       ├── parameters.py    # All 12 parameter sets
│       ├── wots.py          # WOTS+ one-time signatures
│       ├── xmss.py          # XMSS Merkle trees
│       ├── fors.py          # FORS few-time signatures
│       ├── hypertree.py     # Hypertree structure
│       └── address.py       # ADRS address scheme
├── tests/
│   ├── test_mldsa.py        # 18 ML-DSA tests
│   └── test_slhdsa.py       # 22 SLH-DSA tests
├── examples/
│   ├── api_authentication.py
│   ├── document_signing.py
│   └── comparison.py
├── Dockerfile
├── Makefile
├── docker-compose.yml
└── pyproject.toml
```

---

## Quick Reference

### ML-DSA API

```python
from dsa import MLDSA44, MLDSA65, MLDSA87

dsa = MLDSA44()  # or MLDSA65(), MLDSA87()

# Key generation
pk, sk = dsa.keygen()
pk, sk = dsa.keygen(seed=bytes(32))  # Deterministic

# Signing
sig = dsa.sign(sk, message)
sig = dsa.sign(sk, message, ctx=b"app-context")
sig = dsa.sign(sk, message, deterministic=True)

# Verification
valid = dsa.verify(pk, message, sig)
valid = dsa.verify(pk, message, sig, ctx=b"app-context")
```

### SLH-DSA API

```python
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_256f
)

# Key generation
sk, pk = slh_keygen(SLH_DSA_SHAKE_128f)

# Signing
sig = slh_sign(params, message, sk)
sig = slh_sign(params, message, sk, ctx=b"context")
sig = slh_sign(params, message, sk, randomize=False)

# Verification
valid = slh_verify(params, message, sig, pk)
```

---

## Make Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make build` | Build Docker image |
| `make test` | Run all 40 tests |
| `make test-mldsa` | Run ML-DSA tests only |
| `make test-slhdsa` | Run SLH-DSA tests only |
| `make dev` | Run tests with mounted source |
| `make shell` | Interactive Python shell |
| `make demo-api` | API authentication example |
| `make demo-document` | Document signing example |
| `make demo-compare` | Algorithm comparison |
| `make clean` | Remove Docker resources |

---

## Security Notice

This is a **reference implementation** for educational purposes. For production use:

- Use NIST-certified cryptographic libraries
- Store secret keys in Hardware Security Modules (HSMs)
- Follow your organization's key management policies
- Keep keys separate from signed data

---

## References

- [NIST FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [NIST FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

## License

MIT License
