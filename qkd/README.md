# Quantum Cryptography Demonstrations

This project demonstrates two critical aspects of quantum computing and cryptography:

1. **Shor's Algorithm Threat** - How quantum computers break RSA and ECDSA
2. **Quantum Key Distribution (BB84)** - How quantum mechanics enables secure key exchange

## Why This Matters

Current cryptography (RSA, ECDSA) protects:
- All HTTPS web traffic
- Bitcoin and cryptocurrencies ($2+ trillion)
- Banking and financial systems
- Government communications
- Code signing and software updates

**All of this will be broken by quantum computers running Shor's algorithm.**

This project demonstrates:
- Exactly HOW Shor's algorithm breaks these systems
- WHY quantum computers pose an existential threat
- WHAT can be done (post-quantum cryptography, QKD)

---

## Quick Start

```bash
cd /Users/innox/projects/q/qkd

# See all available demos
make help

# Run Shor's algorithm demos
make demo-rsa       # Break RSA encryption
make demo-ecdsa     # Break ECDSA (Bitcoin/Ethereum signatures)
make demo-threat    # Complete quantum threat overview

# Run QKD demo
make demo-qkd       # BB84 quantum key distribution
```

---

## Part 1: Shor's Algorithm Threat

### What is Shor's Algorithm?

Published by Peter Shor in 1994, this quantum algorithm efficiently solves two problems believed to be hard for classical computers:

| Problem | Breaks | Classical Time | Quantum Time |
|---------|--------|----------------|--------------|
| Integer Factorization | RSA | Exponential | Polynomial |
| Discrete Logarithm | ECDSA, DH | Exponential | Polynomial |

### Breaking RSA

RSA security relies on the difficulty of factoring `N = p × q`:

```
Classical Computer:
  - Try each possible factor
  - For 2048-bit N: ~10^600 years

Quantum Computer (Shor's):
  - Use superposition to test all factors at once
  - Extract answer with Quantum Fourier Transform
  - For 2048-bit N: hours to days
```

**Demo:**
```bash
make demo-rsa
```

Output shows:
1. RSA key generation
2. Encryption of secret message
3. Classical factoring attempt (fails)
4. Shor's algorithm (succeeds)
5. Attacker decrypts the secret

### Breaking ECDSA

ECDSA (used in Bitcoin, Ethereum, TLS) relies on the discrete log problem:

```
Given: Public key P = k × G (point on elliptic curve)
Find:  Private key k

Classical: ~2^128 operations (infeasible)
Quantum:   ~2^24 operations (trivial)
```

**Demo:**
```bash
make demo-ecdsa
```

Output shows:
1. ECDSA key generation (like a Bitcoin wallet)
2. Signing a transaction
3. Quantum attack extracting private key
4. Attacker forging transactions

### Cryptocurrency Impact

```
Vulnerable Bitcoin:
- ~4 million BTC with exposed public keys
- Current value: ~$250 billion
- Includes Satoshi's ~1 million BTC

Attack Vector:
1. Attacker collects public keys from blockchain (public information)
2. Quantum computer extracts private keys
3. Attacker signs transactions stealing all funds
```

### Timeline

| Year | Qubits | Threat Level |
|------|--------|--------------|
| 2024 | ~1,000 | No cryptographic threat |
| 2030 | ~100,000 | Early attacks possible |
| 2040 | ~1M+ | Full RSA/ECDSA break |

**"Harvest Now, Decrypt Later"**: Adversaries may store encrypted data today to decrypt when quantum computers arrive.

---

## Part 2: Quantum Key Distribution (BB84)

### The Solution: Physics-Based Security

Unlike RSA/ECDSA (broken by math), QKD security is based on **laws of physics**:

- **No-Cloning Theorem**: Cannot copy unknown quantum states
- **Measurement Disturbance**: Measuring changes the state
- **Eavesdropping Detection**: Any interception is detectable

### How BB84 Works

```
1. QUANTUM TRANSMISSION
   Alice ──── qubits ────> Bob

   Alice: Random bits, random bases, encode in qubits
   Bob:   Random bases, measure qubits

2. BASIS RECONCILIATION (public channel)
   Alice <──── "I used Z,X,X,Z..." ────> Bob

   Keep only bits where bases matched (~50%)

3. EAVESDROPPER DETECTION
   Compare random sample of key bits

   No Eve:   ~0% errors
   Eve present: ~25% errors → Abort!
```

**Demo:**
```bash
make demo-qkd
```

---

## Project Structure

```
qkd/
├── src/
│   ├── qkd/                    # Quantum Key Distribution
│   │   ├── bb84.py             # BB84 protocol
│   │   ├── participants.py     # Alice, Bob, Eve
│   │   └── analysis.py         # Error analysis
│   │
│   └── shors_threat/           # Shor's Algorithm Demos
│       ├── shors_algorithm.py  # Core Shor's implementation
│       ├── rsa_attack.py       # RSA breaking demo
│       └── ecdsa_attack.py     # ECDSA breaking demo
│
├── examples/
│   ├── break_rsa.py            # RSA attack walkthrough
│   ├── break_ecdsa.py          # ECDSA attack walkthrough
│   └── quantum_threat_overview.py  # Complete overview
│
├── tests/
│   ├── test_bb84.py            # QKD tests
│   └── test_shors.py           # Shor's algorithm tests
│
├── docs/
│   └── QKD_GUIDE.md            # Detailed BB84 documentation
│
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## Running Tests

```bash
# All tests
make test

# Shor's algorithm tests only
make test-shors

# QKD tests only
make test-qkd
```

---

## Make Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all commands |
| `make demo-rsa` | Break RSA with Shor's algorithm |
| `make demo-ecdsa` | Break ECDSA with Shor's algorithm |
| `make demo-threat` | Complete quantum threat overview |
| `make demo-qkd` | BB84 quantum key distribution |
| `make test` | Run all tests |
| `make shell` | Interactive Python shell |
| `make clean` | Remove Docker resources |

---

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC LANDSCAPE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   CLASSICAL ERA                    QUANTUM ERA                          │
│   (Today)                          (Coming)                             │
│                                                                         │
│   ┌─────────────┐                  ┌─────────────┐                      │
│   │ RSA, ECDSA  │ ──── BROKEN ───> │   SHOR'S    │                      │
│   │ (math-hard) │      BY          │  ALGORITHM  │                      │
│   └─────────────┘                  └─────────────┘                      │
│                                                                         │
│   ┌─────────────┐                  ┌─────────────┐                      │
│   │  ML-DSA     │ ──── SECURE ───> │   QUANTUM   │                      │
│   │  SLH-DSA    │    AGAINST       │  COMPUTERS  │                      │
│   │ (lattice)   │                  │             │                      │
│   └─────────────┘                  └─────────────┘                      │
│                                                                         │
│   ┌─────────────┐                  ┌─────────────┐                      │
│   │    QKD      │ ──── USES ─────> │   QUANTUM   │                      │
│   │  (BB84)     │    PHYSICS       │   MECHANICS │                      │
│   └─────────────┘                  └─────────────┘                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What Should You Do?

### If You're a Developer:
1. Learn about post-quantum cryptography
2. Test ML-DSA, SLH-DSA implementations (see `../dsa/`)
3. Plan migration from RSA/ECDSA

### If You Hold Cryptocurrency:
1. Never reuse addresses (exposes public key)
2. Support post-quantum protocol upgrades
3. Consider moving to fresh addresses

### If You're an Organization:
1. Inventory systems using RSA/ECDSA
2. Prioritize data with long secrecy requirements
3. Begin migration planning NOW

---

## References

### Shor's Algorithm
- Shor, P. (1994). "Algorithms for Quantum Computation"
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

### Quantum Key Distribution
- Bennett & Brassard (1984). "Quantum Cryptography"
- [BB84 Protocol Explanation](docs/QKD_GUIDE.md)

### Post-Quantum Standards
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/publications/detail/fips/205/final)

---

## License

MIT License
