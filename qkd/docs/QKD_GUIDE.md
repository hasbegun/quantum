# Quantum Key Distribution (QKD) - Theory & Implementation Guide

## What is QKD?

Quantum Key Distribution is a secure communication method that uses quantum mechanics to generate and distribute cryptographic keys. Unlike classical key exchange (like Diffie-Hellman), QKD's security is based on the **laws of physics**, not computational hardness.

### Why QKD Matters for Security

| Classical Crypto | Quantum Crypto (QKD) |
|------------------|----------------------|
| Security based on math problems (factoring, discrete log) | Security based on physics (no-cloning theorem) |
| Vulnerable to quantum computers (Shor's algorithm) | Immune to quantum computer attacks |
| Eavesdropping undetectable | Eavesdropping **always** detectable |

---

## The BB84 Protocol

BB84 (Bennett-Brassard 1984) was the first QKD protocol. It uses two conjugate bases to encode bits.

### The Two Bases

```
COMPUTATIONAL BASIS (Z):        HADAMARD BASIS (X):
|0⟩ = bit 0                     |+⟩ = (|0⟩ + |1⟩)/√2 = bit 0
|1⟩ = bit 1                     |−⟩ = (|0⟩ − |1⟩)/√2 = bit 1
```

**Key Insight**: Measuring in the wrong basis gives random results.
- If Alice sends |0⟩ (Z-basis) and Bob measures in X-basis → 50% chance of 0 or 1
- If Alice sends |+⟩ (X-basis) and Bob measures in Z-basis → 50% chance of 0 or 1

### Protocol Steps

```
┌─────────────────────────────────────────────────────────────────┐
│                        BB84 PROTOCOL                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: QUANTUM TRANSMISSION                                   │
│  ┌───────┐                                      ┌───────┐       │
│  │ ALICE │ ──── quantum channel (qubits) ────▶  │  BOB  │       │
│  └───────┘                                      └───────┘       │
│                                                                 │
│  Alice:                          Bob:                           │
│  • Generate random bits          • Choose random bases          │
│  • Choose random bases           • Measure qubits               │
│  • Encode & send qubits          • Record results               │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 2: BASIS RECONCILIATION (public channel)                  │
│  ┌───────┐                                      ┌───────┐       │
│  │ ALICE │ ◀──── "I used Z,X,X,Z,X,Z..." ────▶  │  BOB  │       │
│  └───────┘                                      └───────┘       │
│                                                                 │
│  • Compare bases (NOT the bits!)                                │
│  • Keep only bits where bases matched                           │
│  • Discard ~50% of bits (mismatched bases)                      │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 3: EAVESDROPPER DETECTION                                 │
│                                                                 │
│  • Sacrifice some bits to check for errors                      │
│  • Compare a random subset of the sifted key                    │
│  • If error rate > threshold (~11%) → Eve detected!             │
│  • If error rate OK → remaining bits = secure key               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why Eavesdropping is Detectable

### The No-Cloning Theorem

**You cannot copy an unknown quantum state.**

Eve cannot:
1. Copy the qubit to measure later
2. Measure and re-send without disturbance

### What Happens When Eve Intercepts

```
Without Eve:
Alice sends |0⟩ (Z-basis) → Bob measures Z-basis → Gets 0 ✓ (100% correct)

With Eve:
Alice sends |0⟩ (Z-basis)
    ↓
Eve intercepts, guesses X-basis, measures → Gets random |+⟩ or |−⟩
    ↓
Eve re-sends |+⟩ (wrong state!)
    ↓
Bob measures Z-basis → Gets 0 or 1 (50% chance of error!)
```

**Detection**: When Alice and Bob compare a sample of their keys:
- No Eve: ~0% error rate
- Eve present: ~25% error rate (Eve guesses wrong basis 50% × causes 50% errors)

---

## Implementation Architecture

```
src/qkd/
├── __init__.py
├── bb84.py          # Core BB84 protocol
├── participants.py  # Alice, Bob, Eve classes
├── channel.py       # Quantum and classical channels
└── analysis.py      # Error rate analysis, key verification
```

### Class Design

```python
# Alice: The sender
class Alice:
    def generate_bits(n: int) -> list[int]
    def choose_bases(n: int) -> list[Basis]
    def encode_qubits() -> list[cirq.Circuit]
    def sift_key(bob_bases: list[Basis]) -> list[int]

# Bob: The receiver
class Bob:
    def choose_bases(n: int) -> list[Basis]
    def measure_qubits(qubits: list[cirq.Circuit]) -> list[int]
    def sift_key(alice_bases: list[Basis]) -> list[int]

# Eve: The eavesdropper
class Eve:
    def intercept(qubit: cirq.Circuit) -> cirq.Circuit
    # Measures in random basis, re-sends based on result
```

---

## Quantum Circuits in BB84

### Encoding (Alice)

```python
# Bit 0 in Z-basis: |0⟩ (do nothing)
circuit = cirq.Circuit()

# Bit 1 in Z-basis: |1⟩
circuit = cirq.Circuit(cirq.X(qubit))

# Bit 0 in X-basis: |+⟩
circuit = cirq.Circuit(cirq.H(qubit))

# Bit 1 in X-basis: |−⟩
circuit = cirq.Circuit(cirq.X(qubit), cirq.H(qubit))
```

### Measuring (Bob)

```python
# Measure in Z-basis
circuit.append(cirq.measure(qubit))

# Measure in X-basis (apply H first)
circuit.append(cirq.H(qubit))
circuit.append(cirq.measure(qubit))
```

---

## Security Analysis

### Error Rate Thresholds

| Error Rate | Interpretation |
|------------|----------------|
| 0-5% | Normal noise, proceed with error correction |
| 5-11% | Suspicious, might be Eve + noise |
| >11% | Abort! Eavesdropper likely present |

The 11% threshold comes from information theory: beyond this, Eve gains too much information.

### Key Rate

After sifting and error checking:
```
Final key length ≈ n × 0.5 × (1 - leaked_for_testing)
                   ↑     ↑           ↑
            original  basis      security
              bits   matching     check
```

---

## Running the Simulator

```python
from qkd import BB84Protocol

# Create protocol instance
protocol = BB84Protocol(num_bits=1000)

# Run without eavesdropper
result = protocol.run(eavesdropper=False)
print(f"Key length: {len(result.key)}")
print(f"Error rate: {result.error_rate:.2%}")

# Run with eavesdropper
result_eve = protocol.run(eavesdropper=True)
print(f"Error rate with Eve: {result_eve.error_rate:.2%}")
print(f"Eve detected: {result_eve.eve_detected}")
```

---

## References

1. Bennett, C.H. & Brassard, G. (1984). "Quantum cryptography: Public key distribution and coin tossing"
2. Shor, P.W. & Preskill, J. (2000). "Simple Proof of Security of the BB84 Quantum Key Distribution Protocol"
3. Nielsen & Chuang, "Quantum Computation and Quantum Information", Chapter 12
