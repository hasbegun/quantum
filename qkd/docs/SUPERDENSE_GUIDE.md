# Superdense Coding - Theory & Implementation Guide

## What is Superdense Coding?

Superdense coding is a quantum communication protocol that allows transmission of **2 classical bits using only 1 qubit**. This is possible through pre-shared quantum entanglement between sender (Alice) and receiver (Bob).

### The Quantum Advantage

| Protocol | Qubits Sent | Classical Bits Transmitted |
|----------|-------------|---------------------------|
| Classical | N/A | 1 bit per signal |
| Superdense Coding | 1 qubit | **2 bits** |

This 2:1 ratio is the maximum allowed by quantum mechanics (Holevo bound).

---

## How It Works

### Prerequisites

Alice and Bob must share an **entangled Bell pair** before communication:

```
|Φ+⟩ = (|00⟩ + |11⟩) / √2
        ↓       ↓
      Alice    Bob
      (q0)     (q1)
```

This entanglement can be created in advance and the qubits distributed.

### The Four Bell States

The protocol uses all four Bell states to encode 2 bits:

```
|Φ+⟩ = (|00⟩ + |11⟩) / √2    ←  Message: 00
|Ψ+⟩ = (|01⟩ + |10⟩) / √2    ←  Message: 01
|Φ-⟩ = (|00⟩ - |11⟩) / √2    ←  Message: 10
|Ψ-⟩ = (|01⟩ - |10⟩) / √2    ←  Message: 11
```

---

## Protocol Steps

```
┌─────────────────────────────────────────────────────────────────┐
│                    SUPERDENSE CODING PROTOCOL                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: ENTANGLEMENT DISTRIBUTION (setup phase)                │
│                                                                 │
│  Source creates Bell pair:                                      │
│       ┌───┐                                                     │
│  q0 ──┤ H ├──●──  →  Alice keeps this qubit                     │
│       └───┘  │                                                  │
│  q1 ────────⊕──  →  Bob keeps this qubit                        │
│                                                                 │
│  State: |Φ+⟩ = (|00⟩ + |11⟩) / √2                               │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 2: ENCODING (Alice's operation)                           │
│                                                                 │
│  Alice wants to send 2 bits (b₁, b₀). She applies:              │
│                                                                 │
│  ┌─────────┬────────────┬─────────────────────────┐             │
│  │ Message │ Gate(s)    │ Resulting State         │             │
│  ├─────────┼────────────┼─────────────────────────┤             │
│  │   00    │ I (none)   │ |Φ+⟩                    │             │
│  │   01    │ X          │ |Ψ+⟩                    │             │
│  │   10    │ Z          │ |Φ-⟩                    │             │
│  │   11    │ X then Z   │ |Ψ-⟩                    │             │
│  └─────────┴────────────┴─────────────────────────┘             │
│                                                                 │
│  Gate application rule:                                         │
│  - If b₀ = 1: Apply X (bit flip)                                │
│  - If b₁ = 1: Apply Z (phase flip)                              │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 3: TRANSMISSION                                           │
│                                                                 │
│  Alice sends her qubit to Bob through quantum channel:          │
│                                                                 │
│  Alice ─────── [quantum channel] ──────→ Bob                    │
│                (1 qubit sent)                                   │
│                                                                 │
│  Bob now has BOTH qubits of the Bell pair.                      │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 4: DECODING (Bob's operation)                             │
│                                                                 │
│  Bob reverses the Bell state creation and measures:             │
│                                                                 │
│       ┌───┐                                                     │
│  q0 ──●──┤ H ├──[M]──→ b₁                                       │
│       │  └───┘                                                  │
│  q1 ──⊕────────[M]──→ b₀                                        │
│                                                                 │
│  The measurement result directly gives the 2-bit message!       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why It Works: The Math

### Initial State
After Bell pair creation, Alice has q0 and Bob has q1:
```
|Φ+⟩ = (|00⟩ + |11⟩) / √2
```

### Encoding Examples

**Message 00** (Identity):
```
I ⊗ I |Φ+⟩ = |Φ+⟩ = (|00⟩ + |11⟩) / √2
```

**Message 01** (X gate):
```
X ⊗ I |Φ+⟩ = (X|0⟩⊗|0⟩ + X|1⟩⊗|1⟩) / √2
           = (|1⟩⊗|0⟩ + |0⟩⊗|1⟩) / √2
           = |Ψ+⟩
```

**Message 10** (Z gate):
```
Z ⊗ I |Φ+⟩ = (Z|0⟩⊗|0⟩ + Z|1⟩⊗|1⟩) / √2
           = (|0⟩⊗|0⟩ - |1⟩⊗|1⟩) / √2
           = |Φ-⟩
```

**Message 11** (XZ gates):
```
ZX ⊗ I |Φ+⟩ = |Ψ-⟩ = (|01⟩ - |10⟩) / √2
```

### Decoding
Bob applies CNOT then H to q0, which maps:
```
|Φ+⟩ → |00⟩
|Ψ+⟩ → |01⟩
|Φ-⟩ → |10⟩
|Ψ-⟩ → |11⟩
```

Measurement directly reveals the message!

---

## Security Implications

### Eavesdropper Detection

If Eve intercepts Alice's qubit:
1. She breaks the entanglement
2. She cannot perfectly clone the quantum state (no-cloning theorem)
3. Her interference introduces detectable errors

### Combining with QKD

Superdense coding can be combined with BB84:
1. Use BB84 to establish a shared secret key
2. Use superdense coding for efficient quantum communication
3. Eve detection works in both protocols

---

## Circuit Diagram

```
Full superdense coding circuit for message "11":

q0: ───H───●───X───Z───●───H───M('b1')───
           │           │
q1: ───────X───────────X───────M('b0')───
     └─Bell─┘  └─encode─┘  └──decode──┘
```

---

## Implementation Usage

```python
from qkd import SuperdenseCoding

# Create protocol instance
sd = SuperdenseCoding(seed=42)

# Send a single 2-bit message
result = sd.send_message((1, 0))  # Send "10"
print(f"Sent: (1, 0), Received: {result.decoded_message}")

# Send multiple messages
messages = [(0, 0), (0, 1), (1, 0), (1, 1)]
result = sd.run(messages)
print(f"Success rate: {result.success_rate:.0%}")

# Run demonstration
sd.demonstrate()
```

---

## Comparison: Superdense Coding vs Quantum Teleportation

| Aspect | Superdense Coding | Quantum Teleportation |
|--------|-------------------|----------------------|
| Input | 2 classical bits | 1 qubit (unknown state) |
| Output | 2 classical bits | 1 qubit (same state) |
| Qubits sent | 1 | 0 (classical bits sent) |
| Classical bits sent | 0 | 2 |
| Pre-shared | 1 Bell pair | 1 Bell pair |
| Direction | Classical → Quantum → Classical | Quantum → Classical → Quantum |

They are "dual" protocols - superdense coding is the reverse of teleportation!

---

## References

1. Bennett, C.H. & Wiesner, S.J. (1992). "Communication via one- and two-particle operators on Einstein-Podolsky-Rosen states"
2. Nielsen & Chuang, "Quantum Computation and Quantum Information", Section 2.3
