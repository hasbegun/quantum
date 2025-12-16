# Shor's Algorithm Threat Demonstration
# Shows how quantum computers threaten RSA and ECDSA

from .shors_algorithm import (
    shors_factor,
    shors_discrete_log,
    classical_order_finding,
    quantum_order_finding_simulation,
)

from .rsa_attack import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    break_rsa_with_shors,
    classical_factor_attempt,
)

from .ecdsa_attack import (
    generate_ecdsa_keypair,
    ecdsa_sign,
    ecdsa_verify,
    break_ecdsa_with_shors,
    classical_discrete_log_attempt,
)

# Quantum circuit implementations (requires Cirq)
from .quantum import (
    # QFT
    qft_circuit,
    inverse_qft_circuit,
    # Period Finding
    QuantumPeriodFinding,
    # Shor's Algorithm with Cirq
    ShorsAlgorithmCirq,
    shors_factor_cirq,
    demonstrate_shors_cirq,
)

__all__ = [
    # Shor's Algorithm (classical simulation)
    "shors_factor",
    "shors_discrete_log",
    "classical_order_finding",
    "quantum_order_finding_simulation",
    # RSA Attack
    "generate_rsa_keypair",
    "rsa_encrypt",
    "rsa_decrypt",
    "break_rsa_with_shors",
    "classical_factor_attempt",
    # ECDSA Attack
    "generate_ecdsa_keypair",
    "ecdsa_sign",
    "ecdsa_verify",
    "break_ecdsa_with_shors",
    "classical_discrete_log_attempt",
    # Quantum Circuits (Cirq)
    "qft_circuit",
    "inverse_qft_circuit",
    "QuantumPeriodFinding",
    "ShorsAlgorithmCirq",
    "shors_factor_cirq",
    "demonstrate_shors_cirq",
]
