"""
Quantum Circuit Components for Shor's Algorithm

This subpackage contains the quantum circuit implementations using Cirq:
- qft.py: Quantum Fourier Transform
- modular_arithmetic.py: Quantum modular arithmetic circuits
- period_finding.py: Quantum period finding subroutine
- shors_cirq.py: Complete Shor's algorithm
"""

from .qft import (
    qft_circuit,
    inverse_qft_circuit,
    qft_rotations,
)

from .modular_arithmetic import (
    controlled_modular_multiplication,
    modular_exponentiation_circuit,
    QuantumModularArithmetic,
)

from .period_finding import (
    QuantumPeriodFinding,
    extract_period_from_measurements,
)

from .shors_cirq import (
    ShorsAlgorithmCirq,
    shors_factor_cirq,
    demonstrate_shors_cirq,
)

__all__ = [
    # QFT
    "qft_circuit",
    "inverse_qft_circuit",
    "qft_rotations",
    # Modular Arithmetic
    "controlled_modular_multiplication",
    "modular_exponentiation_circuit",
    "QuantumModularArithmetic",
    # Period Finding
    "QuantumPeriodFinding",
    "extract_period_from_measurements",
    # Shor's Algorithm
    "ShorsAlgorithmCirq",
    "shors_factor_cirq",
    "demonstrate_shors_cirq",
]
