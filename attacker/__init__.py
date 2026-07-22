"""attacker — a simulated quantum computer running Shor's algorithm.

This is a faithful *statevector simulation*: it builds the real superposition,
applies a real quantum Fourier transform, and samples a measurement under the
Born rule. It factors the maze's tiny RSA moduli honestly. Because a statevector
holds 2^(qubits) amplitudes, it is bounded to a few dozen qubits — enough for the
toy moduli, and nowhere near real RSA. See ``resource_estimate``.
"""

from .shor import shor_factor, quantum_period_finding, resource_estimate, n_qubits_for
from .break_maze import crack_vault, recover_private_key

__all__ = [
    "shor_factor",
    "quantum_period_finding",
    "resource_estimate",
    "n_qubits_for",
    "crack_vault",
    "recover_private_key",
]
