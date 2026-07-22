"""Phase 5 — point the *same* quantum attacker at whatever sealed the vault.

Against classical RSA it factors the modulus and opens the vault. Against
ML-KEM it has nothing to factor: lattice security (Module-LWE) does not reduce
to period-finding, so Shor gives no advantage. This module encodes that
honestly and returns a structured outcome the demo renders as before/after.
"""

from __future__ import annotations

import math
from typing import Any

from cryptolayer.registry import get_lockbox
from maze.vault import Vault

from .break_maze import crack_vault
from .shor import resource_estimate


def run_quantum_attack(vault: Vault, public: Any, *, seed: int = 1,
                       force_quantum: bool = True) -> dict:
    """Attempt to open ``vault`` with a simulated quantum computer.

    Returns a dict describing whether Shor's algorithm even *applies*, whether
    it succeeded, and (for RSA) the quantum-period-finding trace for display.
    """
    box = get_lockbox(vault.algorithm)

    if not box.quantum_vulnerable:
        return {
            "applicable": False,
            "success": False,
            "algorithm": vault.algorithm,
            "reason": (
                "No factoring target. Shor's algorithm breaks RSA/ECC by finding "
                "periods (integer factoring, discrete logs). ML-KEM's security "
                "rests on Module-LWE — a lattice problem with no known efficient "
                "quantum attack — so there is no modulus to factor and no period "
                "to find. The simulated quantum computer has nothing to do."
            ),
        }

    # Quantum-vulnerable target with an RSA modulus: run the real attack.
    secret, priv, result = crack_vault(vault, public, seed=seed, force_quantum=force_quantum)
    win = result.attempts[-1]
    a, N = win["a"], public.n
    r = win.get("period")
    half_exp = pow(a, r // 2, N) if r else None

    return {
        "applicable": True,
        "success": result.success,
        "algorithm": vault.algorithm,
        "N": N,
        "a": a,
        "measured_c": win.get("measured_c"),
        "M": win.get("M"),
        "counting_qubits": win.get("t"),
        "work_qubits": win.get("n"),
        "period": r,
        "half_exp": half_exp,           # a^(r/2) mod N, input to the gcd step
        "peaks": win.get("peaks", []),
        "factors": list(result.factors),
        "recovered_d": priv.d,
        "attempts": len(result.attempts),
        "revealed": secret.decode(errors="replace"),
        "resource_estimate": resource_estimate(math.ceil(math.log2(N))),
    }
