"""Dispatch an RSA-specific factoring attack, reporting unsupported targets.

A missing RSA modulus is an applicability decision, not a security test of
ML-KEM. No quantum simulation is run for an unsupported key type.
"""

from __future__ import annotations

import math
from typing import Any

from cryptolayer.registry import get_lockbox
from maze.vault import Vault

from .break_maze import crack_vault
from .shor import resource_estimate


def _factoring_target(public: Any) -> int | None:
    """Read an RSA factoring target. This does not assess the key's security."""
    n = getattr(public, "n", None)
    return n if type(n) is int and n > 1 else None


def run_quantum_attack(vault: Vault, public: Any, *, seed: int = 1,
                       force_quantum: bool = True) -> dict:
    """Attempt to open ``vault`` with a simulated quantum computer.

    Returns a dict describing whether Shor's algorithm even *applies*, whether
    it succeeded, and (for RSA) the quantum-period-finding trace for display.
    """
    modulus = _factoring_target(public)

    if modulus is None:
        # Unsupported target: no circuit or quantum measurement is executed.
        return {
            "applicable": False,
            "success": False,
            "algorithm": vault.algorithm,
            "probe": {
                "public_key_type": type(public).__name__,
                "integer_modulus_found": False,
                "public_key_bytes": len(getattr(public, "ek", b"")) or None,
            },
            "reason": (
                "Not applicable: this implementation attacks RSA factoring keys. "
                "ML-KEM is a lattice-based key encapsulation mechanism. No Shor "
                "circuit was run against it, and this dispatch result is not a "
                "proof of post-quantum security."
            ),
        }

    # Public key exposes a modulus n: run the real quantum factoring attack.
    secret, priv, result = crack_vault(vault, public, seed=seed, force_quantum=force_quantum)
    win = result.attempts[-1] if result.attempts else {}
    a, N = win.get("a"), public.n
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
