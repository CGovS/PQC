"""Phase 5 — point the *same* quantum attacker at whatever sealed the vault.

Against classical RSA it factors the modulus and opens the vault. Against
ML-KEM it has nothing to factor: lattice security (Module-LWE) does not reduce
to period-finding, so Shor gives no advantage. Crucially, the attacker decides
applicability by *probing the public key* for an integer modulus — not by
reading any 'is this safe?' flag on the algorithm — so the ML-KEM outcome is a
discovered fact. The module returns a structured before/after for the demo.
"""

from __future__ import annotations

import math
from typing import Any

from cryptolayer.registry import get_lockbox
from maze.vault import Vault

from .break_maze import crack_vault
from .shor import resource_estimate


def _factoring_target(public: Any) -> int | None:
    """What Shor's routine needs to run: an integer modulus exposed by the
    public key. RSA public keys carry ``n``; a lattice (ML-KEM) public key
    carries no integer to factor, so this returns ``None`` for them.

    The attack's applicability is decided by *probing the public key* here —
    not by trusting any 'is this safe?' label on the algorithm. That is what
    makes the ML-KEM 'nothing to break' outcome a discovered fact rather than
    an assertion: flip ML-KEM's quantum_vulnerable flag to True and this probe
    still finds no modulus.
    """
    n = getattr(public, "n", None)
    return n if isinstance(n, int) else None


def run_quantum_attack(vault: Vault, public: Any, *, seed: int = 1,
                       force_quantum: bool = True) -> dict:
    """Attempt to open ``vault`` with a simulated quantum computer.

    Returns a dict describing whether Shor's algorithm even *applies*, whether
    it succeeded, and (for RSA) the quantum-period-finding trace for display.
    """
    box = get_lockbox(vault.algorithm)
    modulus = _factoring_target(public)

    if modulus is None:
        # The attacker booted Shor and inspected the public key for an integer
        # modulus to factor. It found none — this target's public key is a
        # lattice object, not an integer. Period-finding has no input, so the
        # attack halts before it can start. Discovered, not declared.
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
                "No factoring target. The attacker inspected the public key for "
                "an integer modulus and found none — this is a lattice public "
                "key, not an integer. Shor's algorithm breaks RSA/ECC by period-"
                "finding (integer factoring / discrete logs); ML-KEM's security "
                "rests on Module-LWE, which does not reduce to period-finding, so "
                "there is nothing to feed the quantum computer. Note this outcome "
                "comes from probing the key, not from trusting a safety label."
            ),
        }

    # Public key exposes a modulus n: run the real quantum factoring attack.
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
