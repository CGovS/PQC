"""RSA modulus ladder for the maze, plus metadata for reporting.

The primes themselves live in ``cryptolayer.classical.DEFAULT_LADDER`` (they
belong to the primitive). Here we attach human-facing metadata used by the
demo now and by the Phase 2 attacker later — e.g. rough qubit costs for a
simulated Shor factorization of each modulus.
"""

from __future__ import annotations

from cryptolayer.interface import KeyPair
from cryptolayer.registry import get_lockbox

# Reporting metadata per security level. ``sim_ok`` flags whether a general
# (non-precompiled) Shor circuit for this modulus is realistically simulable
# on a laptop-class machine.
LEVEL_INFO: dict[str, dict] = {
    "warmup": {"n": 15, "bits": 4, "sim_ok": True,
               "note": "canonical Shor teaching example"},
    "easy": {"n": 21, "bits": 5, "sim_ok": True,
             "note": "classic factor-21 simulation target"},
    "ceiling": {"n": 35, "bits": 6, "sim_ok": True,
                "note": "honest ceiling for a laptop statevector sim"},
}

DEFAULT_LEVEL = "warmup"


def make_keypair(level: str = DEFAULT_LEVEL) -> KeyPair:
    """Generate an RSA key pair at ``level`` via the crypto-agility layer."""
    if level not in LEVEL_INFO:
        raise KeyError(f"unknown level '{level}'. available: {sorted(LEVEL_INFO)}")
    return get_lockbox("rsa-toy").generate_keypair(level=level)
