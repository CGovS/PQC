"""The vault: a secret sealed behind whatever algorithm the registry provides.

Note that nothing in this file mentions RSA. It talks only to the crypto-agility
layer by algorithm *name*. Swapping ``algorithm="rsa-toy"`` for a post-quantum
name later requires zero changes here — which is the whole demonstration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptolayer.registry import get_lockbox


@dataclass
class Vault:
    """A sealed secret plus the name of the algorithm that sealed it."""

    algorithm: str
    ciphertext: bytes
    hint: str = ""

    @property
    def quantum_vulnerable(self) -> bool:
        """Would a quantum computer running Shor's algorithm open this vault?"""
        return get_lockbox(self.algorithm).quantum_vulnerable


def seal(secret: bytes, public: Any, *, algorithm: str = "rsa-toy",
         hint: str = "") -> Vault:
    """Seal ``secret`` under ``public`` using the named algorithm."""
    box = get_lockbox(algorithm)
    return Vault(algorithm=algorithm, ciphertext=box.lock(public, secret), hint=hint)


def open_vault(vault: Vault, private: Any) -> bytes:
    """Open ``vault`` with the matching private key."""
    box = get_lockbox(vault.algorithm)
    return box.unlock(private, vault.ciphertext)
