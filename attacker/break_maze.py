"""Use the simulated Shor attack to open a maze vault with no private key.

Given only the public key, factor the modulus, reconstruct the private
exponent, and decrypt the vault — demonstrating end-to-end that classical RSA
at these sizes provides no protection against a quantum adversary.
"""

from __future__ import annotations

from cryptolayer.classical import RSAPrivateKey, RSAPublicKey, _modinv
from maze.vault import Vault, open_vault

from .shor import ShorResult, shor_factor


def recover_private_key(public: RSAPublicKey, *, seed: int = 1,
                        force_quantum: bool = False) -> tuple[RSAPrivateKey, ShorResult]:
    """Recover the RSA private key from the public key alone, via Shor."""
    result = shor_factor(public.n, seed=seed, force_quantum=force_quantum)
    if not result.success or result.factors is None:
        raise RuntimeError(f"quantum factoring of n={public.n} failed")
    p, q = result.factors
    phi = (p - 1) * (q - 1)
    d = _modinv(public.e, phi)
    return RSAPrivateKey(public.n, d, p, q), result


def crack_vault(vault: Vault, public: RSAPublicKey, *, seed: int = 1,
                force_quantum: bool = False) -> tuple[bytes, RSAPrivateKey, ShorResult]:
    """Open ``vault`` using only its public key. Returns (secret, key, attack)."""
    private, result = recover_private_key(public, seed=seed, force_quantum=force_quantum)
    secret = open_vault(vault, private)
    return secret, private, result
