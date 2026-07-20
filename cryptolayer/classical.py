"""Classical RSA LockBox — DELIBERATELY WEAK, for demonstration only.

The moduli here are tiny (n in {15, 21, 35}) so that a *classical simulation*
of Shor's algorithm can actually factor them on a laptop. This is textbook
"toy RSA": it is broken by design. Never use it to protect anything real.

The security lesson is genuine even though the key sizes are not: breaking a
vault sealed by this LockBox reduces to factoring ``n``, which is precisely
what a quantum computer running Shor's algorithm does in polynomial time.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass

from .interface import KeyPair, LockBox

# Named RSA security "levels" -> the primes (p, q) behind each modulus.
# Kept tiny on purpose so Phase 2's simulated Shor attack can factor them.
DEFAULT_LADDER: dict[str, tuple[int, int]] = {
    "warmup": (3, 5),   # n = 15  — the canonical Shor teaching example
    "easy": (3, 7),     # n = 21  — the classic "factor 21" simulation target
    "ceiling": (5, 7),  # n = 35  — an honest ceiling for laptop statevector sims
}


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    p: int
    q: int


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse for {a} mod {m}")
    return x % m


def _choose_e(phi: int) -> int:
    """Smallest sane public exponent coprime to phi."""
    for e in (3, 5, 7, 11, 13, 17, 65537):
        if 1 < e < phi and math.gcd(e, phi) == 1:
            return e
    e = 3
    while e < phi:
        if math.gcd(e, phi) == 1:
            return e
        e += 2
    raise ValueError(f"could not choose a public exponent for phi={phi}")


def rsa_keypair_from_primes(p: int, q: int) -> KeyPair:
    """Build a textbook RSA key pair from two primes."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = _choose_e(phi)
    d = _modinv(e, phi)
    return KeyPair(RSAPublicKey(n, e), RSAPrivateKey(n, d, p, q))


def _to_base(value: int, base: int) -> list[int]:
    """Little-endian digits of ``value`` in ``base`` (each digit < base)."""
    if value == 0:
        return [0]
    digits: list[int] = []
    while value:
        digits.append(value % base)
        value //= base
    return digits


def _from_base(digits: list[int], base: int) -> int:
    value = 0
    for d in reversed(digits):
        value = value * base + d
    return value


class RSALockBox(LockBox):
    """Toy RSA behind the crypto-agility interface.

    Because the modulus is tiny, a plaintext is encoded as base-``n`` digits
    and each digit is RSA-encrypted independently. Textbook RSA is correct for
    every residue mod ``n`` (by CRT), so the round-trip is exact.
    """

    algorithm = "rsa-toy"
    quantum_vulnerable = True

    def __init__(self, ladder: dict[str, tuple[int, int]] | None = None) -> None:
        self._ladder = ladder or DEFAULT_LADDER

    def generate_keypair(self, *, level: str | None = None) -> KeyPair:
        if level is None:
            level = next(iter(self._ladder))
        if level not in self._ladder:
            raise KeyError(
                f"unknown level '{level}'. available: {sorted(self._ladder)}"
            )
        p, q = self._ladder[level]
        return rsa_keypair_from_primes(p, q)

    def lock(self, public: RSAPublicKey, plaintext: bytes) -> bytes:
        n, e = public.n, public.e
        m_int = int.from_bytes(plaintext, "big")
        cipher = [pow(d, e, n) for d in _to_base(m_int, n)]
        payload = {"n": n, "len": len(plaintext), "c": cipher}
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def unlock(self, private: RSAPrivateKey, ciphertext: bytes) -> bytes:
        payload = json.loads(ciphertext.decode("utf-8"))
        n, d = private.n, private.d
        digits = [pow(c, d, n) for c in payload["c"]]
        length = payload["len"]
        if length == 0:
            return b""
        return _from_base(digits, n).to_bytes(length, "big")
