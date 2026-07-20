"""The crypto-agility interface.

Every algorithm — classical or post-quantum — implements ``LockBox``. The
application never imports a concrete algorithm; it asks the registry for one
by name. This is the abstraction real enterprises lack, and it is what makes
a classical -> post-quantum migration a configuration change rather than a
code change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class KeyPair:
    """An opaque public/private key pair. Concrete shape is algorithm-defined."""

    public: Any
    private: Any


class LockBox(ABC):
    """A pluggable public-key lock/unlock primitive.

    Subclasses set two class attributes:

    ``algorithm``           human-readable id, e.g. ``"rsa-toy"`` or ``"ml-kem-768"``.
    ``quantum_vulnerable``  True if Shor's algorithm on a large enough quantum
                            computer would break it. RSA/ECC -> True.
                            Lattice/hash-based schemes -> False.

    ``level`` is an opaque security-level string the implementation interprets
    (RSA maps it to a modulus size; a real KEM would map it to a parameter
    set such as 512/768/1024). Keeping key parameters behind an opaque level
    is exactly what lets the application stay algorithm-agnostic.
    """

    algorithm: str = "abstract"
    quantum_vulnerable: bool = True

    @abstractmethod
    def generate_keypair(self, *, level: str | None = None) -> KeyPair:
        """Produce a fresh key pair at the named security level."""

    @abstractmethod
    def lock(self, public: Any, plaintext: bytes) -> bytes:
        """Encrypt/encapsulate ``plaintext`` under ``public``. Returns opaque bytes."""

    @abstractmethod
    def unlock(self, private: Any, ciphertext: bytes) -> bytes:
        """Recover the plaintext from ``ciphertext`` using ``private``."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        vuln = "quantum-vulnerable" if self.quantum_vulnerable else "quantum-resistant"
        return f"<LockBox {self.algorithm} ({vuln})>"
