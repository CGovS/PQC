"""cryptolayer — the crypto-agility seam.

Applications talk only to the ``LockBox`` interface and select an algorithm
by name through the registry. Migrating from a quantum-vulnerable primitive
(RSA) to a post-quantum one (ML-KEM, later) becomes a one-line registry swap
instead of an application rewrite. That agility is the point of this project.
"""

from .interface import LockBox, KeyPair
from .registry import get_lockbox, register, available

__all__ = ["LockBox", "KeyPair", "get_lockbox", "register", "available"]
