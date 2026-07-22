"""Algorithm registry — the single place a migration happens.

Pointing the application's config from ``rsa-toy`` to ``ml-kem-768`` is the
*entire* migration from classical to post-quantum crypto: no application code
changes, just a different name resolved here. That is the thesis of this
project, expressed in ~40 lines.
"""

from __future__ import annotations

from typing import Callable

from .classical import RSALockBox
from .interface import LockBox
from .pqc import MLKEMLockBox

_REGISTRY: dict[str, Callable[[], LockBox]] = {}


def register(name: str, factory: Callable[[], LockBox]) -> None:
    """Register a LockBox factory under ``name``."""
    _REGISTRY[name] = factory


def get_lockbox(name: str) -> LockBox:
    """Return a fresh LockBox for ``name``; raises KeyError if unknown."""
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown algorithm '{name}'. available: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]()


def available() -> list[str]:
    """Names of every registered algorithm."""
    return sorted(_REGISTRY)


# --- registrations -------------------------------------------------------
# Classical (quantum-vulnerable):
register("rsa-toy", RSALockBox)
# Post-quantum (quantum-resistant) — the migration targets. Selecting one of
# these names instead of "rsa-toy" is the whole migration:
register("ml-kem-512", lambda: MLKEMLockBox("512"))
register("ml-kem-768", lambda: MLKEMLockBox("768"))
register("ml-kem-1024", lambda: MLKEMLockBox("1024"))
