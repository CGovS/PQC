"""Algorithm registry — the single place a migration happens.

Today only ``rsa-toy`` is registered. When Phase 4 lands, adding

    register("ml-kem-768", MLKEMLockBox)

and pointing the application's config at that name is the *entire* migration
from classical to post-quantum crypto. No application code changes. That is
the thesis of this project, expressed in ~30 lines.
"""

from __future__ import annotations

from typing import Callable

from .classical import RSALockBox
from .interface import LockBox

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
register("rsa-toy", RSALockBox)
# Phase 4 will register the post-quantum replacement here, e.g.:
#   register("ml-kem-768", MLKEMLockBox)
