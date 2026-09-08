"""Shared vault interface and lazy algorithm registry for an educational lab."""

from .interface import LockBox, KeyPair
from .registry import get_lockbox, register, available

__all__ = ["LockBox", "KeyPair", "get_lockbox", "register", "available"]
