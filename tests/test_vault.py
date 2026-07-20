"""Tests for the maze vault."""

import pytest

from maze.keys import LEVEL_INFO, make_keypair
from maze.vault import open_vault, seal

SECRET = b"FLAG{crypto-agility-is-the-real-migration}"


@pytest.mark.parametrize("level", list(LEVEL_INFO))
def test_seal_open_roundtrip(level):
    kp = make_keypair(level)
    vault = seal(SECRET, kp.public, hint=level)
    assert open_vault(vault, kp.private) == SECRET


def test_vault_reports_quantum_vulnerable():
    kp = make_keypair("warmup")
    vault = seal(SECRET, kp.public)
    assert vault.quantum_vulnerable is True


def test_vault_carries_algorithm_name():
    kp = make_keypair("warmup")
    vault = seal(SECRET, kp.public)
    assert vault.algorithm == "rsa-toy"


def test_make_keypair_rejects_unknown_level():
    with pytest.raises(KeyError):
        make_keypair("enterprise-grade")
