"""Round-trip and interface tests for the crypto-agility layer."""

import pytest

from cryptolayer.classical import DEFAULT_LADDER, rsa_keypair_from_primes
from cryptolayer.registry import available, get_lockbox

LEVELS = list(DEFAULT_LADDER)
MESSAGES = [b"", b"A", b"hello", b"FLAG{crypto-agility}", bytes(range(20))]


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("msg", MESSAGES)
def test_rsa_roundtrip(level, msg):
    box = get_lockbox("rsa-toy")
    kp = box.generate_keypair(level=level)
    ct = box.lock(kp.public, msg)
    assert box.unlock(kp.private, ct) == msg


def test_rsa_is_flagged_quantum_vulnerable():
    assert get_lockbox("rsa-toy").quantum_vulnerable is True


def test_registry_lists_rsa():
    assert "rsa-toy" in available()


def test_unknown_algorithm_raises():
    with pytest.raises(KeyError):
        get_lockbox("does-not-exist")


def test_unknown_level_raises():
    with pytest.raises(KeyError):
        get_lockbox("rsa-toy").generate_keypair(level="nope")


@pytest.mark.parametrize("level,expected_n", [("warmup", 15), ("easy", 21), ("ceiling", 35)])
def test_ladder_moduli(level, expected_n):
    p, q = DEFAULT_LADDER[level]
    assert p * q == expected_n


def test_keypair_consistency():
    # e*d == 1 (mod phi) so decryption is well-defined.
    kp = rsa_keypair_from_primes(3, 7)
    p, q = kp.private.p, kp.private.q
    phi = (p - 1) * (q - 1)
    assert (kp.public.e * kp.private.d) % phi == 1
