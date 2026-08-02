"""Tests for the simulated Shor attack and the maze break."""

import math

import pytest

from attacker.shor import n_qubits_for, resource_estimate, shor_factor
from attacker.break_maze import crack_vault
from maze.keys import LEVEL_INFO, make_keypair
from maze.vault import seal

SECRET = b"FLAG{h4rv35t_n0w_d3crypt_l4t3r}"


@pytest.mark.parametrize("N,expected", [(15, {3, 5}), (21, {3, 7}), (35, {5, 7})])
def test_shor_factors_ladder(N, expected):
    res = shor_factor(N, seed=1)
    assert res.success
    assert set(res.factors) == expected
    assert res.factors[0] * res.factors[1] == N


@pytest.mark.parametrize("level", list(LEVEL_INFO))
def test_crack_vault_recovers_secret(level):
    kp = make_keypair(level)
    vault = seal(SECRET, kp.public, hint=level)
    # Attacker sees only the public key.
    secret, priv, result = crack_vault(vault, kp.public, seed=1)
    assert secret == SECRET
    assert result.success
    # Recovered private exponent matches the true one.
    assert priv.d == kp.private.d


def test_n_qubits_for():
    assert n_qubits_for(15) == 4
    assert n_qubits_for(35) == 6


def test_resource_estimate_shows_the_gap():
    toy = resource_estimate(6)      # n=35
    real = resource_estimate(2048)  # RSA-2048
    assert real["logical_qubits_approx"] > 100 * toy["logical_qubits_approx"]
