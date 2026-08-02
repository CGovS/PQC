"""Tests for the post-quantum LockBox and the Phase 5 before/after campaign."""

import pytest

from attacker.campaign import run_quantum_attack
from attacker.report import build_report
from cryptolayer.registry import available, get_lockbox
from maze.keys import make_keypair
from maze.vault import open_vault, seal

SECRET = b"FLAG{h4rv35t_n0w_d3crypt_l4t3r}"


@pytest.mark.parametrize("algo", ["ml-kem-512", "ml-kem-768", "ml-kem-1024"])
def test_mlkem_roundtrip(algo):
    box = get_lockbox(algo)
    assert box.quantum_vulnerable is False
    kp = box.generate_keypair()
    vault = seal(SECRET, kp.public, algorithm=algo)
    assert vault.ciphertext != SECRET
    assert open_vault(vault, kp.private) == SECRET


def test_mlkem_is_registered():
    for name in ("ml-kem-512", "ml-kem-768", "ml-kem-1024"):
        assert name in available()


def test_mlkem_tamper_is_detected():
    box = get_lockbox("ml-kem-768")
    kp = box.generate_keypair()
    vault = seal(SECRET, kp.public, algorithm="ml-kem-768")
    tampered = bytearray(vault.ciphertext)
    tampered[-3] ^= 0x01  # flip a bit inside the base64 tag/body
    vault.ciphertext = bytes(tampered)
    with pytest.raises((ValueError, Exception)):
        open_vault(vault, kp.private)


def test_wrong_key_cannot_open():
    box = get_lockbox("ml-kem-768")
    good = box.generate_keypair()
    other = box.generate_keypair()
    vault = seal(SECRET, good.public, algorithm="ml-kem-768")
    with pytest.raises(Exception):
        open_vault(vault, other.private)


def test_quantum_attack_breaks_rsa_but_not_pqc():
    # RSA: attack applies and succeeds.
    rsa_kp = make_keypair("ceiling")
    rsa_vault = seal(SECRET, rsa_kp.public, algorithm="rsa-toy")
    before = run_quantum_attack(rsa_vault, rsa_kp.public, seed=3)
    assert before["applicable"] and before["success"]
    assert before["revealed"] == SECRET.decode()

    # ML-KEM: same attacker, nothing to factor.
    pqc = get_lockbox("ml-kem-768")
    pqc_kp = pqc.generate_keypair()
    pqc_vault = seal(SECRET, pqc_kp.public, algorithm="ml-kem-768")
    after = run_quantum_attack(pqc_vault, pqc_kp.public, seed=3)
    assert after["applicable"] is False
    assert after["success"] is False


def test_build_report_before_after():
    report = build_report(level="ceiling", seed=3)
    assert report["before"]["attack"]["success"] is True
    assert report["before"]["attack"]["factors"][0] * report["before"]["attack"]["factors"][1] == 35
    assert report["after"]["attack"]["success"] is False
    assert report["after"]["opened_with_key"] is True
    assert report["migration"]["application_code_changes"] == 0
