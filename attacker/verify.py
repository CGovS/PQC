"""End-to-end verification that the demo is an *actual* hack and an *actual*
post-quantum defense — not a scripted animation.

Proves, from scratch and with assertions:

  1. RSA break is real. For every maze level, seal a vault, then using ONLY the
     public key run the simulated Shor attack, factor n, rebuild the private
     exponent, and decrypt the vault. Assert the recovered plaintext equals the
     sealed secret AND the recovered d equals the true private exponent.
  2. ML-KEM defense is real. Seal the same secret with ML-KEM; assert the
     legitimate key opens it, tampering is rejected, and the SAME attacker's
     probe finds no factoring target.
  3. Browser engine agrees. Shell out to node and run demo/parity_check.js so
     the in-page JS Shor/RSA implementation is cross-checked against Python.

    python -m attacker.verify        # or: make verify
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

from attacker.break_maze import crack_vault
from attacker.campaign import run_quantum_attack
from attacker.shor import measurement_distribution
from cryptolayer.registry import get_lockbox
from maze.cli import DEFAULT_SECRET
from maze.keys import LEVEL_INFO, make_keypair
from maze.vault import Vault, open_vault, seal

REPO = os.path.dirname(os.path.dirname(__file__))
PASS, FAIL, SKIP = "  \033[32m✓\033[0m", "  \033[31m✗\033[0m", "  \033[33m∼\033[0m"


class Checker:
    def __init__(self) -> None:
        self.failures = 0
        self.skips = 0

    def check(self, ok: bool, label: str) -> None:
        print(f"{PASS if ok else FAIL} {label}")
        if not ok:
            self.failures += 1

    def skip(self, label: str) -> None:
        print(f"{SKIP} {label}  (SKIPPED — not verified)")
        self.skips += 1


def verify_rsa_break(c: Checker) -> None:
    print("\n[1] RSA break is a genuine factor-and-decrypt (public key only)")
    for level in LEVEL_INFO:
        kp = make_keypair(level)
        secret = DEFAULT_SECRET
        vault = seal(secret, kp.public, algorithm="rsa-toy", hint=level)
        # Attacker sees ONLY the public key + the sealed vault.
        recovered, priv, result = crack_vault(vault, kp.public, seed=3, force_quantum=True)
        n = kp.public.n
        c.check(result.success and result.factors is not None
                and result.factors[0] * result.factors[1] == n,
                f"n={n:>3} ({level}): Shor factored it -> {tuple(sorted(result.factors))} "
                f"via period-finding (a={result.attempts[-1]['a']}, r={result.attempts[-1].get('period')})")
        # The d-equality check is the real teeth: with tiny squarefree moduli a
        # *wrong* exponent congruent to the true one mod lambda(n) can still
        # decrypt correctly, so `recovered == secret` alone is not proof the true
        # key was found — the two checks together are.
        c.check(priv.d == kp.private.d,
                f"n={n:>3} ({level}): reconstructed private exponent d={priv.d} equals the true key")
        c.check(recovered == secret,
                f"n={n:>3} ({level}): decrypted vault == sealed secret")


def verify_mlkem_defense(c: Checker) -> None:
    print("\n[2] ML-KEM defense is real (round-trip, tamper-evident, no target for Shor)")
    box = get_lockbox("ml-kem-768")
    kp = box.generate_keypair()
    secret = DEFAULT_SECRET
    vault = seal(secret, kp.public, algorithm="ml-kem-768", hint="ML-KEM-768")

    c.check(open_vault(vault, kp.private) == secret,
            "legitimate key opens the ML-KEM vault (migration preserved functionality)")

    # Tamper: flip one bit of the DEM body and expect authentication failure.
    payload = json.loads(vault.ciphertext.decode())
    body = bytearray(base64.b64decode(payload["body"]))
    body[0] ^= 0x01
    payload["body"] = base64.b64encode(bytes(body)).decode()
    tampered = Vault("ml-kem-768", json.dumps(payload).encode(), hint="tampered")
    rejected = False
    try:
        open_vault(tampered, kp.private)
    except ValueError:
        rejected = True
    c.check(rejected, "tampered ciphertext is rejected (encrypt-then-MAC catches it)")

    # The SAME attacker: no integer modulus in a lattice public key.
    attack = run_quantum_attack(vault, kp.public, seed=3)
    c.check(attack["applicable"] is False and attack["success"] is False
            and attack.get("probe", {}).get("integer_modulus_found") is False,
            "same Shor attacker probes the public key and finds no modulus to factor")


def _seal_vector(box, level: str, plaintext: bytes, label: str) -> dict:
    kp = make_keypair(level)
    ciphertext = box.lock(kp.public, plaintext)   # a real Python RSA ciphertext
    return {
        "label": label,
        "n": kp.public.n,
        "e": kp.public.e,
        "ciphertext": ciphertext.decode(),
        "plaintext_hex": plaintext.hex(),
    }


def verify_js_parity(c: Checker) -> None:
    print("\n[3] Browser engine (demo/quantum.js) reproduces Python's quantum + crypto")
    node = shutil.which("node")
    if node is None:
        c.skip("JS/Python cross-check — node not installed (install Node to run it)")
        return

    # Build a challenge FRESH from Python now (not from a committed snapshot),
    # so the cross-check compares the JS engine to a live Python computation.
    box = get_lockbox("rsa-toy")
    challenge = {
        "dist": {"a": 17, "N": 35, "prob": measurement_distribution(17, 35).tolist()},
        "vectors": [
            _seal_vector(box, "ceiling", DEFAULT_SECRET, "maze flag (ascii)"),
            _seal_vector(box, "ceiling", "héllo café ✓".encode(), "utf-8 multibyte"),
            _seal_vector(box, "ceiling", bytes([255, 0, 128, 1, 254]), "binary / non-utf8"),
        ],
        "live": {**_seal_vector(box, "ceiling", DEFAULT_SECRET, "live"), "runs": 40},
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(challenge, fh)
        challenge_path = fh.name
    try:
        proc = subprocess.run(
            [node, os.path.join(REPO, "demo", "parity_check.js"), challenge_path],
            capture_output=True, text=True)
    finally:
        os.unlink(challenge_path)

    for ln in (proc.stdout + proc.stderr).strip().splitlines():
        print("   " + ln)
    c.check(proc.returncode == 0,
            "node cross-check: JS QFT matches numpy + byte-exact decryption + live sampling")


def main() -> int:
    print("=" * 68)
    print(" PQC — verifying the demo is an ACTUAL hack and ACTUAL PQC defense")
    print("=" * 68)
    c = Checker()
    verify_rsa_break(c)
    verify_mlkem_defense(c)
    verify_js_parity(c)
    print("\n" + "=" * 68)
    if c.failures:
        print(f" RESULT: \033[31m{c.failures} check(s) FAILED\033[0m")
        return 1
    if c.skips:
        print(f" RESULT: \033[33mPASSED with {c.skips} check(s) SKIPPED\033[0m — not fully verified "
              "(install any missing tools and re-run).")
        return 0
    print(" RESULT: \033[32mALL CHECKS PASSED\033[0m — the break and the defense are real.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
