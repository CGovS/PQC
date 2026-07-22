"""Generate the before/after attack report consumed by the visual demo.

Runs the whole story on real data:

  BEFORE  seal a secret with classical RSA, crack it with the simulated Shor
          attack (full quantum period-finding trace).
  AFTER   re-seal the *same* secret with ML-KEM (a one-name registry swap),
          run the *same* attacker — it has nothing to factor and fails.

Emits JSON and a JS shim so the demo works over http:// or file://.

    python -m attacker.report            # default RSA level = ceiling (n=35)
"""

from __future__ import annotations

import argparse
import json
import os

from attacker.campaign import run_quantum_attack
from attacker.shor import resource_estimate
from cryptolayer.pqc import DEFAULT_PQC_LEVEL
from cryptolayer.registry import get_lockbox
from maze.cli import DEFAULT_SECRET
from maze.keys import LEVEL_INFO, make_keypair
from maze.vault import open_vault, seal

DEMO_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demo")


def build_report(level: str = "ceiling", seed: int = 1,
                 pqc_level: str = DEFAULT_PQC_LEVEL) -> dict:
    secret = DEFAULT_SECRET
    info = LEVEL_INFO[level]

    # --- BEFORE: classical RSA, cracked by the simulated quantum computer ----
    rsa_kp = make_keypair(level)
    rsa_vault = seal(secret, rsa_kp.public, algorithm="rsa-toy", hint=f"RSA-{info['n']}")
    before_attack = run_quantum_attack(rsa_vault, rsa_kp.public, seed=seed)

    # --- AFTER: same secret, one-line algorithm swap to ML-KEM ---------------
    pqc_algo = f"ml-kem-{pqc_level}"
    pqc_box = get_lockbox(pqc_algo)
    pqc_kp = pqc_box.generate_keypair(level=pqc_level)
    pqc_vault = seal(secret, pqc_kp.public, algorithm=pqc_algo, hint=pqc_algo.upper())
    after_attack = run_quantum_attack(pqc_vault, pqc_kp.public, seed=seed)
    # The legitimate holder still opens it — migration preserved functionality.
    opened = open_vault(pqc_vault, pqc_kp.private)
    assert opened == secret, "ML-KEM round-trip failed"

    return {
        "secret_plaintext": secret.decode(),
        "before": {
            "algorithm": "rsa-toy",
            "label": "Classical RSA",
            "family": "integer factoring",
            "quantum_vulnerable": True,
            "n": info["n"],
            "e": rsa_kp.public.e,
            "bits": info["bits"],
            "note": info["note"],
            "ciphertext": rsa_vault.ciphertext.decode("utf-8"),
            "ciphertext_bytes": len(rsa_vault.ciphertext),
            "attack": before_attack,
        },
        "after": {
            "algorithm": pqc_algo,
            "label": f"{pqc_algo.upper()} (FIPS 203)",
            "family": "Module-LWE (lattice)",
            "quantum_vulnerable": False,
            "public_bytes": len(pqc_kp.public.ek),
            "private_bytes": len(pqc_kp.private.dk),
            "ciphertext_preview": pqc_vault.ciphertext[:80].decode("utf-8", "replace"),
            "ciphertext_bytes": len(pqc_vault.ciphertext),
            "attack": after_attack,
            "opened_with_key": opened == secret,
        },
        "resources": {
            "toy": resource_estimate(info["bits"]),
            "rsa2048": resource_estimate(2048),
        },
        "migration": {
            "application_code_changes": 0,
            "registry_line": f'register("{pqc_algo}", lambda: MLKEMLockBox("{pqc_level}"))',
            "note": "The maze app never named an algorithm; only the registry changed.",
        },
    }


def write_report(report: dict) -> tuple[str, str]:
    os.makedirs(DEMO_DIR, exist_ok=True)
    json_path = os.path.join(DEMO_DIR, "attack_report.json")
    js_path = os.path.join(DEMO_DIR, "attack_data.js")
    text = json.dumps(report, indent=2)
    with open(json_path, "w") as fh:
        fh.write(text)
    with open(js_path, "w") as fh:
        fh.write("window.ATTACK = " + text + ";\n")
    return json_path, js_path


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="attacker.report")
    parser.add_argument("--level", default="ceiling", choices=list(LEVEL_INFO))
    parser.add_argument("--seed", type=int, default=3)
    parser.add_argument("--pqc-level", default=DEFAULT_PQC_LEVEL, choices=["512", "768", "1024"])
    args = parser.parse_args(argv)

    report = build_report(level=args.level, seed=args.seed, pqc_level=args.pqc_level)
    json_path, js_path = write_report(report)

    b = report["before"]["attack"]
    a = report["after"]["attack"]
    print(f"[report] BEFORE rsa-toy n={report['before']['n']}: "
          f"factored {b['factors']} (a={b['a']}, r={b['period']}) in "
          f"{b['attempts']} attempt(s) -> secret revealed.")
    print(f"[report] AFTER  {report['after']['algorithm']}: "
          f"attack applicable={a['applicable']}, success={a['success']} "
          f"(vault still opens with real key: {report['after']['opened_with_key']}).")
    print(f"[report] wrote {json_path}")
    print(f"[report] wrote {js_path}")


if __name__ == "__main__":
    main()
