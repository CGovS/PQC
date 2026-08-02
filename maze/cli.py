"""Command-line demo for the maze.

    python -m maze.cli demo --level warmup

Seals a secret into a vault and opens it with the private key, then explains
what an attacker without that key would have to do (factor the modulus — the
job of the Phase 2 simulated Shor attack).
"""

from __future__ import annotations

import argparse
from typing import Sequence

from maze.keys import DEFAULT_LEVEL, LEVEL_INFO, make_keypair
from maze.vault import open_vault, seal

DEFAULT_SECRET = b"FLAG{h4rv35t_n0w_d3crypt_l4t3r}"


def cmd_demo(args: argparse.Namespace) -> None:
    level = args.level
    info = LEVEL_INFO[level]
    kp = make_keypair(level)

    print(f"[maze] level={level}  RSA modulus n={info['n']} "
          f"(e={kp.public.e}, {info['bits']} bits) — {info['note']}")

    vault = seal(DEFAULT_SECRET, kp.public, hint=f"RSA-{info['n']}")
    print(f"[maze] sealed vault  algorithm={vault.algorithm}  "
          f"quantum_vulnerable={vault.quantum_vulnerable}")
    print(f"[maze] ciphertext (opaque): {vault.ciphertext[:60]!r}...")

    opened = open_vault(vault, kp.private)
    assert opened == DEFAULT_SECRET, "round-trip failed"
    print(f"[maze] opened with private key: {opened.decode()}")

    print()
    print("An attacker holding only the public key must recover the private")
    print(f"exponent d, which means factoring n={info['n']}. Doing that with a")
    print("simulated Shor's algorithm is Phase 2 of this project.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maze", description="Classical-crypto maze (Phase 1)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="seal and open a vault end-to-end")
    demo.add_argument(
        "--level", default=DEFAULT_LEVEL, choices=list(LEVEL_INFO),
        help="RSA security level / modulus size",
    )
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
