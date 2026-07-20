# PQC — a crypto-agility layer, demonstrated end to end

**Thesis:** the hard part of post-quantum migration is not the new algorithms
(those are finished, standardized, and free) — it is that most software
*hardcodes* its cryptography and cannot swap it. This project builds the thing
enterprises actually lack — a **crypto-agility layer** — and then proves its
value with a story you can run on a laptop:

1. a small application (**the maze**) locks a secret using classical RSA;
2. a **simulated Shor's algorithm** factors the RSA modulus and opens it;
3. the **same application**, unchanged, is re-sealed with a post-quantum
   algorithm through a one-line registry swap, and the same attack fails.

> **Why this matters (the honest version).** The NIST post-quantum standards
> (FIPS 203 / 204 / 205) are done and open source (liboqs, OpenSSL 3.5+).
> Re-implementing them adds no value. The genuine, unsolved enterprise problem
> is **migration**: crypto *discovery* (finding everywhere RSA/ECC is used),
> **crypto-agility** (systems that hardcode the algorithm), and **hybrid
> rollout**. The urgency is "harvest now, decrypt later" plus compliance
> deadlines (NSM-10 / CNSA 2.0) — *not* a claim that a quantum computer is
> imminent; that timeline is genuinely uncertain. This repo targets the part
> that is real: agility.

## Status

| Phase | What | State |
|------:|------|-------|
| 1 | Crypto-agility layer + classical RSA maze + OSS packaging | ✅ built |
| 2 | Simulated Shor's algorithm that breaks the maze (Qiskit) | ⏳ next |
| 3 | End-to-end "the maze is broken" demonstration | ⏳ |
| 4 | Post-quantum migration (ML-KEM) via a registry swap | ⏳ |
| 5 | Re-run the same attack against PQC — it fails | ⏳ |

## Repository layout

```
cryptolayer/     the crypto-agility seam — the actual deliverable
  interface.py     the LockBox ABC every algorithm implements
  classical.py     toy RSA (DELIBERATELY WEAK — see below)
  registry.py      name -> algorithm; migration happens here in one line
maze/            the vulnerable application
  keys.py          the RSA modulus ladder + reporting metadata
  vault.py         seals/opens a secret — mentions no algorithm by name
  cli.py           `python -m maze.cli demo`
tests/           round-trip + interface tests
```

The application (`maze/`) never imports a concrete algorithm; it asks the
registry for one by name. That is what lets the classical → post-quantum change
be configuration, not code.

## Quick start

```bash
make demo     # seal a secret with RSA and open it, no dependencies needed
make test     # round-trip + interface tests (needs: make setup)
```

Requires Python 3.11+. Phase 1 is pure standard library — no third-party
packages — so it reproduces anywhere.

## Honest constraints (read before trusting the demo)

- **The RSA here is a toy and broken by design.** Moduli are tiny (`n` ∈
  {15, 21, 35}) so that a *classical simulation* of Shor's algorithm can
  actually factor them. Never use `cryptolayer/classical.py` for anything real.
- **A simulated quantum computer cannot break real RSA.** A statevector
  simulator holds `2^n` amplitudes, so it caps out around a few dozen qubits —
  enough for these toy moduli, nowhere near RSA-2048. Phase 2 will factor the
  toy moduli honestly *and* ship a resource estimate showing what real key
  sizes would cost a fault-tolerant machine. That estimate — not the tiny live
  break — is what generalizes.

## License

Apache-2.0. See [LICENSE](LICENSE). (Copyright holder is currently `CGovS`;
replace with your legal name/entity before any formal release.)
