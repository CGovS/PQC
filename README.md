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
| 2 | Simulated Shor's algorithm that breaks the maze | ✅ built |
| 3 | End-to-end "the maze is broken" demonstration | ✅ built |
| 4 | Post-quantum migration (ML-KEM, FIPS 203) via a registry swap | ✅ built |
| 5 | Re-run the same attack against PQC — it fails | ✅ built |
| 6 | Hardening, docs, packaging | ⏳ ongoing |

**See it:** `make web` → open <http://localhost:8765/> for the visual
before/after — RSA cracked by the simulated quantum computer on the left,
ML-KEM holding against the identical attack on the right.

> **A note on the quantum simulator.** The plan named Qiskit; the shipped
> attacker is instead a from-scratch **numpy statevector simulation** (genuine
> superposition → quantum Fourier transform → Born-rule measurement →
> continued-fraction period extraction). Reason: Qiskit removed its built-in
> `Shor`, and Aer is a heavy, volatile dependency; a numpy statevector sim is
> transparent, reproducible, and honest about its `2^(2n)`-amplitude ceiling.
> A Qiskit circuit view can be added later without changing the result.

## Repository layout

```
cryptolayer/     the crypto-agility seam — the actual deliverable
  interface.py     the LockBox ABC every algorithm implements
  classical.py     toy RSA (DELIBERATELY WEAK — see below)
  pqc.py           ML-KEM (FIPS 203) via kyber-py, KEM-DEM hybrid
  registry.py      name -> algorithm; migration happens here in one line
maze/            the vulnerable application
  keys.py          the RSA modulus ladder + reporting metadata
  vault.py         seals/opens a secret — mentions no algorithm by name
  cli.py           `python -m maze.cli demo`
attacker/        the simulated quantum computer
  shor.py          statevector Shor: superposition -> QFT -> measure -> period
  break_maze.py    factor n, rebuild the private key, open the vault
  campaign.py      point the SAME attacker at RSA vs ML-KEM (Phase 5)
  report.py        emit the before/after data the web demo renders
demo/            the visual before/after (index.html + generated data)
tests/           round-trip + interface + attack + PQC tests (45)
```

The application (`maze/`) never imports a concrete algorithm; it asks the
registry for one by name. That is what lets the classical → post-quantum change
be configuration, not code.

## Quick start

```bash
make demo     # seal a secret with RSA and open it, no dependencies needed
make setup    # install numpy + kyber-py + pytest (for attacker, PQC, tests)
make test     # 45 tests: round-trip + interface + Shor attack + ML-KEM
make report   # regenerate the before/after attack data
make web      # serve the visual demo at http://localhost:8765/
```

The maze is pure standard library. The attacker needs `numpy`; the
post-quantum layer needs `kyber-py` (both installed by `make setup`).

## Honest constraints (read before trusting the demo)

- **The RSA here is a toy and broken by design.** Moduli are tiny (`n` ∈
  {15, 21, 35}) so that a *classical simulation* of Shor's algorithm can
  actually factor them. Never use `cryptolayer/classical.py` for anything real.
- **A simulated quantum computer cannot break real RSA.** A statevector
  simulator holds `2^n` amplitudes, so it caps out around a few dozen qubits —
  enough for these toy moduli (the maze factorization runs in a `2^18`-amplitude
  state), nowhere near RSA-2048 (`2^6144`). The attacker factors the toy moduli
  honestly *and* ships a resource estimate; that estimate — not the tiny live
  break — is what generalizes.
- **The post-quantum side is real, the DEM is not the point.** ML-KEM is the
  genuine FIPS 203 primitive (via `kyber-py`). Because a KEM only transports a
  shared secret, the payload is sealed with a stdlib encrypt-then-MAC DEM
  (SHA-256 CTR + HMAC-SHA-256); a production system would use AES-256-GCM or
  ChaCha20-Poly1305. Swapping the DEM does not change the migration story — the
  point is that the *public-key* primitive is now lattice-based, so Shor's
  algorithm has nothing to factor.

## License

Apache-2.0. See [LICENSE](LICENSE). (Copyright holder is currently `CGovS`;
replace with your legal name/entity before any formal release.)
