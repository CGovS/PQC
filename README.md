# PQC Lab — same secret, different ending

An educational side-by-side experiment. A local Python server encrypts a fresh
hidden flag with toy RSA and ML-KEM-768 + AES-256-GCM. A browser worker receives
only RSA public data, simulates Shor's period-finding, recovers the private
exponent, and decrypts the flag. Animated mazes illustrate execution milestones.

## Run locally

Python 3.14 and Node.js 26 were used for the tested environment (Python 3.11+
supported by the package). From the source checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pip install --no-deps -e .
make web
```

Open http://localhost:8765. `make web PORT=8766` selects another port.
The new UI requires this server: a static file server cannot perform the
live encryption. If the engine is missing, the page says so; it never falls
back to recorded results. No external services or credentials are needed.

## Architecture and trust boundary

```text
browser → POST /api/run → maze/lab.py
                           ├─ registry → toy RSA → vault ciphertext
                           └─ registry → ML-KEM → HKDF → AES-GCM → vault ciphertext
browser ← public keys, ciphertext, operation outputs, SHA-256 commitment
   └─ isolated worker → Shor simulation → recovered RSA key → decrypted bytes
browser → compare SHA-256(recovered bytes) with the commitment
```

- `cryptolayer/`: interchangeable `LockBox` implementations and lazy registry.
- `maze/vault.py`: shared seal/open operations. `maze/lab.py`: creates a fresh
  challenge and performs owner, tamper, and wrong-key checks.
- `maze/server.py`: loopback server with a public asset allowlist, local Host/
  Origin checks, and no code execution endpoint or arbitrary file serving.
- `attacker/shor.py`: ideal period-finding simulation with NumPy FFT;
  `break_maze.py`: factor → exponent → decrypt;
  `campaign.py`: RSA-specific attack dispatch.
- `demo/quantum.js`: equivalent JavaScript simulation; `worker.js`: runs it
  off the main UI thread; `app.js`: presentation and digest verification.
- `attacker/report.py`: optional offline report, explicitly separate from the
  live demo. Its plaintext and computed factors are **not served to the UI**.
- `attacker/verify.py`, `demo/parity_check.js`, `tests/`: verification.

The live response never includes the flag, private keys, or RSA factors.
Encryption code shown in the drawer is retrieved from the executed source.
Operation timings are measured server-side. The animation plays completed
results at a readable pace; it is not a debugger stepping the CPU instruction
by instruction. The maze route is illustrative, not Shor searching corridors.

## What is real

**RSA:** the main demonstration uses n=33, e=3, d=7. It applies textbook RSA to
base-n digits and recovers the bytes using the factored private key. The former
n=35 example had e=d=5 and could decrypt with the public exponent: that flaw is
fixed and regression-tested. The 15/21 teaching cases remain in CLI tests and
are also degenerate; they are not the main browser demonstration.

**Shor:** both engines explicitly calculate modular powers, Fourier-transform
work-register columns, sum Born probabilities, sample, recover candidate periods
by continued fractions, and extract factors with gcd. The demo disables the
lucky classical gcd shortcut. Invalid measurements are retried and logged.
This is a classical simulation of ideal Shor period-finding, **not Qiskit or a
physical quantum computer**. It cannot demonstrate a practical RSA-2048 break.
N is limited to 127 to prevent runaway allocation.

**PQC:** kyber-py implements ML-KEM per FIPS 203. Tests independently compare
keys and encapsulation/decapsulation with OpenSSL through cryptography, in
both directions. HKDF-SHA256 derives a 256-bit key; AES-GCM encrypts/authenticates
the payload. Format, parameter set, and KEM ciphertext are bound as associated
data. The previous custom SHA256 stream/HMAC envelope is no longer accepted.
This wire-format change is versioned as `pqc-lab-v2`.

**Limits:** kyber-py is educational and not constant-time. This is not a
production protocol, security certification, or FIPS-validated module.
Shor's RSA factoring attack is *not applicable* to ML-KEM. A missing `n` field
is not evidence of security, and no PQC spectrum is calculated or invented.
Owner round-trip, wrong-key rejection, and tamper rejection are real but do not
prove resistance to every classical or quantum attack.

## Verification

```sh
make test       # regression tests, analytic QFT check, independent ML-KEM interop
make verify     # RSA recovery, negative PQC checks, JS/NumPy distributions
```

Distribution parity covers several bases/moduli plus an analytic order-4 case.
Controlled random draws check inverse-CDF sampling. Fresh byte vectors include
UTF-8 and binary data. Missing Node makes verification incomplete (exit 2), not
successful. Observing different samples alone is not a proof of quantum
computation. See `docs/AUDIT.md` for findings and practical limits.

## Real migration

The registry makes the algorithm selectable for this already-abstracted app.
A real company must inventory crypto, select compatible protocols/providers,
rotate keys, re-encrypt or rewrap stored data, handle certificates/signatures,
test interoperability/performance, and prevent silent downgrades. Classical +
PQC hybrid key establishment requires a reviewed combiner/protocol: having two
registered algorithms is not a hybrid implementation.

The suggested human gates are: approve inventory/scope; review a staging
migration and compatibility evidence; approve a production rollout and rollback
policy. Agents can prepare these artifacts; humans own production decisions.

Sources: [NIST ML-KEM](https://csrc.nist.gov/pubs/fips/203/final),
[IBM Shor tutorial](https://quantum.cloud.ibm.com/docs/en/tutorials/shors-algorithm),
[NIST migration project](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc),
[kyber-py limitations](https://github.com/GiacomoPope/kyber-py).

Apache-2.0; see LICENSE. Local version snapshots live in ignored `backups/`.
