# Architecture and implementation audit — 2026-09-07

Read scope: all tracked source, tests, static assets, generated data, packaging,
license, and contributor documentation in the v2.2.0 checkout. This is an
implementation review with targeted tests, not an independent security audit.

## Confirmed defects and changes

| Finding | Impact | Resolution |
|---|---|---|
| Main RSA key had e=d=5 (n=35) | The public exponent itself decrypted the vault, bypassing Shor | Main challenge is n=33, e=3, d=7; wrong-exponent regression |
| Page claimed “35-bit” RSA | n=35 was actually 6 bits | Explicit n=33 / 6-bit label |
| PQC chart plotted random flat noise | Invented measurement implied quantum resistance | Removed; report “not applicable,” show real negative checks |
| PQC target constructed without the actual public key | Missing-field check was circular | Return actual ML-KEM public bytes and typed Python dispatch; no inference of security from a missing field |
| UI shipped plaintext and precalculated RSA answers | Animation was not a challenge boundary | Live API returns commitment + public data only; worker gets only RSA public key and ciphertext |
| Custom SHA256 stream cipher and HMAC | Unreviewed DEM despite AEAD explanations | HKDF-SHA256 + AES-256-GCM, versioned envelope; legacy payloads rejected |
| Invalid ML-KEM level silently fell back | Configuration errors were hidden | Reject mismatched/unknown parameter sets |
| RSA parser accepted mismatched modulus and zero-length truncation | Malformed payloads could silently decode | Validate fields/ranges and reject overflow in Python and JS |
| Simulator allowed unbounded shifts/allocation | Malformed input could hang/exhaust memory | Explicit educational range, browser worker and timeout |
| UI errors could leave the button disabled | Failed run looked stuck | Catch/finally, incomplete state, clear retry |
| Missing Node returned success from verification | Incomplete verification looked successful to CI | Exit 2 for skipped required work |
| “One line is the whole migration” | Omitted stored ciphertext, PKI, hybrid protocols and deployment | Scope registry claim to this application and explain enterprise work |

## Verification strategy

- Main RSA public-exponent failure, all-byte round-trip, actual Shor recovery.
- ML-KEM deterministic public-key equivalence and two-way encapsulation interop
  with the independent OpenSSL provider (cryptography 50).
- AEAD owner/binary/empty round-trips, every envelope field altered, wrong keys,
  repeated encryption randomness, mismatched algorithm parameters.
- JS/NumPy distributions for (2,15), (2,21), (13,33), (17,35), plus analytic
  order-4 spectrum. Controlled quantiles check the actual sampling step.
- Fresh challenge boundary: no private keys, plaintext, or factors in API data;
  different commitments and ciphertexts each run; recovered digest matches.
- Browser: encryption request → isolated attack worker → digest verification →
  red breach; PQC generation → real access/tamper checks → unsupported attack.

## Important limits

The NumPy/JS method sums QFT probabilities over grouped work-register values;
it models an ideal quantum subroutine but is not a decomposed Qiskit circuit.
There is no demonstrated speed advantage: tiny RSA is trivial classically.
The historical warmup moduli 15/21 are degenerate and are labeled educational.
An exact d equality test chooses one representative modulo phi; other exponents
congruent modulo lambda can also be valid decryption keys. This is not evidence
that congruent exponents are “wrong.”

The PQC provider remains educational/non-constant-time. AES-GCM improves the
payload primitive but does not turn this app into production cryptography.
No signature migration, hybrid combiner, certificate lifecycle, or enterprise
discovery implementation is present. Visual paths are metaphorical and paced
after computations; only probability charts correspond to numerical results.

## Design references

Linear (https://linear.app) and Stripe (https://stripe.com) informed the use of
restrained typography, spacing, and progressive detail. No assets were copied.

## Completed verification

67 tests passed. Four JS/NumPy distributions agreed within 2.8e-15; the
analytic case and controlled-quantile sampler checks passed. Forty full browser
engine breaks recovered the expected bytes. OpenSSL interoperability passed
both directions. Desktop and 390px mobile browser runs displayed verified
results without horizontal overflow or JavaScript errors. An injected fetch
failure produced an incomplete state with a working retry; the retry generated
a new flag and completed. The old answer-bearing asset returns HTTP 404.
