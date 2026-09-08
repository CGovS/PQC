/* quantum.js — a real (tiny) quantum computer + RSA breaker, in the browser.
 *
 * This is NOT a replay of pre-computed numbers. When the demo calls shorFactor()
 * it genuinely:
 *   1. builds the superposition  Σ_x |x>|a^x mod N>  as a statevector,
 *   2. applies a real quantum Fourier transform (an FFT) to the counting register,
 *   3. samples a measurement under the Born rule (fresh randomness each run),
 *   4. turns the measured value into the period r by continued fractions,
 *   5. recovers the factors from gcd(a^(r/2) ± 1, N).
 * Then rsaDecrypt() reconstructs the private exponent and decrypts the maze's
 * real ciphertext — so the flag on screen is DERIVED from public data, not read
 * from a file. Re-run it and the measured value changes while the factors don't:
 * that is what a live quantum measurement looks like.
 *
 * The moduli are tiny by design (n ∈ {15,21,35}) so the statevector fits in a
 * browser. That is the same honest ceiling as the Python attacker; see the
 * README on why this scales to prove the point but cannot touch real RSA.
 *
 * Works in the browser (global `QC`) and under node (module.exports) so the
 * verification harness can cross-check it against the Python implementation.
 */
(function (root) {
  "use strict";

  // ---- integer helpers (small N: plain Number is exact) --------------------
  const iabs = (a) => (a < 0 ? -a : a);
  function gcdInt(a, b) { a = iabs(a); b = iabs(b); while (b) { [a, b] = [b, a % b]; } return a; }
  function powmodInt(base, exp, mod) {
    base %= mod; let r = 1;
    while (exp > 0) { if (exp & 1) r = (r * base) % mod; base = (base * base) % mod; exp >>= 1; }
    return r;
  }

  // ---- BigInt helpers (for the RSA reconstruction) -------------------------
  function egcdBig(a, b) { if (b === 0n) return [a, 1n, 0n]; const [g, x, y] = egcdBig(b, a % b); return [g, y, x - (a / b) * y]; }
  function modinvBig(a, m) { let [g, x] = egcdBig(((a % m) + m) % m, m); if (g !== 1n) throw new Error("no modular inverse"); return ((x % m) + m) % m; }
  function powmodBig(base, exp, mod) { base %= mod; let r = 1n; while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; base = (base * base) % mod; exp >>= 1n; } return r; }

  // ---- iterative radix-2 FFT (forward, sign=-1) matches numpy.fft.fft ------
  function fft(re, im, sign) {
    const n = re.length;
    for (let i = 1, j = 0; i < n; i++) {
      let bit = n >> 1;
      for (; j & bit; bit >>= 1) j ^= bit;
      j ^= bit;
      if (i < j) { [re[i], re[j]] = [re[j], re[i]]; [im[i], im[j]] = [im[j], im[i]]; }
    }
    for (let len = 2; len <= n; len <<= 1) {
      const ang = (sign * 2 * Math.PI) / len;
      const wr = Math.cos(ang), wi = Math.sin(ang);
      for (let i = 0; i < n; i += len) {
        let cr = 1, ci = 0;
        for (let k = 0; k < len >> 1; k++) {
          const a = i + k, b = i + k + (len >> 1);
          const vr = re[b] * cr - im[b] * ci;
          const vi = re[b] * ci + im[b] * cr;
          re[b] = re[a] - vr; im[b] = im[a] - vi;
          re[a] = re[a] + vr; im[a] = im[a] + vi;
          const ncr = cr * wr - ci * wi; ci = cr * wi + ci * wr; cr = ncr;
        }
      }
    }
  }

  const bitLen = (N) => Math.max(1, Math.ceil(Math.log2(N)));

  // ---- continued-fraction period extraction --------------------------------
  function periodFromMeasurement(c, M, a, N) {
    if (c === 0) return null;
    let num = c, den = M, h0 = 0, h1 = 1, k0 = 1, k1 = 0;
    while (den) {
      const q = Math.floor(num / den);
      [num, den] = [den, num % den];
      const h = q * h1 + h0, k = q * k1 + k0;
      if (k > 0 && k < N && powmodInt(a, k, N) === 1) return k;
      [h0, h1, k0, k1] = [h1, h, k1, k];
    }
    return null;
  }

  // ---- the measurement distribution (the actual QFT output) ----------------
  // Builds Σ_x |x>|a^x mod N>, QFTs the counting register, returns the Born-rule
  // probability over measured values. Exposed via QC.distribution so the
  // verification harness can compare this engine to Python's numpy statevector
  // element-by-element — i.e. verify the QUANTUM machinery, not just the factors.
  function _distribution(a, N) {
    if (!Number.isInteger(N) || N < 3 || N > 127 || !Number.isInteger(a) || a <= 1 || a >= N || gcdInt(a,N) !== 1) throw new RangeError("simulation requires a coprime base and 3 <= N <= 127");
    const n = bitLen(N), t = 2 * n, M = 1 << t;
    const fx = new Int32Array(M);
    let val = 1;
    for (let x = 0; x < M; x++) { fx[x] = val; val = (val * a) % N; }

    const workVals = Array.from(new Set(fx));
    const prob = new Float64Array(M);
    const amp0 = 1 / Math.sqrt(M);
    for (const w of workVals) {
      const re = new Float64Array(M), im = new Float64Array(M);
      for (let x = 0; x < M; x++) if (fx[x] === w) re[x] = amp0;
      fft(re, im, -1);
      const inv = 1 / Math.sqrt(M);
      for (let c = 0; c < M; c++) { const R = re[c] * inv, I = im[c] * inv; prob[c] += R * R + I * I; }
    }
    let s = 0; for (let c = 0; c < M; c++) s += prob[c];
    for (let c = 0; c < M; c++) prob[c] /= s;
    return { n, t, M, prob };
  }

  function distribution(a, N) { return Array.from(_distribution(a, N).prob); }

  // ---- the quantum period-finding subroutine (real statevector sim) --------
  function quantumPeriodFinding(a, N, rng) {
    const { n, t, M, prob } = _distribution(a, N);

    // Born-rule measurement (genuine randomness → different c each run)
    let rnd = rng(), acc = 0, measuredC = 0;
    for (let c = 0; c < M; c++) { acc += prob[c]; if (rnd <= acc) { measuredC = c; break; } }

    // top peaks for the chart, plus the measured value so it always renders
    const idx = Array.from(prob.keys()).sort((i, j) => prob[j] - prob[i]).slice(0, 16);
    const set = new Set(idx); set.add(measuredC);
    const peaks = Array.from(set).sort((i, j) => i - j).map((c) => [c, prob[c]]);

    return { a, N, n, t, M, measuredC, period: periodFromMeasurement(measuredC, M, a, N), peaks };
  }

  // ---- Shor's algorithm ----------------------------------------------------
  function shorFactor(N, opts) {
    if (!Number.isInteger(N) || N < 3 || N > 127) throw new RangeError("educational simulator supports 3 <= N <= 127");
    opts = opts || {};
    const rng = opts.rng || Math.random;
    const forceQuantum = opts.forceQuantum !== false; // default: exercise the quantum path
    const maxAttempts = opts.maxAttempts || 40;
    if (N % 2 === 0) return { N, success: true, factors: [2, N / 2], attempts: [] };

    const attempts = [];
    for (let i = 0; i < maxAttempts; i++) {
      const a = 2 + Math.floor(rng() * (N - 2)); // in [2, N-1]
      const g = gcdInt(a, N);
      if (g > 1) {
        if (forceQuantum) { continue; }
        attempts.push({ a, luckyGcd: g, period: null, peaks: [] });
        return { N, success: true, factors: [g, N / g], a, attempts };
      }
      const pf = quantumPeriodFinding(a, N, rng);
      attempts.push(pf);
      // period may occasionally be a multiple of the true order; the
      // `N % f === 0` divisibility guard below rejects any bad factor, so a
      // non-useful measurement just costs a retry — never a wrong result.
      const r = pf.period;
      if (r && r % 2 === 0) {
        const half = powmodInt(a, r / 2, N);
        if (half !== N - 1) {
          for (const f of [gcdInt(half - 1, N), gcdInt(half + 1, N)]) {
            if (f > 1 && f < N && N % f === 0) {
              return { N, success: true, factors: [f, N / f], a, period: r, half, pf, attempts };
            }
          }
        }
      }
    }
    return { N, success: false, attempts };
  }

  // ---- toy-RSA private-key reconstruction + decryption ---------------------
  // Recover d from the factored modulus, then decrypt the maze ciphertext.
  function recoverPrivateExponent(e, p, q) {
    const phi = BigInt(p - 1) * BigInt(q - 1);
    return modinvBig(BigInt(e), phi);
  }

  const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const decodeUtf8 = (bytes) =>
    typeof TextDecoder !== "undefined" ? new TextDecoder().decode(bytes) : Buffer.from(bytes).toString("utf8");

  // payload = {n, len, c:[...]} exactly as cryptolayer.classical.RSALockBox emits.
  // Returns the raw recovered bytes — the byte-exact analogue of Python's
  // RSALockBox.unlock (which returns bytes, not str). Throws if the reconstructed
  // integer does not fit in payload.len bytes, mirroring Python's to_bytes
  // OverflowError instead of silently truncating a malformed/adversarial payload.
  function rsaDecryptBytes(payload, d, n) {
    if (payload.n !== n || !Number.isInteger(payload.len) || payload.len < 0 || payload.len > 4096 || !Array.isArray(payload.c) || !payload.c.length || payload.c.length > 32768 || payload.c.some(c => !Number.isInteger(c) || c < 0 || c >= n)) throw new RangeError("invalid toy RSA ciphertext");
    const N = BigInt(n), D = typeof d === "bigint" ? d : BigInt(d), base = BigInt(n);
    const digits = payload.c.map((c) => powmodBig(BigInt(c), D, N)); // c^d mod n
    let val = 0n, p = 1n;
    for (const dig of digits) { val += dig * p; p *= base; } // little-endian base-n
    const bytes = new Uint8Array(payload.len);
    for (let i = payload.len - 1; i >= 0; i--) { bytes[i] = Number(val & 0xffn); val >>= 8n; }
    if (val !== 0n) throw new RangeError("plaintext exceeds payload.len bytes (corrupt payload)");
    return bytes;
  }

  // Text view of the recovered plaintext (for display). Byte-exact recovery is
  // rsaDecryptBytes; UTF-8 decoding here is display-only and lossy for binary.
  function rsaDecrypt(payload, d, n) { return decodeUtf8(rsaDecryptBytes(payload, d, n)); }

  // The attacker's target-acquisition, identical to Python's _factoring_target:
  // Shor needs an integer modulus from the public key. RSA exposes one (`n`); a
  // lattice (ML-KEM) public key exposes none, so this returns null for it.
  function probeFactoringTarget(pub) { return pub && Number.isInteger(pub.n) ? pub.n : null; }

  // Full break: public (n,e) + ciphertext -> factors -> d -> plaintext.
  function crackRSA(pub, ciphertextJSON, opts) {
    const shor = shorFactor(pub.n, opts);
    if (!shor.success) throw new Error("quantum factoring failed");
    const [p, q] = shor.factors;
    const d = recoverPrivateExponent(pub.e, p, q); // BigInt, full precision
    const payload = typeof ciphertextJSON === "string" ? JSON.parse(ciphertextJSON) : ciphertextJSON;
    const bytes = rsaDecryptBytes(payload, d, pub.n);
    return { shor, factors: [p, q], d, bytesHex: bytesToHex(bytes), plaintext: decodeUtf8(bytes) };
  }

  const QC = {
    gcdInt, powmodInt, periodFromMeasurement, quantumPeriodFinding, distribution,
    shorFactor, recoverPrivateExponent, rsaDecrypt, rsaDecryptBytes, bytesToHex,
    probeFactoringTarget, crackRSA, bitLen,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = QC;
  root.QC = QC;
})(typeof self !== "undefined" ? self : this);
