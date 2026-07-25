/* parity_check.js — prove the in-browser JS engine reproduces Python's.
 *
 * Reads a challenge generated FRESH by Python at run time (not a committed
 * snapshot) and adversarially checks the parts that actually matter:
 *
 *   1. QFT engine: the JS Born-rule distribution matches numpy's, element by
 *      element. This verifies the quantum machinery itself — a non-quantum
 *      stub (e.g. trial division) that returns the right factors would FAIL
 *      here, because it produces no distribution.
 *   2. Decryption: JS recovers byte-exact plaintext (compared as raw bytes, so
 *      binary/non-UTF-8 inputs count) matching a fresh Python decryption.
 *   3. Live sampling: across many breaks the measured value genuinely varies
 *      (asserted, not just printed) while the recovered bytes stay correct.
 *
 * Exits non-zero on any failure so `make verify` fails loudly.
 *
 *     node demo/parity_check.js <challenge.json>
 */
"use strict";
const fs = require("fs");
const QC = require("./quantum.js");

const challengePath = process.argv[2];
if (!challengePath) { console.error("usage: node parity_check.js <challenge.json>"); process.exit(2); }
const ch = JSON.parse(fs.readFileSync(challengePath, "utf8"));

let fails = 0;
const fail = (m) => { console.error("     FAIL: " + m); fails++; };
const pass = (m) => console.log("     ok: " + m);

// 1. QFT distribution parity — the real anti-tautology check.
{
  const { a, N, prob } = ch.dist;
  const js = QC.distribution(a, N);
  if (js.length !== prob.length) {
    fail(`distribution length ${js.length} != python ${prob.length}`);
  } else {
    let maxDiff = 0;
    for (let i = 0; i < prob.length; i++) maxDiff = Math.max(maxDiff, Math.abs(js[i] - prob[i]));
    if (maxDiff < 1e-9) pass(`QFT distribution matches numpy for a=${a}, N=${N} (max |Δ|=${maxDiff.toExponential(2)} over ${prob.length} outcomes)`);
    else fail(`QFT distribution diverges from numpy: max |Δ|=${maxDiff.toExponential(2)}`);
  }
}

// 2. Byte-exact decryption vs a fresh Python break (covers binary / multibyte).
for (const v of ch.vectors) {
  const res = QC.crackRSA({ n: v.n, e: v.e }, v.ciphertext); // full break, not a handed key
  if (res.bytesHex === v.plaintext_hex) pass(`byte-exact recovery vs Python: ${v.label}`);
  else fail(`byte mismatch (${v.label}): js=${res.bytesHex} python=${v.plaintext_hex}`);
}

// 3. Live sampling is asserted, not merely printed.
{
  const { n, e, ciphertext, plaintext_hex, runs } = ch.live;
  const seen = new Set();
  let bytesOK = 0;
  for (let i = 0; i < runs; i++) {
    const res = QC.crackRSA({ n, e }, ciphertext);
    seen.add(res.shor.pf.measuredC);
    if (res.bytesHex === plaintext_hex) bytesOK++;
  }
  if (bytesOK === runs) pass(`${runs}/${runs} independent live breaks recovered the exact bytes`);
  else fail(`${runs - bytesOK}/${runs} live breaks recovered wrong bytes`);
  if (seen.size >= 2) pass(`${seen.size} distinct Born-rule measurements across ${runs} runs (live sampling, not replay)`);
  else fail(`only ${seen.size} distinct measurement across ${runs} runs — sampling is not live`);
}

if (fails) { console.error(`JS/Python parity FAILED (${fails} check(s))`); process.exit(1); }
console.log("JS/Python parity OK — browser engine reproduces numpy's QFT and Python's byte-exact decryption.");
