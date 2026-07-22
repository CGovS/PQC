"""Shor's algorithm on a simulated low-qubit quantum computer.

The quantum core is genuine: we prepare the uniform superposition over a
counting register, entangle it with a work register holding ``a^x mod N``,
apply an inverse quantum Fourier transform (via the DFT), and measure under
the Born rule. Classical continued fractions turn the measured value into the
period ``r``, and ``gcd(a^(r/2) ± 1, N)`` yields the factors.

Honest limit: Shor's full statevector has ``2^(3n)`` amplitudes for an n-bit
modulus — a ``2n``-qubit counting register tensored with an ``n``-qubit work
register (``resource_estimate`` reports this). This simulator exploits the
period structure to hold only a ``2^(2n)``-sized counting column per distinct
work value, but even that counting register is built with a Python loop over
``M = 2^(2n)`` states, so the practical laptop ceiling is ~13-15 bits — enough
for the toy moduli, nowhere near real RSA. ``resource_estimate`` spells out the
gap.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

import numpy as np


def n_qubits_for(N: int) -> int:
    """Work-register size: bits needed to hold a residue mod N."""
    return max(1, math.ceil(math.log2(N)))


@dataclass
class PeriodFinding:
    a: int
    N: int
    t: int                       # counting qubits
    n: int                       # work qubits
    M: int                       # 2**t (size of counting register)
    measured_c: int
    period: int | None
    peaks: list[tuple[int, float]]  # top (c, probability) for visualization


def quantum_period_finding(a: int, N: int, *, rng: random.Random) -> PeriodFinding:
    """Simulate the quantum period-finding subroutine of Shor's algorithm."""
    n = n_qubits_for(N)
    t = 2 * n                     # standard choice: 2n counting qubits
    M = 1 << t

    # Entangled state after the modular-exponentiation oracle:
    #   |psi> = (1/sqrt(M)) * sum_x |x> |a^x mod N>
    # f(x) = a^x mod N cycles with period r, so only r distinct work values
    # appear. We group amplitude by work value and QFT each group's x-column.
    fx = np.empty(M, dtype=np.int64)
    val = 1
    for xi in range(M):
        fx[xi] = val
        val = (val * a) % N

    amp0 = 1.0 / math.sqrt(M)
    prob = np.zeros(M)
    for w in np.unique(fx):
        col = np.zeros(M, dtype=complex)
        col[np.where(fx == w)[0]] = amp0
        # Inverse QFT over the counting register (DFT up to convention).
        transformed = np.fft.fft(col) / math.sqrt(M)
        prob += np.abs(transformed) ** 2

    prob = prob / prob.sum()
    measured_c = int(rng.choices(range(M), weights=prob.tolist(), k=1)[0])

    # Top peaks for visualization, plus the actually-measured value so the
    # demo can always highlight it — Born sampling draws from the full
    # distribution, so measured_c need not be among the top 16.
    top = set(int(c) for c in np.argsort(prob)[::-1][:16])
    top.add(measured_c)
    peaks = sorted((c, float(prob[c])) for c in top)

    period = _period_from_measurement(measured_c, M, a, N)
    return PeriodFinding(a=a, N=N, t=t, n=n, M=M, measured_c=measured_c,
                         period=period, peaks=peaks)


def _continued_fraction(num: int, den: int) -> list[int]:
    cf = []
    while den:
        cf.append(num // den)
        num, den = den, num % den
    return cf


def _convergents(cf: list[int]):
    h0, h1, k0, k1 = 0, 1, 1, 0
    for term in cf:
        h, k = term * h1 + h0, term * k1 + k0
        yield h, k
        h0, h1, k0, k1 = h1, h, k1, k


def _period_from_measurement(c: int, M: int, a: int, N: int) -> int | None:
    """Recover period r from a measured value via continued fractions."""
    if c == 0:
        return None
    for _, k in _convergents(_continued_fraction(c, M)):
        if 0 < k < N and pow(a, k, N) == 1:
            return k
    return None


@dataclass
class ShorResult:
    N: int
    success: bool
    factors: tuple[int, int] | None = None
    a: int | None = None
    period: int | None = None
    attempts: list[dict] = field(default_factory=list)


def shor_factor(N: int, *, seed: int = 1, max_attempts: int = 40,
                force_quantum: bool = False) -> ShorResult:
    """Factor N using the simulated quantum period-finding subroutine.

    ``force_quantum`` skips the rare classical shortcut where a random ``a``
    happens to share a factor with N, so the factorization must come from the
    quantum period-finding subroutine — used by the demo to always exercise
    (and visualize) the quantum machinery.
    """
    rng = random.Random(seed)
    if N % 2 == 0:
        return ShorResult(N, True, factors=(2, N // 2))

    attempts: list[dict] = []
    for _ in range(max_attempts):
        a = rng.randrange(2, N)
        g = math.gcd(a, N)
        if g > 1:
            if force_quantum:
                continue
            # Rare classical shortcut: a shares a factor with N.
            attempts.append({"a": a, "lucky_gcd": g, "period": None, "peaks": []})
            return ShorResult(N, True, factors=(g, N // g), a=a, attempts=attempts)

        pf = quantum_period_finding(a, N, rng=rng)
        rec = {"a": a, "measured_c": pf.measured_c, "M": pf.M, "t": pf.t,
               "n": pf.n, "period": pf.period, "peaks": pf.peaks}
        attempts.append(rec)

        r = pf.period
        if r and r % 2 == 0:
            y = pow(a, r // 2, N)
            if y != N - 1:                       # a^(r/2) != -1 (mod N)
                for f in (math.gcd(y - 1, N), math.gcd(y + 1, N)):
                    if 1 < f < N and N % f == 0:
                        return ShorResult(N, True, factors=(f, N // f),
                                          a=a, period=r, attempts=attempts)

    return ShorResult(N, False, attempts=attempts)


def resource_estimate(bits: int) -> dict:
    """Rough logical-qubit cost of Shor for a ``bits``-bit modulus.

    Uses the textbook ~2n counting + n work qubits. The point is the contrast:
    the toy moduli are simulable; real RSA is not, by a wide margin.
    """
    return {
        "modulus_bits": bits,
        "counting_qubits": 2 * bits,
        "work_qubits": bits,
        "logical_qubits_approx": 3 * bits + 2,
        "statevector_amplitudes": f"2^{3 * bits}",
    }
