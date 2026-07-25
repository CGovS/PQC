"""Post-quantum LockBox — ML-KEM (FIPS 203) behind the same interface.

This is the Phase 4 payoff: the application already talks only to ``LockBox``
and picks an algorithm by name, so making the maze quantum-resistant is adding
this file and one ``register(...)`` line — *zero* application changes.

ML-KEM is a key-encapsulation mechanism, not a general encryptor, so this uses
the standard **KEM-DEM** construction — exactly how post-quantum crypto is
deployed in practice:

    encapsulate a shared secret with ML-KEM  (the quantum-resistant part)
      -> derive symmetric keys from it       (a KDF)
        -> encrypt the plaintext with them   (the DEM)

The KEM is real (FIPS 203 via ``kyber-py``). The DEM here is a stdlib
encrypt-then-MAC (SHA-256 counter-mode stream + HMAC-SHA-256); a production
system would drop in AES-256-GCM or ChaCha20-Poly1305. Swapping the DEM does
not change the migration story — the point is that the *public-key* primitive
is now lattice-based, and Shor's algorithm has no purchase on it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

from .interface import KeyPair, LockBox

# Security level -> FIPS 203 parameter set.
_PARAMS = {"512": ML_KEM_512, "768": ML_KEM_768, "1024": ML_KEM_1024}
DEFAULT_PQC_LEVEL = "768"


@dataclass(frozen=True)
class MLKEMPublicKey:
    level: str
    ek: bytes            # encapsulation (public) key


@dataclass(frozen=True)
class MLKEMPrivateKey:
    level: str
    dk: bytes            # decapsulation (secret) key


def _kdf(shared_secret: bytes, label: bytes) -> bytes:
    """Derive a 32-byte subkey from the KEM shared secret (HKDF-Expand-style)."""
    return hmac.new(shared_secret, label, hashlib.sha256).digest()


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    """SHA-256 counter-mode keystream of length ``n``."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


class MLKEMLockBox(LockBox):
    """ML-KEM (FIPS 203) + a stdlib DEM, behind the crypto-agility interface."""

    quantum_vulnerable = False

    def __init__(self, level: str = DEFAULT_PQC_LEVEL) -> None:
        if level not in _PARAMS:
            raise KeyError(f"unknown ML-KEM level '{level}'. available: {sorted(_PARAMS)}")
        self.level = level
        self.algorithm = f"ml-kem-{level}"
        self._kem = _PARAMS[level]

    def generate_keypair(self, *, level: str | None = None) -> KeyPair:
        kem = _PARAMS[level] if level in _PARAMS else self._kem
        lvl = level if level in _PARAMS else self.level
        ek, dk = kem.keygen()
        return KeyPair(MLKEMPublicKey(lvl, ek), MLKEMPrivateKey(lvl, dk))

    def lock(self, public: MLKEMPublicKey, plaintext: bytes) -> bytes:
        kem = _PARAMS[public.level]
        shared_secret, kem_ct = kem.encaps(public.ek)
        enc_key = _kdf(shared_secret, b"pqc-dem-enc")
        mac_key = _kdf(shared_secret, b"pqc-dem-mac")

        nonce = hashlib.sha256(kem_ct).digest()[:16]  # unique per encapsulation
        body = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
        # Bind the level (associated data) into the MAC so a tampered level
        # fails authentication rather than an incidental parse/size error.
        aad = public.level.encode()
        tag = hmac.new(mac_key, aad + b"|" + kem_ct + nonce + body, hashlib.sha256).digest()

        payload = {
            "level": public.level,
            "kem_ct": base64.b64encode(kem_ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "body": base64.b64encode(body).decode(),
            "tag": base64.b64encode(tag).decode(),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def unlock(self, private: MLKEMPrivateKey, ciphertext: bytes) -> bytes:
        payload = json.loads(ciphertext.decode("utf-8"))
        kem = _PARAMS[payload["level"]]
        kem_ct = base64.b64decode(payload["kem_ct"])
        nonce = base64.b64decode(payload["nonce"])
        body = base64.b64decode(payload["body"])
        tag = base64.b64decode(payload["tag"])

        shared_secret = kem.decaps(private.dk, kem_ct)
        enc_key = _kdf(shared_secret, b"pqc-dem-enc")
        mac_key = _kdf(shared_secret, b"pqc-dem-mac")

        aad = payload["level"].encode()
        expected = hmac.new(mac_key, aad + b"|" + kem_ct + nonce + body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise ValueError("authentication failed — wrong key or tampered ciphertext")

        return bytes(a ^ b for a, b in zip(body, _keystream(enc_key, nonce, len(body))))
