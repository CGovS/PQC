"""Educational ML-KEM + HKDF-SHA256 + AES-256-GCM envelope.

ML-KEM is implemented by kyber-py, an educational, non-constant-time library.
This versioned demo envelope is NOT a standardized transport protocol or a
FIPS-validated cryptographic module. Legacy custom-DEM ciphertext is rejected.
"""
from __future__ import annotations
import base64
import json
import os
from dataclasses import dataclass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from .interface import KeyPair, LockBox

_PARAMS = {"512": ML_KEM_512, "768": ML_KEM_768, "1024": ML_KEM_1024}
DEFAULT_PQC_LEVEL = "768"
FORMAT = "pqc-lab-v2"

@dataclass(frozen=True)
class MLKEMPublicKey:
    level: str
    ek: bytes

@dataclass(frozen=True)
class MLKEMPrivateKey:
    level: str
    dk: bytes


def _aad(level: str, kem_ct: bytes) -> bytes:
    return f"{FORMAT}|ml-kem-{level}|aes-256-gcm|".encode() + kem_ct


def _derive(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=aad).derive(shared)


class MLKEMLockBox(LockBox):
    """Real ML-KEM primitive; educational provider and demo-only protocol."""
    quantum_vulnerable = False

    def __init__(self, level: str = DEFAULT_PQC_LEVEL) -> None:
        if level not in _PARAMS:
            raise ValueError("unknown ML-KEM parameter set")
        self.level = level
        self.algorithm = f"ml-kem-{level}"
        self._kem = _PARAMS[level]

    def generate_keypair(self, *, level: str | None = None) -> KeyPair:
        if level is not None and level != self.level:
            raise ValueError("key parameters must match the selected algorithm")
        ek, dk = self._kem.keygen()
        return KeyPair(MLKEMPublicKey(self.level, ek), MLKEMPrivateKey(self.level, dk))

    def lock(self, public: MLKEMPublicKey, plaintext: bytes) -> bytes:
        if public.level != self.level:
            raise ValueError("public key parameters do not match algorithm")
        shared, kem_ct = self._kem.encaps(public.ek)
        aad = _aad(self.level, kem_ct)
        key = _derive(shared, aad)
        nonce = os.urandom(12)
        body = AESGCM(key).encrypt(nonce, plaintext, aad)
        payload = {"format": FORMAT, "level": self.level,
                   "kem_ct": base64.b64encode(kem_ct).decode(),
                   "nonce": base64.b64encode(nonce).decode(),
                   "body": base64.b64encode(body).decode()}
        return json.dumps(payload, separators=(",", ":")).encode()

    def unlock(self, private: MLKEMPrivateKey, ciphertext: bytes) -> bytes:
        try:
            if len(ciphertext) > 65536:
                raise ValueError("envelope too large")
            payload = json.loads(ciphertext)
            if (set(payload) != {"format", "level", "kem_ct", "nonce", "body"}
                    or payload["format"] != FORMAT
                    or payload["level"] != self.level or private.level != self.level):
                raise ValueError("unsupported envelope or mismatched parameters")
            kem_ct, nonce, body = (base64.b64decode(payload[k], validate=True)
                                  for k in ("kem_ct", "nonce", "body"))
            if len(nonce) != 12 or len(body) < 16:
                raise ValueError("invalid AEAD envelope")
            shared = self._kem.decaps(private.dk, kem_ct)
            aad = _aad(self.level, kem_ct)
            key = _derive(shared, aad)
            return AESGCM(key).decrypt(nonce, body, aad)
        except (InvalidTag, ValueError, TypeError, KeyError) as exc:
            raise ValueError("invalid envelope, wrong key, or tampered ciphertext") from exc
