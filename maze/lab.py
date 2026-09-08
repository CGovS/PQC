"""Generate a fresh two-vault challenge. Private keys never enter the response."""
import base64
import hashlib
import inspect
import json
import secrets
import time
from cryptolayer.registry import get_lockbox
from attacker.campaign import run_quantum_attack
from maze.vault import seal, open_vault


def _encrypt(secret, algorithm, level=None):
    events = []
    def record(code, output, started):
        events.append({"code": code, "output": output,
                       "ms": round((time.perf_counter() - started) * 1000, 3)})
    start = time.perf_counter()
    box = get_lockbox(algorithm)
    record('box = get_lockbox(algorithm)', algorithm, start)
    start = time.perf_counter()
    keys = box.generate_keypair(level=level)
    record('keys = box.generate_keypair(level=level)', 'Public + private keys created; private key stays on server.', start)
    start = time.perf_counter()
    vault = seal(secret, keys.public, algorithm=algorithm)
    record('vault = seal(secret, keys.public, algorithm=algorithm)', f'{len(vault.ciphertext)} bytes of ciphertext', start)
    start = time.perf_counter()
    opened = open_vault(vault, keys.private)
    if opened != secret:
        raise RuntimeError('owner round-trip failed')
    record('opened = open_vault(vault, keys.private)', 'Owner recovered the original bytes.', start)
    return box, keys, vault, events


def create_challenge():
    secret = f"FLAG{{GHOST_IN_THE_MAZE_{secrets.token_hex(4).upper()}}}".encode()
    rsa, rkeys, rvault, revents = _encrypt(secret, 'rsa-toy', 'ceiling')
    pqc, pkeys, pvault, pevents = _encrypt(secret, 'ml-kem-768')
    # These are real negative checks, not a property such as quantum_vulnerable.
    payload = json.loads(pvault.ciphertext)
    body = bytearray(base64.b64decode(payload['body']))
    body[0] ^= 1
    payload['body'] = base64.b64encode(body).decode()
    try:
        pqc.unlock(pkeys.private, json.dumps(payload).encode())
        tamper_rejected = False
    except ValueError:
        tamper_rejected = True
    other = pqc.generate_keypair()
    try:
        pqc.unlock(other.private, pvault.ciphertext)
        wrong_key_rejected = False
    except ValueError:
        wrong_key_rejected = True
    if not tamper_rejected or not wrong_key_rejected:
        raise RuntimeError('PQC negative checks failed')
    attack = run_quantum_attack(pvault, pkeys.public)
    return {
        'run_id': secrets.token_hex(6),
        'secret_sha256': hashlib.sha256(secret).hexdigest(),
        'rsa': {'algorithm': rsa.algorithm,
                'public': {'n': rkeys.public.n, 'e': rkeys.public.e},
                'ciphertext': rvault.ciphertext.decode(), 'events': revents,
                'source': inspect.getsource(type(rsa).lock)},
        'pqc': {'algorithm': pqc.algorithm,
                'public': {'level': pkeys.public.level, 'ek': base64.b64encode(pkeys.public.ek).decode()},
                'ciphertext': pvault.ciphertext.decode(), 'events': pevents,
                'source': inspect.getsource(type(pqc).lock), 'attack': attack,
                'checks': {'owner_roundtrip': True, 'tamper_rejected': tamper_rejected,
                           'wrong_key_rejected': wrong_key_rejected}},
        'vault_source': inspect.getsource(seal) + '\n' + inspect.getsource(open_vault),
    }
