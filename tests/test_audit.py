"""Regression checks for defects identified in the September architecture audit."""
import base64
import hashlib
import json
import random
import subprocess
import shutil
import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from kyber_py.ml_kem import ML_KEM_768
from cryptolayer.registry import get_lockbox
from cryptolayer.classical import RSAPrivateKey
from attacker.shor import measurement_distribution, shor_factor
from attacker.break_maze import crack_vault
from maze.keys import make_keypair
from maze.vault import seal
from maze.lab import create_challenge


def test_demo_rsa_public_exponent_is_not_a_decryption_key():
    box=get_lockbox('rsa-toy'); kp=make_keypair('ceiling')
    assert kp.public.n==33 and kp.public.e!=kp.private.d
    secret=bytes(range(256)); ct=box.lock(kp.public,secret)
    fake=RSAPrivateKey(kp.public.n,kp.public.e,0,0)
    try:
        result=box.unlock(fake,ct)
    except OverflowError:
        result=None
    assert result!=secret
    recovered,_,r=crack_vault(seal(secret,kp.public),kp.public,seed=3,force_quantum=True)
    assert recovered==secret and r.attempts[-1]['period']


@pytest.mark.parametrize('field',['format','level','kem_ct','nonce','body'])
def test_every_pqc_envelope_field_is_bound(field):
    b=get_lockbox('ml-kem-768');kp=b.generate_keypair();p=json.loads(b.lock(kp.public,b'test'))
    if field=='format':p[field]='old-format'
    elif field=='level':p[field]='512'
    else:
        raw=bytearray(base64.b64decode(p[field]));raw[0]^=1;p[field]=base64.b64encode(raw).decode()
    with pytest.raises(ValueError):b.unlock(kp.private,json.dumps(p).encode())


def test_pqc_invalid_parameters_do_not_silently_fallback():
    b=get_lockbox('ml-kem-768')
    with pytest.raises(ValueError):b.generate_keypair(level='typo')
    with pytest.raises(ValueError):b.lock(get_lockbox('ml-kem-512').generate_keypair().public,b'x')


@pytest.mark.parametrize('secret',[b'',b'\x00',bytes(range(256))])
def test_pqc_binary_roundtrip(secret):
    b=get_lockbox('ml-kem-768');kp=b.generate_keypair();ct=b.lock(kp.public,secret)
    assert b.unlock(kp.private,ct)==secret
    assert b.lock(kp.public,secret)!=ct


def test_mlkem_interoperates_with_independent_openssl_provider():
    seed=bytes(range(64));independent=MLKEM768PrivateKey.from_seed_bytes(seed)
    ek,dk=ML_KEM_768.key_derive(seed)
    assert independent.public_key().public_bytes_raw()==ek
    shared,ct=ML_KEM_768.encaps(independent.public_key().public_bytes_raw())
    assert independent.decapsulate(ct)==shared
    shared,ct=MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    assert ML_KEM_768.decaps(dk,ct)==shared


def test_qft_known_analytic_distribution():
    # Base 2 modulo 15 has order 4: ideal probability 1/4 at 0,64,128,192.
    expected=np.zeros(256);expected[::64]=.25
    assert np.allclose(measurement_distribution(2,15),expected,atol=1e-13)


@pytest.mark.parametrize('n',[0,1,-1,128,2048])
def test_simulator_rejects_unsafe_allocation(n):
    with pytest.raises(ValueError):shor_factor(n)


def test_challenge_separates_secret_from_attacker_and_changes_each_run():
    a=create_challenge();b=create_challenge()
    assert a['secret_sha256']!=b['secret_sha256'] and a['run_id']!=b['run_id']
    assert a['pqc']['ciphertext']!=b['pqc']['ciphertext']
    banned={'d','dk','private','private_key','secret_plaintext','revealed','factors'}
    def walk(obj):
        if isinstance(obj,dict):
            assert not (set(obj)&banned)
            for v in obj.values():walk(v)
        elif isinstance(obj,list):
            for v in obj:walk(v)
    walk(a)
    pub=make_keypair('ceiling').public
    from maze.vault import Vault
    plaintext,_,_=crack_vault(Vault('rsa-toy',a['rsa']['ciphertext'].encode()),pub,seed=3,force_quantum=True)
    assert hashlib.sha256(plaintext).hexdigest()==a['secret_sha256']
    assert all(a['pqc']['checks'].values())


@pytest.mark.parametrize('payload',[{'n':99,'len':1,'c':[1]}, {'n':33,'len':-1,'c':[1]}, {'n':33,'len':0,'c':[1]}, {'n':33,'len':1,'c':[33]}])
def test_bad_rsa_payloads_rejected(payload):
    b=get_lockbox('rsa-toy');kp=make_keypair('ceiling')
    with pytest.raises((ValueError,OverflowError)):b.unlock(kp.private,json.dumps(payload).encode())
