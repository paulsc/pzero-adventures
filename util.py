from Crypto.PublicKey import RSA
import json

from crypto import SigningKey, VerifyingKey

def verify(key_id, player_name, score, signature):
    with open(f'./keys/{key_id}.pub') as f:
        key_bytes = f.read()
    key = RSA.import_key(key_bytes)
    vk = VerifyingKey(key.n, key.e)
    message = json.dumps([key_id, player_name, score]).encode()
    return vk.verify(message, signature)

def sign(key_id, player_name, score):
    with open(f'./keys/{key_id}.priv') as f:
        key_bytes = f.read()
    key = RSA.import_key(key_bytes)
    sk = SigningKey(key.p, key.q, key.e)
    message = json.dumps([key_id, player_name, score]).encode()
    return sk.sign(message)
