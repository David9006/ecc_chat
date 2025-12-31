# Encryption side
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from typing import Optional


def encrypt(recipient_pub_bytes: bytes,
            plaintext: bytes,
            aad: Optional[bytes] = None) -> bytes:
    # recipient_pub_bytes: raw 32-byte X25519 public key
    recipient_pub = X25519PrivateKey.from_private_bytes(
        secrets.token_bytes(32))
    # create ephemeral key
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    # load recipient public
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    shared = eph_priv.exchange(recipient_pub)
    # derive symmetric key
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"ecies").derive(shared)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # return ephemeral public || nonce || ciphertext
    return eph_pub + nonce + ct


def decrypt(recipient_priv_bytes: bytes,
            packed: bytes,
            aad: Optional[bytes] = None) -> bytes:
    # unpack
    eph_pub = packed[:32]
    nonce = packed[32:44]
    ct = packed[44:]
    priv = X25519PrivateKey.from_private_bytes(recipient_priv_bytes)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"ecies").derive(shared)
    return AESGCM(key).decrypt(nonce, ct, aad)
