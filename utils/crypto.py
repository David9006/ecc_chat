import secrets
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt(recipient_pub_bytes: bytes,
            plaintext: bytes,
            aad: Optional[bytes] = None) -> bytes:
    """Encrypt plaintext for a recipient using an X25519-based ECIES-like scheme.

    Parameters
    ----------
    recipient_pub_bytes : bytes
        The recipient's raw X25519 public key (32 bytes, raw format).
    plaintext : bytes
        Data to encrypt.
    aad : Optional[bytes], optional
        Additional authenticated data for AES-GCM (must be the same on decrypt), by default None.

    Returns
    -------
    bytes
        Concatenation: ephemeral public key (32 bytes, raw format) |
        12-byte AES-GCM nonce | AES-GCM ciphertext (ciphertext + tag).

    Notes
    -----
    The function generates an ephemeral X25519 keypair, performs a DH exchange
    with the recipient public key, derives a 32-byte AES-GCM key via HKDF(SHA256),
    and returns the ephemeral public key prefixed to the AES-GCM output.
    """
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

    # return ephemeral public | nonce | ciphertext
    return eph_pub + nonce + ct


def decrypt(recipient_priv_bytes: bytes,
            packed: bytes,
            aad: Optional[bytes] = None) -> bytes:
    """Decrypt data produced by encrypt().

    Parameters
    ----------
    recipient_priv_bytes : bytes
        The recipient's raw X25519 private key (32 bytes, raw format).
    packed : bytes
        Data output from encrypt(): eph_pub | nonce | ciphertext.
    aad : Optional[bytes], optional
        Additional authenticated data used during encryption, by default None.

    Returns
    -------
    bytes
        The decrypted plaintext.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If AES-GCM authentication fails (wrong key/aad or corrupted data).
    """
    # unpack
    eph_pub = packed[:32]
    nonce = packed[32:44]
    ct = packed[44:]

    # compute key
    priv = X25519PrivateKey.from_private_bytes(recipient_priv_bytes)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"ecies").derive(shared)

    # decrypt
    return AESGCM(key).decrypt(nonce, ct, aad)
