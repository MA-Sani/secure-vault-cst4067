"""
encryption.py
AES-256-GCM file encryption and decryption.
Each file gets its own randomly generated 256-bit key and 96-bit nonce.
Keys are stored in Firestore alongside file metadata.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """Generate a new random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt file bytes using AES-256-GCM.
    Returns (ciphertext, nonce).
    The nonce is randomly generated per encryption — never reused.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce, recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return ciphertext, nonce


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    Raises InvalidTag if the key/nonce is wrong or data is tampered.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Serialisation helpers (store bytes as base64 strings in Firestore) ──

def key_to_str(key: bytes) -> str:
    return base64.b64encode(key).decode('utf-8')


def str_to_key(key_str: str) -> bytes:
    return base64.b64decode(key_str.encode('utf-8'))


def nonce_to_str(nonce: bytes) -> str:
    return base64.b64encode(nonce).decode('utf-8')


def str_to_nonce(nonce_str: str) -> bytes:
    return base64.b64decode(nonce_str.encode('utf-8'))
