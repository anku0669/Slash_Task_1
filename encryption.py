import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend


ITERATIONS = 100_000
KEY_LENGTH = 32   # 256 bits
SALT_LENGTH = 16
IV_LENGTH = 16


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode())


def encrypt(plaintext: str, passphrase: str) -> str:
    """
    Encrypt plaintext with AES-256-CBC.
    Returns a base64-encoded string: salt:iv:ciphertext (all base64).
    Every call produces a unique output due to random salt + IV.
    """
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = _derive_key(passphrase, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode()

    return f"{b64(salt)}:{b64(iv)}:{b64(ciphertext)}"


def decrypt(token: str, passphrase: str) -> str:
    """
    Decrypt a token produced by encrypt().
    Raises ValueError on bad format or wrong passphrase.
    """
    try:
        salt_b64, iv_b64, ct_b64 = token.split(":")
    except ValueError:
        raise ValueError("Invalid token format — expected salt:iv:ciphertext.")

    def b64d(s: str) -> bytes:
        return base64.urlsafe_b64decode(s)

    salt = b64d(salt_b64)
    iv = b64d(iv_b64)
    ciphertext = b64d(ct_b64)
    key = _derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise ValueError("Decryption failed — wrong passphrase or corrupted data.")

    return plaintext.decode()
