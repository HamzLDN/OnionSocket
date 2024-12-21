from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt(plaintext, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(plaintext) + encryptor.finalize()

def decrypt(ciphertext, key):
    decryptor = Cipher(algorithms.AES(key), modes.CTR(ciphertext[:16]), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

def generate_key() -> bytes:
    return os.urandom(16)