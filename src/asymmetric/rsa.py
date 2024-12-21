from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size=2048):
    # this is where i generate the asymmetric keys
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=key_size,backend=default_backend())
    return private_key, private_key.public_key()

def encrypt_message(public_key, plaintext):
    return public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_message(private_key, ciphertext):
    return private_key.decrypt(ciphertext, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),    # mgf improves the security and unpredictability of encryption by generating a mask in RSA OAEP.
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()