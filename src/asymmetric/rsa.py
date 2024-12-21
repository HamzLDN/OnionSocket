from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size=2048):
    # this is where i generate the asymmetric keys
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=key_size,backend=default_backend())
    return private_key, private_key.public_key()

def encrypt_message(public_key, plaintext) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def load_public_key(public_key):
    return serialization.load_pem_public_key(public_key,backend=default_backend())

def decrypt_message(private_key, ciphertext):
    return private_key.decrypt(ciphertext, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),    # mgf improves the security and unpredictability of encryption by generating a mask in RSA OAEP.
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def export_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

def export_private_key(private_key):
   return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
