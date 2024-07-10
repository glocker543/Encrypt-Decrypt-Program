from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64

class EncryptionApp:
    def __init__(self):
        self.backend = default_backend()

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_rsa(self, public_key, message):
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    def decrypt_rsa(self, private_key, ciphertext):
        decoded_ciphertext = base64.b64decode(ciphertext.encode())
        plaintext = private_key.decrypt(
            decoded_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def generate_symmetric_key(self):
        return os.urandom(32)  # AES-256

    def encrypt_symmetric(self, key, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_symmetric(self, key, data):
        iv = data[:16]
        actual_ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

    def save_key(self, key, filename):
        with open(filename, 'wb') as f:
            f.write(key)

    def load_key(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

    def hash_file(self, file_path):
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                digest.update(chunk)
        return base64.b64encode(digest.finalize()).decode()
