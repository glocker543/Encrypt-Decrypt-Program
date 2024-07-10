from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import keywrap
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

    def encrypt_symmetric(self, key, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt_symmetric(self, key, ciphertext):
        decoded_ciphertext = base64.b64decode(ciphertext.encode())
        iv = decoded_ciphertext[:16]
        actual_ciphertext = decoded_ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

    def save_key(self, key, filename):
        with open(filename, 'wb') as f:
            f.write(key)

    def load_key(self, filename):
        with open(filename, 'rb') as f:
            return f.read()

if __name__ == "__main__":
    app = EncryptionApp()
    
    # Example usage for RSA
    private_key, public_key = app.generate_rsa_keys()
    message = "This is a secret message."
    encrypted_message = app.encrypt_rsa(public_key, message)
    decrypted_message = app.decrypt_rsa(private_key, encrypted_message)

    print("Original Message:", message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)

    # Example usage for Symmetric Encryption
    symmetric_key = app.generate_symmetric_key()
    encrypted_message_sym = app.encrypt_symmetric(symmetric_key, message)
    decrypted_message_sym = app.decrypt_symmetric(symmetric_key, encrypted_message_sym)

    print("Original Message:", message)
    print("Encrypted Message (Symmetric):", encrypted_message_sym)
    print("Decrypted Message (Symmetric):", decrypted_message_sym)

    # Save and load keys
    app.save_key(symmetric_key, "symmetric.key")
    loaded_symmetric_key = app.load_key("symmetric.key")
    assert symmetric_key == loaded_symmetric_key

    # Save RSA keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)
