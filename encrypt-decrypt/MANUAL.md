# Encryption and Decryption Program Manual

This manual provides detailed instructions on how to use the encryption and decryption program. The program allows users to encrypt and decrypt files using symmetric encryption and verify the integrity of the files using hashing.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
   - [Cloning the Repository](#cloning-the-repository)
   - [Installing Dependencies](#installing-dependencies)
4. [Usage](#usage)
   - [Encrypting a File](#encrypting-a-file)
   - [Decrypting a File](#decrypting-a-file)
   - [Verifying File Integrity Manually](#verifying-file-integrity-manually)
5. [Example Files](#example-files)
6. [License](#license)
7. [Troubleshooting](#troubleshooting)
8. [Contact](#contact)

# 1 - Overview

This program provides the following capabilities:

- **Encrypt Files**: Encrypt any file using AES-256 encryption.
- **Decrypt Files**: Decrypt previously encrypted files.
- **Hash Files**: Compute SHA-256 hashes of files to ensure integrity.
- **Verify Integrity**: Compare the hash of the original file with the hash of the decrypted file to verify integrity.

# 2 - Prerequisites

- Python 3.x
- `cryptography` library

# 3 - Setup

## 3.1 - Cloning the Repository
    Command:
        git clone <repository-url>
## 3.2 - Installing Dependicies
    Navigate to the project directory and install the required dependencies using pip:
        Command:
            cd path/to/project_directory
            pip install -r requirements.txt
# 4 Usage
## 4.1 - Encrypting a File
    To encrypt a file, use the encrypt mode. This will generate an encrypted file, a key file, and a hash file.
        Command:
            python encrypt_decrypt_file.py encrypt <input_file>
        Example:
            python encrypt_decrypt_file.py encrypt "example_files/example.txt"
        Output:
            Encrypted file in the encrypted/ directory.
            Key file in the keys/ directory.
            Hash file in the hash/ directory.
## 4.2 - Decrypting a File
    To decrypt a file, use the decrypt mode. This will generate a decrypted file and verify its integrity.
        Command:
            python encrypt_decrypt_file.py decrypt <input_file>
        Example:
            python encrypt_decrypt_file.py decrypt "encrypted/encrypted_example.txt"
        Output:
            Decrypted file in the decrypted/ directory.
            Integrity verification message.
## 4.3 Verifying File Integrity Manually
    To manually verify the integrity of the decrypted file, use the compare_hashes.py script. This script compares the hash of the decrypted file with the stored hash of the original file.
        1 - Ensure that the filenames in the compare_hashes.py script match the files you are verifying.
        2 - Run the script:
            python compare_hashes.py
        Example: compare_hashes.py
            Script:
                import hashlib

                def compute_hash(file_path):
                    sha256_hash = hashlib.sha256()
                    with open(file_path, 'rb') as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    return sha256_hash.hexdigest()

                # Path to the decrypted file
                decrypted_file_path = 'decrypted/decrypted_example.txt'
                decrypted_file_hash = compute_hash(decrypted_file_path)

                # Path to the stored hash file
                hash_file_path = 'hash/hash_example.txt.txt'
                with open(hash_file_path, 'r') as f:
                    stored_hash = f.read().strip()

                # Print both hashes for manual comparison
                print(f"Stored hash: {stored_hash}")
                print(f"Decrypted file hash: {decrypted_file_hash}")

                # Compare hashes
                if stored_hash == decrypted_file_hash:
                    print("Hashes match. The file integrity is verified.")
                else:
                    print("Hashes do not match. The file integrity is compromised.")

# 5 - Example Files
    Example files are provided in the example_files/ directory for testing purposes.
# 6 - LICENSE
    This project is licensed under the MIT License. See the LICENSE file for more information.
# 7 - Troubleshooting
    Common Issues
        1 - Dependencies not installed: Ensure you have installed all required dependencies using pip install -r requirements.txt.
        2 - File not found: Ensure the file paths are correct and the files exist.
        3 - Hash mismatch: Ensure the original and decrypted files are correct and have not been tampered with.
    Error Messages
        1 - ModuleNotFoundError: No module named 'cryptography':
            - Ensure you have installed the cryptography library by running pip install -r requirements.txt.
        2 - FileNotFoundError: [Errno 2] No such file or directory:
            - Verify the file path and ensure the file exists.
        3 - UnicodeDecodeError: 'utf-8' codec can't decode byte:
            - Ensure you are using binary mode ('rb' and 'wb') when reading and writing non-text files.
    Directory Configuation Issues
        Make sure your project directory is configured as follows:
            project_directory/
            ├── encryption_app.py
            ├── encrypt_decrypt_file.py
            ├── compare_hashes.py
            ├── requirements.txt
            ├── LICENSE
            ├── README.md
            ├── MANUAL.md
            ├── example_files/
            │ ├── example.txt
            ├── encrypted/
            ├── decrypted/
            ├── keys/
            └── hash/
# 8 - Contact
    For further assistance, contact the project maintainer at [your-email@example.com]