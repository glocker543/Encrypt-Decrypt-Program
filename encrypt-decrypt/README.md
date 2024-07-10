# Encryption and Decryption Program

This program allows users to encrypt and decrypt files using symmetric encryption and verify the integrity of the files using hashing. It ensures that the original file content is preserved through the encryption and decryption processes.

## Capabilities and Scope

### Capabilities

1. **Encrypt Files**: Encrypt any file using AES-256 encryption.
2. **Decrypt Files**: Decrypt previously encrypted files.
3. **Hash Files**: Compute SHA-256 hashes of files to ensure integrity.
4. **Verify Integrity**: Compare the hash of the original file with the hash of the decrypted file to verify integrity.

### Scope

- **Supported File Types**: Any file type (text, images, videos, etc.).
- **Encryption Algorithm**: AES-256.
- **Hashing Algorithm**: SHA-256.

## Use Cases

1. **Secure File Storage**: Encrypt files before storing them to protect sensitive information.
2. **Secure File Transfer**: Encrypt files before sending them over untrusted networks.
3. **File Integrity Verification**: Ensure that files have not been tampered with during storage or transfer.

## Prerequisites

- Python 3.x
- `cryptography` library

## Setup

### Step 1: Clone the Repository or Download the Project Files

You can clone this repository using Git or download the project files as a ZIP archive.

To clone the repository:
```sh
git clone <repository-url>
