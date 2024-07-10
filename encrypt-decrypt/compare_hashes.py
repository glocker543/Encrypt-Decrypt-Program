import hashlib
import os

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Path to the decrypted file
decrypted_file_path = 'decrypted/decrypted_example.txt'

# Compute the hash of the decrypted file
decrypted_file_hash = compute_hash(decrypted_file_path)

# Path to the stored hash file
hash_file_path = 'hash/hash_example.txt.txt'

# Read the stored hash
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
