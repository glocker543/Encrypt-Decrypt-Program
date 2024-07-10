import os
from encryption_app import EncryptionApp

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def compute_file_hash(file_path):
    app = EncryptionApp()
    return app.hash_file(file_path)

def encrypt_file(input_file):
    app = EncryptionApp()
    symmetric_key = app.generate_symmetric_key()
    
    # Compute hash of the original file
    original_hash = compute_file_hash(input_file)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted_data = app.encrypt_symmetric(symmetric_key, data)

    # Ensure the 'encrypted', 'keys', and 'hash' directories exist
    ensure_directory_exists('encrypted')
    ensure_directory_exists('keys')
    ensure_directory_exists('hash')

    filename = os.path.basename(input_file)
    output_file = os.path.join('encrypted', f"encrypted_{filename}")

    # Create the key file name and path
    key_file = os.path.join('keys', f"key_{filename}")
    hash_file = os.path.join('hash', f"hash_{filename}.txt")
    
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    
    app.save_key(symmetric_key, key_file)
    with open(hash_file, 'w') as f:
        f.write(original_hash)
    
    print(f"File encrypted and saved to {output_file}")
    print(f"Symmetric key saved to {key_file}")
    print(f"Original file hash saved to {hash_file}")

def decrypt_file(input_file):
    app = EncryptionApp()

    # Ensure the 'decrypted' directory exists
    ensure_directory_exists('decrypted')

    # Determine the key file name based on the input file name
    filename = input_file.replace('encrypted_', '')
    key_file = os.path.join('keys', f"key_{filename}")
    hash_file = os.path.join('hash', f"hash_{filename}.txt")
    symmetric_key = app.load_key(key_file)
    
    input_file_path = os.path.join('encrypted', input_file)
    with open(input_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = app.decrypt_symmetric(symmetric_key, encrypted_data)

    # Create the output file name and path
    output_file = os.path.join('decrypted', f"decrypted_{filename}")
    
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"File decrypted and saved to {output_file}")

    # Verify the integrity of the decrypted file
    with open(hash_file, 'r') as f:
        original_hash = f.read()
    decrypted_hash = compute_file_hash(output_file)
    
    if original_hash == decrypted_hash:
        print("File integrity check passed.")
    else:
        print("File integrity check failed.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt")
    parser.add_argument('input_file', help="Input file path")

    args = parser.parse_args()

    if args.mode == 'encrypt':
        encrypt_file(args.input_file)
    elif args.mode == 'decrypt':
        decrypt_file(args.input_file)
