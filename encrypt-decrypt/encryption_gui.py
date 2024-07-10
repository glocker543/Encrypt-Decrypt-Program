import os
import tkinter as tk
from tkinter import filedialog, messagebox
from encryption_app import EncryptionApp

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def compute_file_hash(file_path):
    app = EncryptionApp()
    return app.hash_file(file_path)

def encrypt_file(file_path):
    app = EncryptionApp()
    symmetric_key = app.generate_symmetric_key()
    
    original_hash = compute_file_hash(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    encrypted_data = app.encrypt_symmetric(symmetric_key, data)

    ensure_directory_exists('encrypted')
    ensure_directory_exists('keys')
    ensure_directory_exists('hash')

    filename = os.path.basename(file_path)
    output_file = os.path.join('encrypted', f"encrypted_{filename}")
    key_file = os.path.join('keys', f"key_{filename}")
    hash_file = os.path.join('hash', f"hash_{filename}.txt")
    
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    
    app.save_key(symmetric_key, key_file)
    with open(hash_file, 'w') as f:
        f.write(original_hash)
    
    messagebox.showinfo("Success", f"File encrypted and saved to {output_file}\nSymmetric key saved to {key_file}\nOriginal file hash saved to {hash_file}")

def decrypt_file(file_path):
    app = EncryptionApp()

    ensure_directory_exists('decrypted')

    filename = os.path.basename(file_path).replace('encrypted_', '')
    key_file = os.path.join('keys', f"key_{filename}")
    hash_file = os.path.join('hash', f"hash_{filename}.txt")
    symmetric_key = app.load_key(key_file)
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = app.decrypt_symmetric(symmetric_key, encrypted_data)

    output_file = os.path.join('decrypted', f"decrypted_{filename}")
    
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    
    with open(hash_file, 'r') as f:
        original_hash = f.read()
    decrypted_hash = compute_file_hash(output_file)
    
    if original_hash == decrypted_hash:
        messagebox.showinfo("Success", f"File decrypted and saved to {output_file}\nFile integrity check passed.")
    else:
        messagebox.showerror("Error", "File integrity check failed.")

def select_file(action):
    initial_dir = ''
    if action == "decrypt":
        initial_dir = os.path.join(os.getcwd(), 'encrypted')
    file_path = filedialog.askopenfilename(initialdir=initial_dir)
    if file_path:
        if action == "encrypt":
            encrypt_file(file_path)
        elif action == "decrypt":
            decrypt_file(file_path)

app = tk.Tk()
app.title("Encryption and Decryption Program")

encrypt_button = tk.Button(app, text="Encrypt File", command=lambda: select_file("encrypt"))
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(app, text="Decrypt File", command=lambda: select_file("decrypt"))
decrypt_button.pack(pady=10)

app.mainloop()
