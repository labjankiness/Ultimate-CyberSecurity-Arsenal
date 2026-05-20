import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    iv = data[:16]
    encrypted_data = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"Decrypted {file_path}")

if __name__ == "__main__":
    key = b'thisisatestkey12'
    sandbox_path = 'sandbox/'
    for filename in os.listdir(sandbox_path):
        if filename != '.gitkeep':
            decrypt_file(os.path.join(sandbox_path, filename), key)
