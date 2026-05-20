import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    print(f"Encrypted {file_path}")

if __name__ == "__main__":
    # Educational purpose only
    key = b'thisisatestkey12' # 16 bytes for AES-128
    sandbox_path = 'sandbox/'
    if not os.path.exists(sandbox_path):
        os.makedirs(sandbox_path)
        with open(os.path.join(sandbox_path, 'test.txt'), 'w') as f:
            f.write("Sensitive data")
            
    for filename in os.listdir(sandbox_path):
        if filename != '.gitkeep':
            encrypt_file(os.path.join(sandbox_path, filename), key)
