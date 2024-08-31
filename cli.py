from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
import sys
import os

def encrypt_aes(input_text, key):
    key = hashlib.sha256(key.encode()).digest()  # Use SHA-256 to hash the key
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(input_text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv + encrypted_text

def decrypt_aes(encrypted_data, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_text = cipher.decrypt(ciphertext)
    return unpad(padded_text, AES.block_size).decode('utf-8')

def encrypt_des(input_text, key):
    key = hashlib.md5(key.encode()).digest()  # DES key must be 16 bytes
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(input_text.encode('utf-8'), DES3.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv + encrypted_text

def decrypt_des(encrypted_data, key):
    key = hashlib.md5(key.encode()).digest()
    iv = encrypted_data[:DES3.block_size]
    ciphertext = encrypted_data[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_text = cipher.decrypt(ciphertext)
    return unpad(padded_text, DES3.block_size).decode('utf-8')

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 encryptor.py [encrypt/decrypt] [aes/des] [input_text/encrypted_data] [key]")
        return

    action = sys.argv[1].lower()
    encryption_type = sys.argv[2].lower()
    input_text = sys.argv[3]
    key = sys.argv[4]

    # Ensure the key length is valid for the selected algorithm
    if encryption_type == 'aes' and len(key) not in [16, 24, 32]:
        print("AES key must be 16, 24, or 32 bytes long.")
        return
    if encryption_type == 'des' and len(key) != 16:
        print("DES key must be 16 bytes long.")
        return

    try:
        if action == "encrypt":
            if encryption_type == "aes":
                encrypted_data = encrypt_aes(input_text, key)
                print(f"Encrypted data (AES): {encrypted_data.hex()}")

            elif encryption_type == "des":
                encrypted_data = encrypt_des(input_text, key)
                print(f"Encrypted data (DES): {encrypted_data.hex()}")

            else:
                print(f"Unsupported encryption type: {encryption_type}")

        elif action == "decrypt":
            encrypted_data = bytes.fromhex(input_text)  # Convert hex input back to bytes

            if encryption_type == "aes":
                decrypted_text = decrypt_aes(encrypted_data, key)
                print(f"Decrypted data (AES): {decrypted_text}")

            elif encryption_type == "des":
                decrypted_text = decrypt_des(encrypted_data, key)
                print(f"Decrypted data (DES): {decrypted_text}")

            else:
                print(f"Unsupported encryption type: {encryption_type}")

        else:
            print(f"Unsupported action: {action}")

    except Exception as e:
        print(f"Operation failed: {e}")

if __name__ == "__main__":
    main()
