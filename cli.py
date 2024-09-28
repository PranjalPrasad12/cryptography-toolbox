from Crypto.Cipher import AES, DES3, ChaCha20, Blowfish, Salsa20
from Crypto.Util.Padding import pad, unpad
import hashlib
import sys
import os

# AES encryption and decryption
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

# DES3 encryption and decryption
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
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8')

# ChaCha20 encryption and decryption
def encrypt_chacha20(input_text, key):
    key = hashlib.sha256(key.encode()).digest()[:32]  # ChaCha20 key must be 32 bytes
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce
    encrypted_text = cipher.encrypt(input_text.encode('utf-8'))
    return nonce + encrypted_text

def decrypt_chacha20(encrypted_data, key):
    key = hashlib.sha256(key.encode()).digest()[:32]
    nonce = encrypted_data[:8]  # ChaCha20 nonce is 8 bytes
    ciphertext = encrypted_data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Blowfish encryption and decryption
def encrypt_blowfish(input_text, key):
    key = hashlib.sha256(key.encode()).digest()[:56]  # Blowfish key can be up to 56 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(input_text.encode('utf-8'), Blowfish.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv + encrypted_text

def decrypt_blowfish(encrypted_data, key):
    key = hashlib.sha256(key.encode()).digest()[:56]
    iv = encrypted_data[:Blowfish.block_size]
    ciphertext = encrypted_data[Blowfish.block_size:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), Blowfish.block_size).decode('utf-8')

# Salsa20 encryption and decryption
def encrypt_salsa20(input_text, key):
    key = hashlib.sha256(key.encode()).digest()[:32]  # Salsa20 key must be 32 bytes
    cipher = Salsa20.new(key=key)
    nonce = cipher.nonce
    encrypted_text = cipher.encrypt(input_text.encode('utf-8'))
    return nonce + encrypted_text

def decrypt_salsa20(encrypted_data, key):
    key = hashlib.sha256(key.encode()).digest()[:32]
    nonce = encrypted_data[:8]  # Salsa20 nonce is 8 bytes
    ciphertext = encrypted_data[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Hashing functions
def hash_sha256(input_text):
    return hashlib.sha256(input_text.encode()).hexdigest()

def hash_md5(input_text):
    return hashlib.md5(input_text.encode()).hexdigest()

def main():
    if len(sys.argv) < 5:
        print("Usage: python3 encryptor.py [encrypt/decrypt/hash] [aes/des/chacha20/blowfish/salsa20] [input_text/encrypted_data] [key]")
        return

    action = sys.argv[1].lower()
    encryption_type = sys.argv[2].lower()
    input_text = sys.argv[3]
    key = sys.argv[4]

    try:
        if action == "encrypt":
            if encryption_type == "aes":
                encrypted_data = encrypt_aes(input_text, key)
                print(f"Encrypted data (AES): {encrypted_data.hex()}")

            elif encryption_type == "des":
                encrypted_data = encrypt_des(input_text, key)
                print(f"Encrypted data (DES): {encrypted_data.hex()}")

            elif encryption_type == "chacha20":
                encrypted_data = encrypt_chacha20(input_text, key)
                print(f"Encrypted data (ChaCha20): {encrypted_data.hex()}")

            elif encryption_type == "blowfish":
                encrypted_data = encrypt_blowfish(input_text, key)
                print(f"Encrypted data (Blowfish): {encrypted_data.hex()}")

            elif encryption_type == "salsa20":
                encrypted_data = encrypt_salsa20(input_text, key)
                print(f"Encrypted data (Salsa20): {encrypted_data.hex()}")

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

            elif encryption_type == "chacha20":
                decrypted_text = decrypt_chacha20(encrypted_data, key)
                print(f"Decrypted data (ChaCha20): {decrypted_text}")

            elif encryption_type == "blowfish":
                decrypted_text = decrypt_blowfish(encrypted_data, key)
                print(f"Decrypted data (Blowfish): {decrypted_text}")

            elif encryption_type == "salsa20":
                decrypted_text = decrypt_salsa20(encrypted_data, key)
                print(f"Decrypted data (Salsa20): {decrypted_text}")

            else:
                print(f"Unsupported encryption type: {encryption_type}")

        elif action == "hash":
            if encryption_type == "sha256":
                hashed_value = hash_sha256(input_text)
                print(f"SHA-256 hash: {hashed_value}")

            elif encryption_type == "md5":
                hashed_value = hash_md5(input_text)
                print(f"MD5 hash: {hashed_value}")

            else:
                print(f"Unsupported hashing type: {encryption_type}")

        else:
            print(f"Unsupported action: {action}")

    except Exception as e:
        print(f"Operation failed: {e}")

if __name__ == "__main__":
    main()
