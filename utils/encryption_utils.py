# encryption_utils.py

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os
import time

# Function to encrypt plaintext with DES CBC mode
def encrypt_data(key, plaintext):
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC)
    iv = des.iv
    padded_text = pad(plaintext, DES.block_size)
    encrypted_text = des.encrypt(padded_text)
    encoded_text = iv + encrypted_text
    return encoded_text

# Function to decrypt ciphertext with DES CBC mode
def decrypt_data(key, encrypted_text):
    iv = encrypted_text[:DES.block_size]
    ciphertext = encrypted_text[DES.block_size:]
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    padded_text = des.decrypt(ciphertext)
    plaintext = unpad(padded_text, DES.block_size)
    return plaintext

import binascii

# Fungsi untuk melakukan enkripsi menggunakan algoritma DES
def des_encrypt(plaintext, key):
    key = binascii.unhexlify(key.replace(" ", ""))
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext.hex()

# Fungsi untuk melakukan dekripsi menggunakan algoritma DES
def des_decrypt(ciphertext, key):
    key = binascii.unhexlify(key.replace(" ", ""))
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = cipher.decrypt(bytes.fromhex(ciphertext))
    plaintext = unpad(padded_text, DES.block_size)
    return plaintext.decode()

# Function to measure file size in KB
def get_file_size_kb(file_path):
    file_size = os.path.getsize(file_path)
    file_size_kb = file_size / 1024
    return file_size_kb

# Function to measure execution time
def measure_execution_time(start_time):
    end_time = time.time()
    duration = end_time - start_time
    return duration
