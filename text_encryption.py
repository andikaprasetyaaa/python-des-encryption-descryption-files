# text_encryption_gui.py

import customtkinter as ctk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DES Encryption/Decryption")
        self.root.geometry("660x525")

        # Label dan input fields untuk plaintext, kunci, dan output
        self.input_label = ctk.CTkLabel(self.root, text="Input:")
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.input_entry = ctk.CTkEntry(self.root, width=200)
        self.input_entry.grid(row=0, column=1, padx=10, pady=5)

        self.key_label = ctk.CTkLabel(self.root, text="Key (8 bytes in hex):")
        self.key_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.key_entry = ctk.CTkEntry(self.root, width=200)
        self.key_entry.grid(row=1, column=1, padx=10, pady=5)

        self.output_label = ctk.CTkLabel(self.root, text="Output:")
        self.output_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.output_entry = ctk.CTkLabel(self.root, width=200, text="")
        self.output_entry.grid(row=2, column=1, padx=10, pady=5)

        # Radio button untuk memilih enkripsi atau dekripsi
        self.operation = ctk.StringVar(value="Encrypt")
        self.encrypt_radio = ctk.CTkRadioButton(self.root, text="Encrypt", variable=self.operation, value="Encrypt")
        self.encrypt_radio.grid(row=3, column=0, padx=10, pady=5)

        self.decrypt_radio = ctk.CTkRadioButton(self.root, text="Decrypt", variable=self.operation, value="Decrypt")
        self.decrypt_radio.grid(row=3, column=1, padx=10, pady=5)

        # Tombol untuk memproses enkripsi atau dekripsi
        self.process_button = ctk.CTkButton(self.root, text="Process", width=100, command=self.process)
        self.process_button.grid(row=4, column=0, columnspan=2, pady=10)

    # Fungsi untuk melakukan enkripsi menggunakan algoritma DES
    def des_encrypt(self, plaintext, key):
        key = binascii.unhexlify(key.replace(" ", ""))
        cipher = DES.new(key, DES.MODE_ECB)
        padded_text = pad(plaintext.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return ciphertext.hex()

    # Fungsi untuk melakukan dekripsi menggunakan algoritma DES
    def des_decrypt(self, ciphertext, key):
        key = binascii.unhexlify(key.replace(" ", ""))
        cipher = DES.new(key, DES.MODE_ECB)
        padded_text = cipher.decrypt(bytes.fromhex(ciphertext))
        plaintext = unpad(padded_text, DES.block_size)
        return plaintext.decode()

    # Fungsi untuk memproses enkripsi atau dekripsi berdasarkan input pengguna
    def process(self):
        key = self.key_entry.get()  
        if self.operation.get() == "Encrypt":
            plaintext = self.input_entry.get() 
            try:
                ciphertext = self.des_encrypt(plaintext, key)
                self.output_entry.configure(text=ciphertext)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            ciphertext = self.input_entry.get()
            try:
                plaintext = self.des_decrypt(ciphertext, key)
                self.output_entry.configure(text=plaintext)
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    # Buat main window menggunakan customtkinter untuk testing
    root = ctk.CTk()
    app = TextEncryptionApp(root)
    root.mainloop()
