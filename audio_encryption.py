import customtkinter as ctk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os
import time

class EncryptionAudioApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Decryption Using DES Algorithm")
        self.input_file_path = None

        # Attempt to set the custom theme, fallback to default theme if not found
        try:
            ctk.set_default_color_theme(r"c:\pykripto\MoonLitSky.json")
        except FileNotFoundError:
            print("Warning: Theme file not found. Using default theme.")
            ctk.set_default_color_theme("green")

        # Set up user interface components
        self.setup_ui()

    def setup_ui(self):
        frame = ctk.CTkFrame(self.root)
        frame.pack(pady=10, padx=5)

        browse_button = ctk.CTkButton(frame, text="( + ) Browse File", command=self.browse_file, width=626, height=70)
        browse_button.grid(row=1, column=0, columnspan=3, padx=6, pady=5, sticky='ew')

        self.input_file_label = ctk.CTkLabel(frame, text="Selected File: None")
        self.input_file_label.grid(row=2, column=0, columnspan=3, padx=6, pady=5)

        button_frame = ctk.CTkFrame(self.root)
        button_frame.pack(pady=10, padx=10)

        key_label = ctk.CTkLabel(button_frame, text="Key (8 characters):")
        key_label.grid(row=0, column=0, columnspan=1, padx=5, pady=5)
        self.key_entry = ctk.CTkEntry(button_frame)
        self.key_entry.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky='ew')

        encryption_button = ctk.CTkButton(button_frame, text="Encryption", command=self.encrypt_file, width=256)
        encryption_button.grid(row=1, column=0, padx=5, pady=5, sticky='ew')

        decryption_button = ctk.CTkButton(button_frame, text="Decryption", command=self.decrypt_file, width=256)
        decryption_button.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        reset_button = ctk.CTkButton(button_frame, text="Reset", command=self.reset, fg_color="#D03F2C", hover_color="lightcoral", width=100)
        reset_button.grid(row=1, column=2, padx=5, pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Audio and Encrypted files", "*.mp3 *.wav *.aac *.flac *.bin")])
        if file_path:
            self.input_file_path = file_path
            self.input_file_label.configure(text=f"Selected File: {os.path.basename(self.input_file_path)}")

    def encrypt_file(self):
        key = self.key_entry.get()
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 characters long!")
            return
        if not self.input_file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        try:
            with open(self.input_file_path, 'rb') as file:
                plaintext = file.read()

            # Measure start time
            start_time = time.time()

            des = DES.new(key.encode('utf-8'), DES.MODE_CBC)
            iv = des.iv
            padded_text = pad(plaintext, DES.block_size)
            encrypted_text = des.encrypt(padded_text)
            encoded_text = iv + encrypted_text

            output_path = self.input_file_path + '_encrypt.bin'
            with open(output_path, 'wb') as file:
                file.write(encoded_text)

            # Calculate encrypted file size
            encrypted_size = os.path.getsize(output_path)
            encrypted_size_kb = encrypted_size / 1024  # Size in kilobytes

            # Measure end time
            end_time = time.time()
            duration = end_time - start_time

            messagebox.showinfo("Success", f"Encrypted file saved as {output_path}\n\nTime: {duration:.4f} seconds\nSize: {encrypted_size_kb:.2f} KB")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")

    def decrypt_file(self):
        key = self.key_entry.get()
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 characters long!")
            return
        if not self.input_file_path or not self.input_file_path.endswith('_encrypt.bin'):
            messagebox.showerror("Error", "Please select an encrypted file (.bin) first!")
            return
        try:
            with open(self.input_file_path, 'rb') as file:
                encrypted_text = file.read()

            # Measure start time
            start_time = time.time()

            iv = encrypted_text[:DES.block_size]
            ciphertext = encrypted_text[DES.block_size:]
            des = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
            padded_text = des.decrypt(ciphertext)
            plaintext = unpad(padded_text, DES.block_size)

            # Determine the original file name and extension
            original_extension = os.path.splitext(self.input_file_path)[0].split('_encrypt')[0]  # Handle extension properly
            output_path = original_extension

            with open(output_path, 'wb') as file:
                file.write(plaintext)

            # Calculate decrypted file size
            decrypted_size = os.path.getsize(output_path)
            decrypted_size_kb = decrypted_size / 1024  # Size in kilobytes

            # Measure end time
            end_time = time.time()
            duration = end_time - start_time

            messagebox.showinfo("Success", f"Decrypted file saved as {output_path}\n\nTime: {duration:.4f} seconds\nSize: {decrypted_size_kb:.2f} KB")
        except ValueError as ve:
            messagebox.showerror("Error", f"Decryption error (possibly incorrect padding or key): {ve}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")

    def reset(self):
        self.input_file_label.configure(text='Selected File: None')
        self.input_file_path = None
        self.key_entry.delete(0, 'end')

# Main program entry point for testing this class
if __name__ == "__main__":
    root = ctk.CTk()
    app = EncryptionAudioApp(root)
    root.mainloop()
