import customtkinter as ctk
from audio_encryption import EncryptionAudioApp
from files_encryption import EncryptionFilesApp
from image_encryption import ImageEncryptorApp
from text_encryption import TextEncryptionApp
from video_encryption import VideoEncryptorApp

class HomePage:
    def __init__(self, root):
        self.root = root
        self.root.title("Data Encryption Standard App")
        self.root.geometry("660x525")

        # Header
        self.header_label = ctk.CTkLabel(self.root, text="DATA ENCRYPTION STANDARD APP", font=("Helvetica", 30, "bold"))
        self.header_label.pack(pady=(10, 20))

        # Text button
        self.text_button = ctk.CTkButton(self.root, text="Text", command=self.open_text_page, width=300, height=70)
        self.text_button.pack(pady=10)

        # File button
        self.file_button = ctk.CTkButton(self.root, text="Files", command=self.open_file_page, width=300, height=70)
        self.file_button.pack(pady=10)

        # Image button
        self.image_button = ctk.CTkButton(self.root, text="Image", command=self.open_image_page, width=300, height=70)
        self.image_button.pack(pady=10)

        # Video button
        self.video_button = ctk.CTkButton(self.root, text="Video", command=self.open_video_page, width=300, height=70)
        self.video_button.pack(pady=10)

        # Audio button
        self.audio_button = ctk.CTkButton(self.root, text="Audio", command=self.open_audio_page, width=300, height=70)
        self.audio_button.pack(pady=10)

    def open_image_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = ImageEncryptorApp(self.new_window)

    def open_video_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = VideoEncryptorApp(self.new_window)

    def open_text_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = TextEncryptionApp(self.new_window)  

    def open_file_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = EncryptionAudioApp(self.new_window)

    def open_audio_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = EncryptionAudioApp(self.new_window)

    def open_file_page(self):
        self.new_window = ctk.CTkToplevel(self.root)
        self.app = EncryptionFilesApp(self.new_window)

# Main program entry point
if __name__ == "__main__":
    app = ctk.CTk()
    homepage = HomePage(app)
    app.mainloop()
