import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature
import os

class Encryption:
    def __init__(self):
        self.key = None
        self.iv_nonce = None

    

# Helper functions for cryptography
def generate_key():
    return os.urandom(32)  # 256-bit key for AES

def generate_iv():
    return os.urandom(16)  # 128-bit IV for AES

# Required for CBC, ECB
def pad(data):
    padder = PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def hmac_sign(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def hmac_verify(key, signature, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False

def mode_from_str(mode: str, iv_nonce) -> modes.Mode:
    if mode == 'ECB':
        return modes.ECB()
    if mode == 'CBC':
        return modes.CBC(iv_nonce)
    if mode == 'CTR':
        return modes.CTR(iv_nonce)


# metadata format: mode (3 bytes) + iv_nonce (16 bytes) + hmac (32 bytes)
def write_metadata(mode: str, iv_nonce, hmac) -> bytes:
    if iv_nonce is None:
        iv_nonce = bytes(16)
    if hmac is None:
        hmac = bytes(32)
    return mode.encode('ascii') + iv_nonce + hmac

def read_metadata(data: bytes):
    mode = data[:3].decode('ascii')
    iv_nonce = data[3:19]
    hmac = data[19:51]
    return mode, iv_nonce, hmac

def drop_metadata(data: bytes) -> bytes:
    return data[51:]

def get_file_extension(filepath: str) -> str:
    _, extension = os.path.splitext(filepath)
    return extension

def file_signature_len(filepath: str) -> int:
    extension = get_file_extension(filepath)
    if extension == '.png':
        return 8
    if extension == '.jpg':
        return 4
    
def get_file_signature(filepath: str, text: bytes) -> bytes:
    return text[:file_signature_len(filepath)]

def drop_file_signature(filepath: str, text: bytes) -> bytes:
    return text[file_signature_len(filepath):]

def encrypt(data, key, mode, iv_nonce):
    cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return write_metadata(mode, iv_nonce, hmac_sign(key, ciphertext)) + ciphertext

def decrypt(ciphertext, key):
    try:
        mode, iv_nonce, original_hmac = read_metadata(ciphertext)
        ciphertext = drop_metadata(ciphertext)
        if not hmac_verify(key, original_hmac, ciphertext):
            raise ValueError("Ciphertext has been tampered with or the key is incorrect")
        cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad(padded_plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return None
    

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encryption Application")
        self.geometry("400x250")
        self.selected_app_mode = tk.StringVar(value="Normal")
        self.selected_mode = tk.StringVar(value="ECB")
        self.key = generate_key()

        app_modes_frame = tk.Frame(self)
        app_modes_frame.pack(pady=10)
        tk.Label(app_modes_frame, text="Choose application mode:").pack(side="left")
        for mode in ["Normal", "Demo"]:
            tk.Radiobutton(app_modes_frame, text=mode, value=mode, variable=self.selected_app_mode).pack(side="left")

        modes_frame = tk.Frame(self)
        modes_frame.pack(pady=10)
        tk.Label(modes_frame, text="Choose encryption mode:").pack(side="left")
        for mode in ["ECB", "CBC", "CTR"]:
            tk.Radiobutton(modes_frame, text=mode, value=mode, variable=self.selected_mode).pack(side="left")

        self.encrypt_button = tk.Button(self, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)
        self.decrypt_button = tk.Button(self, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)
        self.tamper_button = tk.Button(self, text="Tamper with Encrypted File", command=self.tamper_file)
        self.tamper_button.pack(pady=5)

    def encrypt_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        with open(filepath, 'rb') as f:
            data = f.read()
        mode = self.selected_mode.get()
        iv_nonce = generate_iv() if mode in ["CBC", "CTR"] else None
        ciphertext = encrypt(data, self.key, mode, iv_nonce)
        with open(filepath + ".enc", 'wb') as f:
            f.write(ciphertext)
        messagebox.showinfo("Encryption", f"File encrypted using {mode} mode.")


    def decrypt_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return
        with open(filepath, 'rb') as f:
            file_content = f.read()
        plaintext = decrypt(file_content, self.key)
        if plaintext is not None:
            with open(filepath.replace(".enc", ""), 'wb') as f:
                f.write(plaintext)
            messagebox.showinfo("Decryption", f"File decrypted.")
        else:
            messagebox.showerror("Decryption Error", "Failed to decrypt due to tampering or other errors.")

    def tamper_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return
        byte_position = simpledialog.askinteger("Tamper", "Enter the byte position to tamper with:", minvalue=0)
        with open(filepath, 'rb+') as f:
            f.seek(byte_position)
            original_byte = f.read(1)
            tampered_byte = bytes([original_byte[0] ^ 0xFF])  # Simple XOR with 0xFF to flip the bits
            f.seek(byte_position)
            f.write(tampered_byte)
        messagebox.showinfo("Tampering", f"Byte at position {byte_position} has been tampered with.")

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()

