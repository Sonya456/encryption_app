import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature
import os

# Helper functions for cryptography
def generate_key():
    return os.urandom(32)  # 256-bit key for AES

def generate_iv():
    return os.urandom(16)  # 128-bit IV for AES

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

def encrypt(data, key, mode, iv_nonce=None):
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_nonce), backend=default_backend())
    elif mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv_nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv_nonce + ciphertext + hmac_sign(key, ciphertext) if iv_nonce else ciphertext + hmac_sign(key, ciphertext)

def decrypt(ciphertext, key, mode, iv_nonce=None):
    try:
        hmac_offset = -32
        original_hmac = ciphertext[hmac_offset:]
        ciphertext = ciphertext[:hmac_offset]
        if not hmac_verify(key, original_hmac, ciphertext):
            raise ValueError("Ciphertext has been tampered with or the key is incorrect")
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif mode == 'CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_nonce), backend=default_backend())
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv_nonce), backend=default_backend())
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
        self.selected_mode = tk.StringVar(value="ECB")
        self.key = generate_key()

        modes_frame = tk.Frame(self)
        modes_frame.pack(pady=10)
        tk.Label(modes_frame, text="Choose Mode:").pack(side="left")
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
        if iv_nonce:
            ciphertext = iv_nonce + ciphertext  # prepend IV/nonce for CBC and CTR modes
        with open(filepath + ".enc", 'wb') as f:
            f.write(ciphertext)
        messagebox.showinfo("Encryption", f"File encrypted using {mode} mode.")

    def decrypt_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return
        with open(filepath, 'rb') as f:
            file_content = f.read()
        mode = self.selected_mode.get()
        iv_nonce = file_content[:16] if mode in ["CBC", "CTR"] else None
        ciphertext = file_content[16:] if mode in ["CBC", "CTR"] else file_content
        plaintext = decrypt(ciphertext, self.key, mode, iv_nonce)
        if plaintext is not None:
            with open(filepath.replace(".enc", ".dec"), 'wb') as f:
                f.write(plaintext)
            messagebox.showinfo("Decryption", f"File decrypted using {mode} mode.")
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

