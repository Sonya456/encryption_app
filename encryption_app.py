import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature
from PIL import Image
import os

    
demo_iv = b"\xa3\x95\x87\x92\x1d\x3f\xb0\x4d\x7e\x8f\x59\x3c\x24\x68\xa0\x6e"

demo_key = b"\x9b\x8f\xae\x2c\xd1\x45\x0f\x78\x3b\x2e\x4d\x9f\xa4\xb7\x8c\xfe\x12"\
           b"\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88"

def open_file(filetype):
    """ 
        Reads file in binary mode, used to generate ciphertext or use as a key
        Returns: filepath, file_content
    """

    filepath = filedialog.askopenfilename(filetypes=filetype)
    if not filepath:
        return None, None
    with open(filepath, 'rb') as f:
            file_content = f.read()
    return filepath, file_content

def open_image(filetype):
    """ 
        Reads file in binary mode to generate ciphertext and image to generate encrypted image in demo mode
        Returns: filepath, file_content, image_content, image
    """

    filepath, file_content = open_file(filetype)
    if filepath is None:
        return None, None, None, None
    image = Image.open(filepath)
    image_content = image.tobytes()
    return filepath, file_content, image_content, image

def save_file(text, default_ext, initialfile='*'):
    """ 
        Saves bytes array to file with given extension, used to save ciphertexts and keys
        Returns: True for successful save, False otherwise
    """
        
    filepath = filedialog.asksaveasfilename(initialfile=initialfile, defaultextension=default_ext)
    if not filepath:
        return False
    if text is not None:
        with open(filepath, 'wb') as f:
            f.write(text)
    return True

def save_image(file: Image, default_ext, initialfile='*'):
    """ 
        Saves image to file with given extension, used to save encrypted images in demo mode
        Returns: True for successful save, False otherwise
    """

    filepath = filedialog.asksaveasfilename(initialfile=initialfile, defaultextension=default_ext)
    if not filepath:
        return False
    file.save(filepath)
    return True

def get_file_extension(filepath: str) -> str:
    _, extension = os.path.splitext(filepath)
    return extension

def get_file_name(filepath: str) -> str:
    name, _ = os.path.splitext(os.path.basename(filepath))
    return name

def xor_images_content(image: Image, image_content1: bytes, image_content2: bytes):
    """ 
        Parameters: image is any of two original images, is used to create xored image\n
        Returns: Image with xored content
    """
    xor_bytes = bytes(a ^ b for a, b in zip(image_content1, image_content2))
    return Image.frombytes(image.mode, image.size, xor_bytes)


def generate_key():
    """ 
        Returns: 256-bit key for AES
    """

    return os.urandom(32)

def generate_iv():
    """ 
        Returns: 128-bit key for AES
    """
    return os.urandom(16)  # 128-bit IV for AES

def mode_from_str(mode: str, iv_nonce) -> modes.Mode:
    if mode == 'ECB':
        return modes.ECB()
    if mode == 'CBC':
        return modes.CBC(iv_nonce)
    if mode == 'CTR':
        return modes.CTR(iv_nonce)


def pad(data):
    """ 
        Required for CBC and ECB modes
    """
    padder = PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def hmac_sign(key, data):
    """ 
        Generates Hash-based message authentication code using SHA256
    """

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



def generate_metadata(mode: str, iv_nonce, hmac, extension: str) -> bytes:
    """ 
        Generates ciphertext metadata in following format:\n
        mode (3 bytes) + iv_nonce (16 bytes) + hmac (32 bytes) + file extension (16 bytes) - total 67 bytes
    """

    if iv_nonce is None:
        iv_nonce = bytes(16)
    if hmac is None:
        hmac = bytes(32)
    if extension is None:
        extension = bytes(16)
    else:
        extension = extension.ljust(16, '\0').encode('ascii')
    return mode.encode('ascii') + iv_nonce + hmac + extension

def read_metadata(data: bytes):
    """ 
        Reads 67 bytes of ciphertext metadata from the END of ciphertext
    """

    extension = data[-16:].decode('ascii').strip('\0')
    hmac = data[-48:-16]
    iv_nonce = data[-64:-48]
    mode = data[-67:-64].decode('ascii')
    return mode, iv_nonce, hmac, extension

def drop_metadata(data: bytes) -> bytes:
    """ 
        Drops 67 bytes of ciphertext metadata from the end of ciphertext
        Returns: data without metadata
    """
    return data[:-67]


def encrypt(data: bytes, key: bytes, mode: str, extension: str) -> bytes:
    """ 
        Encrypts data using AES with given 256-bit key and encryption mode.
        IV_nonce is generated inside the function
        Parameters: extension stands for original file extension to be stored in metadata
        Returns: ciphertext with metadata included in the end of array
    """
    iv_nonce = generate_iv() if mode in ["CBC", "CTR"] else None

    cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext + generate_metadata(mode, iv_nonce, hmac_sign(key, ciphertext), extension)

def demo_encrypt(data, image_data, mode, extension):
    """ 
        Encrypts image using AES with given encryption mode.\n
        Key and IV_nonce are constants, HMAC is not included in
         metadata for demo purposes\n
        Parameters:
            data: file data to be encrypted and be used as ciphertext
            image_data: image data to be encrypted and be used to create encrypted image
            mode: encryption mode
            extension: original file extension to be stored in metadata
        Returns: ciphertext with metadata included in the end of array, 
         encrypted image data
    """

    global demo_iv, demo_key
    key = demo_key
    iv_nonce = demo_iv if mode in ["CBC", "CTR"] else None

    data_cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
    image_cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
    data_encryptor = data_cipher.encryptor()
    image_encryptor = image_cipher.encryptor()

    padded_data = pad(data)
    padded_image_data = pad(image_data)

    ciphertext = data_encryptor.update(padded_data) + data_encryptor.finalize()
    ciphered_image = image_encryptor.update(padded_image_data) + image_encryptor.finalize()

    return ciphertext + generate_metadata(mode, iv_nonce, None, extension), ciphered_image

def decrypt(ciphertext, key):
    """ 
        Decrypts ciphertext using AES with given 256-bit key.\n
        IV_nonce, HMAC and encryption mode are read from metadata. Wrong key or failure to verify HMAC will raise ValueError
        Returns: plaintext and original file extension
    """

    try:
        mode, iv_nonce, original_hmac, extension = read_metadata(ciphertext)
        ciphertext = drop_metadata(ciphertext)

        if not hmac_verify(key, original_hmac, ciphertext):
            raise ValueError("Ciphertext has been changed or the key is incorrect")
        
        cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return unpad(padded_plaintext), extension
    
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return None, None

def demo_decrypt(ciphertext):
    """ 
        Decrypts ciphertext using AES\n
        Key is constant for demo purposes\n
        IV_nonce and encryption mode are read from metadata, HMAC is not verified
        Returns: plaintext and original file extension
    """

    global demo_key
    key = demo_key
    try:
        mode, iv_nonce, _, extension = read_metadata(ciphertext)
        ciphertext = drop_metadata(ciphertext)

        cipher = Cipher(algorithms.AES(key), mode_from_str(mode, iv_nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return unpad(padded_plaintext), extension
    
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return None, None


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
            tk.Radiobutton(app_modes_frame, text=mode, value=mode, 
                           variable=self.selected_app_mode, command=self.update_buttons_mode).pack(side="left")

        modes_frame = tk.Frame(self)
        modes_frame.pack(pady=10)
        tk.Label(modes_frame, text="Choose encryption mode:").pack(side="left")
        for mode in ["ECB", "CBC", "CTR"]:
            tk.Radiobutton(modes_frame, text=mode, value=mode, variable=self.selected_mode).pack(side="left")
        
        key_frame = tk.Frame(self)
        key_frame.pack(pady=5)
        self.save_key_button = tk.Button(key_frame, text="Save current key", command=self.save_key, )
        self.save_key_button.pack(side="left", padx=5)
        self.save_key_button = tk.Button(key_frame, text="Load key", command=self.load_key)
        self.save_key_button.pack(side="left")

        encrypt_frame = tk.Frame(self)
        encrypt_frame.pack(pady=5)
        self.encrypt_button = tk.Button(encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(side="left", padx=5)
        self.decrypt_button = tk.Button(encrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(side="left")

        self.change_button = tk.Button(self, text="Change File", command=self.change_file)
        self.change_button.pack(pady=5)
        self.xor_button = tk.Button(self, text="Xor two images", command=self.xor_images)
        self.xor_button.pack(pady=5)

    def update_buttons_mode(self):
        if self.selected_app_mode.get() == "Normal":
            self.encrypt_button.config(command = self.encrypt_file)
            self.decrypt_button.config(command = self.decrypt_file)
        else:
            self.encrypt_button.config(command = self.demo_encrypt_file)
            self.decrypt_button.config(command = self.demo_decrypt_file)

    def save_key(self):
        if save_file(self.key, ".key"):
            self.key = generate_key()
            messagebox.showinfo("Key", "Key saved, current active key is changed.")

    def load_key(self):
        filepath, key = open_file([("Key file", "*.key")])
        if filepath is not None:
            if len(key) == 32:
                self.key = key
                messagebox.showinfo("Key", "Key loaded")
            else:
                messagebox.showerror("Key Error", "Key must be 256-bit long")


    def encrypt_file(self):
        filepath, file_content = open_file([("File to encrypt", "*.*")])
        if filepath is None:
            return
        mode = self.selected_mode.get()
        ciphertext = encrypt(file_content, self.key, mode, get_file_extension(filepath))
        if save_file(ciphertext, ".enc"):
            messagebox.showinfo("Encryption", f"File encrypted using {mode} mode.")

    def demo_encrypt_file(self):
        filepath, file_content, image_content, image = open_image([("File to encrypt", "*.*")])
        if filepath is None:
            return
        
        mode = self.selected_mode.get()
        ciphertext, ciphered_image  = demo_encrypt(file_content, image_content, mode, 
                                  get_file_extension(filepath))
        
        # saving demo ciphertext
        if save_file(ciphertext, ".enc"):
            messagebox.showinfo("Encryption", "File demo encryption saved")

        ciphered_image = Image.frombytes(image.mode, image.size, ciphered_image)

        # saving ciphered image
        if save_image(ciphered_image, get_file_extension(filepath), get_file_name(filepath)):
            messagebox.showinfo("Encryption", "Encrypted image saved")


    def decrypt_file(self):
        filepath, file_content = open_file([("File to decrypt", "*.enc")])
        if filepath is None:
            return
        
        plaintext, extension = decrypt(file_content, self.key)
        if plaintext is not None:
            if save_file(plaintext, extension, get_file_name(filepath)):
                messagebox.showinfo("Decryption", "File decrypted.")
        else:
            messagebox.showerror("Decryption Error", "Failed to decrypt due to changed ciphertext or other errors.")

    def demo_decrypt_file(self):
        filepath, file_content = open_file([("File to decrypt", "*.enc")])
        if filepath is None:
            return
        
        plaintext, extension = demo_decrypt(file_content)
        if plaintext is not None:
                if save_file(plaintext, extension, get_file_name(filepath)):
                    messagebox.showinfo("Decryption", "File decrypted.")
        else:
            messagebox.showerror("Decryption Error", "Failed to decrypt due to changed ciphertext or other errors.")

    def change_file(self):
        filepath, file_content = open_file([("File to change", "*.*")])
        if filepath is None:
            return
        
        byte_position = simpledialog.askinteger("Change", "Enter the byte position ( 0 - " + 
                                                str(len(file_content)) + " ) to change:", minvalue=0)
        
        if byte_position is None or byte_position < 0 or byte_position >= len(file_content):
            messagebox.showerror("Changing", "Invalid byte position")
            return
        
        with open(filepath, 'rb+') as f:
            f.seek(byte_position)
            original_byte = f.read(1)

            # flipping bits
            tampered_byte = bytes([original_byte[0] ^ 0xFF])
            f.seek(byte_position)
            f.write(tampered_byte)
        messagebox.showinfo("Changing", f"Byte at position {byte_position} has been changed.")

    def xor_images(self):
        # open first image
        filepath, _, image_content1, image = open_image([("First image to xor", "*.*")])
        if filepath is None:
            return
        
        # open second image
        filepath2, _, image_content2, _ = open_image([("Second image to xor", "*.*")])
        if filepath2 is None:
            return
        
        if len(image_content1) != len(image_content2):
            messagebox.showerror("XOR", "Images must have the same size")
            return

        xor_image = xor_images_content(image, image_content1, image_content2)
        if save_image(xor_image, get_file_extension(filepath), get_file_name(filepath)):
            messagebox.showinfo("XOR", "XOR of images saved")



if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()

