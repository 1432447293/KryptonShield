"""
KryptonShield GUI - A graphical interface for the Argon2 + AES-256-GCM encryption tool.
"""

import os
import sys
import shutil
import tempfile
import secrets
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from argon2 import PasswordHasher
from Crypto.Cipher import AES

# --- Configuration Parameters ---
KEY_LENGTH = 32
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 512 * 1024  # 512 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN
)

# --- Cryptographic Core ---
def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(ARGON2_SALT_LEN)
    password_bytes = password.encode('utf-8')
    derived_hash = ph.hash(password_bytes, salt=salt)
    aes_key = hashlib.sha256(derived_hash.encode('utf-8')).digest()
    return aes_key, salt

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    key, _ = derive_key_from_password(password, salt)
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + nonce + tag + ciphertext

def decrypt_data(encrypted_blob: bytes, password: str) -> bytes:
    if len(encrypted_blob) < ARGON2_SALT_LEN + 12 + 16:
        raise ValueError("Invalid or corrupted encrypted data")
    salt = encrypted_blob[:ARGON2_SALT_LEN]
    nonce = encrypted_blob[ARGON2_SALT_LEN:ARGON2_SALT_LEN+12]
    tag = encrypted_blob[ARGON2_SALT_LEN+12:ARGON2_SALT_LEN+12+16]
    ciphertext = encrypted_blob[ARGON2_SALT_LEN+12+16:]
    key, _ = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# --- File/Folder Operations ---
def encrypt_file(filepath: str, password: str, output_path: str = None) -> str:
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_data(data, password)
    if output_path is None:
        output_path = filepath + '.enc'
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    return output_path

def encrypt_folder(folder_path: str, password: str, output_path: str = None) -> str:
    if not os.path.isdir(folder_path):
        raise ValueError(f"Not a folder: {folder_path}")
    folder_name = os.path.basename(os.path.normpath(folder_path))
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, folder_name)
        created_zip = shutil.make_archive(zip_path, 'zip', folder_path)
        with open(created_zip, 'rb') as f:
            zip_data = f.read()
    encrypted_data = encrypt_data(zip_data, password)
    if output_path is None:
        output_path = os.path.join(os.path.dirname(folder_path), folder_name + '.zip.enc')
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    return output_path

def decrypt_file(filepath: str, password: str, output_path: str = None) -> str:
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_data(encrypted_data, password)
    if output_path is None:
        if filepath.endswith('.enc'):
            base = filepath[:-4]
        else:
            base = filepath + '.dec'
        output_path = base
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    # If it's a ZIP, ask to extract
    if decrypted_data[:2] == b'PK':
        # For GUI, we handle extraction automatically if user wants
        return output_path  # Return the decrypted file path; extraction will be handled separately
    return output_path

# --- GUI Application ---
class KryptonShieldGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("KryptonShield - High-Security Encryption Tool")
        self.root.geometry("650x400")
        self.root.resizable(False, False)
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Main Frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="KryptonShield", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=(0, 5))
        subtitle_label = ttk.Label(main_frame, text="Argon2 + AES-256-GCM", font=("Helvetica", 10))
        subtitle_label.pack(pady=(0, 20))
        
        # Path Selection
        path_frame = ttk.LabelFrame(main_frame, text="File / Folder Selection", padding="10")
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, state='readonly')
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="Browse...", command=self.browse_path)
        browse_btn.pack(side=tk.RIGHT)
        
        # Operation Mode
        mode_frame = ttk.LabelFrame(main_frame, text="Operation", padding="10")
        mode_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.mode_var = tk.StringVar(value="encrypt_file")
        ttk.Radiobutton(mode_frame, text="Encrypt a File", variable=self.mode_var, value="encrypt_file").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Encrypt a Folder", variable=self.mode_var, value="encrypt_folder").pack(anchor=tk.W)
        ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt").pack(anchor=tk.W)
        
        # Password Frame
        pass_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Password entry
        pass_row1 = ttk.Frame(pass_frame)
        pass_row1.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(pass_row1, text="Password:", width=15).pack(side=tk.LEFT)
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(pass_row1, textvariable=self.pass_var, show="*")
        self.pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Confirm password (only for encryption)
        pass_row2 = ttk.Frame(pass_frame)
        pass_row2.pack(fill=tk.X)
        ttk.Label(pass_row2, text="Confirm:", width=15).pack(side=tk.LEFT)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(pass_row2, textvariable=self.confirm_var, show="*")
        self.confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Toggle confirm field based on mode
        self.mode_var.trace('w', self.toggle_confirm)
        
        # Action Button
        self.action_btn = ttk.Button(main_frame, text="Start Encryption", command=self.start_action)
        self.action_btn.pack(pady=(10, 5))
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(5, 10))
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.toggle_confirm()  # Initial state
    
    def toggle_confirm(self, *args):
        """Enable confirm password only for encryption modes."""
        mode = self.mode_var.get()
        if mode == "decrypt":
            self.confirm_entry.config(state='disabled')
            self.action_btn.config(text="Start Decryption")
        else:
            self.confirm_entry.config(state='normal')
            if mode == "encrypt_file":
                self.action_btn.config(text="Encrypt File")
            else:
                self.action_btn.config(text="Encrypt Folder")
    
    def browse_path(self):
        mode = self.mode_var.get()
        if mode == "encrypt_file":
            path = filedialog.askopenfilename(title="Select a file to encrypt")
        elif mode == "encrypt_folder":
            path = filedialog.askdirectory(title="Select a folder to encrypt")
        else:  # decrypt
            path = filedialog.askopenfilename(title="Select an encrypted file", 
                                              filetypes=[("Encrypted files", "*.enc *.zip.enc"), ("All files", "*.*")])
        if path:
            self.path_var.set(path)
    
    def start_action(self):
        # Run in separate thread to avoid blocking GUI
        threading.Thread(target=self._action_thread, daemon=True).start()
    
    def _action_thread(self):
        mode = self.mode_var.get()
        path = self.path_var.get().strip()
        password = self.pass_var.get()
        confirm = self.confirm_var.get()
        
        if not path:
            self.show_error("Please select a file or folder.")
            return
        if not password:
            self.show_error("Password cannot be empty.")
            return
        
        if mode != "decrypt":
            if password != confirm:
                self.show_error("Passwords do not match.")
                return
        
        # Disable UI elements
        self.root.after(0, self.set_ui_state, False)
        self.root.after(0, self.progress.start)
        self.update_status("Processing... This may take a few seconds.")
        
        try:
            if mode == "encrypt_file":
                out = filedialog.asksaveasfilename(
                    title="Save encrypted file as",
                    defaultextension=".enc",
                    initialfile=os.path.basename(path) + ".enc"
                )
                if not out:
                    self.root.after(0, self.set_ui_state, True)
                    self.root.after(0, self.progress.stop)
                    self.update_status("Cancelled")
                    return
                result = encrypt_file(path, password, out)
                self.show_info(f"File encrypted successfully!\nSaved to: {result}")
                self.update_status("Encryption completed")
                
            elif mode == "encrypt_folder":
                out = filedialog.asksaveasfilename(
                    title="Save encrypted folder as",
                    defaultextension=".zip.enc",
                    initialfile=os.path.basename(path) + ".zip.enc"
                )
                if not out:
                    self.root.after(0, self.set_ui_state, True)
                    self.root.after(0, self.progress.stop)
                    self.update_status("Cancelled")
                    return
                result = encrypt_folder(path, password, out)
                self.show_info(f"Folder encrypted successfully!\nSaved to: {result}")
                self.update_status("Encryption completed")
                
            else:  # decrypt
                out = filedialog.asksaveasfilename(
                    title="Save decrypted file as",
                    initialfile=os.path.splitext(os.path.basename(path))[0]
                )
                if not out:
                    self.root.after(0, self.set_ui_state, True)
                    self.root.after(0, self.progress.stop)
                    self.update_status("Cancelled")
                    return
                result = decrypt_file(path, password, out)
                # Check if it's a ZIP and offer extraction
                with open(result, 'rb') as f:
                    header = f.read(2)
                if header == b'PK':
                    extract = messagebox.askyesno("Extract ZIP", 
                                                  "Decrypted file is a ZIP archive. Extract it now?")
                    if extract:
                        extract_dir = filedialog.askdirectory(title="Select extraction folder")
                        if extract_dir:
                            import zipfile
                            with zipfile.ZipFile(result, 'r') as zf:
                                zf.extractall(extract_dir)
                            os.remove(result)
                            self.show_info(f"Folder extracted to: {extract_dir}")
                            self.update_status("Decryption and extraction completed")
                            return
                self.show_info(f"Decryption successful!\nSaved to: {result}")
                self.update_status("Decryption completed")
                
        except Exception as e:
            self.show_error(f"Operation failed: {str(e)}")
            self.update_status("Error occurred")
        finally:
            self.root.after(0, self.set_ui_state, True)
            self.root.after(0, self.progress.stop)
    
    def set_ui_state(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        for child in self.root.winfo_children():
            try:
                child.config(state=state)
            except:
                pass
        # Keep status label enabled
        self.toggle_confirm()
    
    def update_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))
    
    def show_error(self, msg):
        self.root.after(0, lambda: messagebox.showerror("Error", msg))
    
    def show_info(self, msg):
        self.root.after(0, lambda: messagebox.showinfo("Success", msg))

# --- Main Entry Point ---
if __name__ == "__main__":
    root = tk.Tk()
    app = KryptonShieldGUI(root)
    root.mainloop()
