# changed size of login box - Delete this before submitting

import os
import json
import base64 #binary to text encode and decode
import hashlib #SHA-256 hashing
import tkinter as tk
from tkinter import messagebox

# derives key with password and salt, PBKDF2 (Password-Based Key Derivation Function 2), HMAC (Hash-based Message Authentication Code)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.primitives import hashes #hashing algorithms for PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Advanced Encryption Standard in Galois/Counter Mode


CURRENT_DIR = os.getcwd()
USERS_FILE = os.path.join(CURRENT_DIR, "users.json")
#randomness added to plaintext for hashing
SALT_SIZE = 16  # size of the salt for PBKDF2
KEY_SIZE = 32   # AES-256 key size
# Number used once: ensure uniqueness with encryption
NONCE_SIZE = 12 # size of the nonce for AES-GCM


def hash_password(password):
    """Securely hashes a password using the SHA-256 hashing algorithm

    Args:
        password (str): Plain text

    Returns:
        str: returns the SHA-256 hash of the password as a hexadecimal string
    """
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(password, salt):
    """Derives a cryptographic key from a password using the PBKDF2-HMAC-SHA256 algorithm.
    Args:
        password (str): plain text password from which to derive the key
        salt (bytes): cryptographic salt that adds randomness to the key derivation process

    Returns:
        bytes: derived cryptographic key, with a length specified by the `KEY_SIZE` constant
    """
    #key derivation function (kdf)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(data, key):
    """Encrypts the provided data using AES-GCM (Galois/Counter Mode) with the provided key

    Args:
        data (str): plain text data to be encrypted
        key (bytes): cryptographic key used for encryption

    Returns:
        str: base64-encoded string containing the nonce and the encrypted data
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + encrypted_data).decode()

def decrypt(encrypted_data, key):
    """
    Decrypts base64-encoded AES-GCM encrypted data.

    Args:
        encrypted_data (str): Base64-encoded encrypted data.
        key (bytes): Key used for decryption (must be 16, 24, or 32 bytes long).

    Returns:
        str: Decrypted plaintext.
    """
    encrypted_data = base64.b64decode(encrypted_data.encode())
    nonce = encrypted_data[:NONCE_SIZE]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_data[NONCE_SIZE:], None).decode()

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager Login")
        self.master.geometry("300x150")
        
        self.username_label = tk.Label(master, text="Username:")
        self.username_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.username_entry = tk.Entry(master)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)
        
        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=5)
        
        self.password_entry = tk.Entry(master, show='*')
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)
        
        self.login_button = tk.Button(master, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.register_button = tk.Button(master, text="Register", command=self.register)
        self.register_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.users = self.load_users()
        
    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as file:
                return json.load(file)
        return {}
        
    def save_users(self):
        with open(USERS_FILE, 'w') as file:
            json.dump(self.users, file)
        
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = hash_password(password)
        
        if username in self.users and self.users[username] == hashed_password:
            # close the main window and open new window
            self.master.destroy()
            main_app(username, password)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = hash_password(password)
        
        if username in self.users:
            messagebox.showerror("Registration Failed", "Username already exists")
        elif not username or not password:
            messagebox.showerror("Registration Failed", "Username and password cannot be empty")
        else:
            self.users[username] = hashed_password
            self.save_users()
            messagebox.showinfo("Registration Successful", "User registered successfully")

class PasswordManagerUI:
    def __init__(self, master, username, password):
        self.master = master
        self.master.title(f"Password Manager - {username}")
        self.master.geometry("400x450")
        
        self.username = username
        self.password = password
        
        self.account_label = tk.Label(master, text="Account/Service:")
        self.account_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.account_entry = tk.Entry(master)
        self.account_entry.grid(row=0, column=1, padx=10, pady=5)
        
        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=5)
        
        self.password_entry = tk.Entry(master)
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)
        
        self.add_button = tk.Button(master, text="Add Password", command=self.add_password)
        self.add_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.update_button = tk.Button(master, text="Update Password", command=self.update_password)
        self.update_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.retrieve_button = tk.Button(master, text="Retrieve Password", command=self.retrieve_password)
        self.retrieve_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.delete_button = tk.Button(master, text="Delete Password", command=self.delete_password)
        self.delete_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        
        self.display_button = tk.Button(master, text="Display Passwords", command=self.display_passwords)
        self.display_button.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky="ew") 
        
        self.logout_button = tk.Button(master, text="Logout", command=self.logout)
        self.logout_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.output_label = tk.Label(master, text="")
        self.output_label.grid(row=8, column=0, columnspan=2, padx=10, pady=5)
        
        self.manager = PasswordManager(username, password)
        
    def add_password(self):
        account = self.account_entry.get()
        password = self.password_entry.get()
        
        if account and password:
            self.manager.add_password(account, password)
            self.output_label.config(text=f"Password for {account} added successfully")
        else:
            self.output_label.config(text="Please enter both an account and password")
            
    def update_password(self):
        account = self.account_entry.get()
        new_password = self.password_entry.get()
        if account and new_password:
            self.manager.update_password(account, new_password)
            self.output_label.config(text=f"Password for {account} updated successfully")
        else:
            self.output_label.config(text="Please enter both an account and new password")
        
    def retrieve_password(self):
        account = self.account_entry.get()
        if account:
            password = self.manager.get_password(account)
            if password:
                self.output_label.config(text=f"Password for {account}: {password}")
            else:
                self.output_label.config(text=f"No password found for {account}")
        else:
            self.output_label.config(text="Please enter the account to retrieve the password")
            
    def delete_password(self):
        account = self.account_entry.get()
        if account:
            self.manager.delete_password(account)
            self.output_label.config(text=f"Password for {account} deleted successfully")
        else:
            self.output_label.config(text="Please enter the account to delete a password")
            
    def display_passwords(self):
        passwords = self.manager.display_all_passwords()
        if passwords:
            self.output_label.config(text=passwords)
        else:
            self.output_label.config(text="No passwords stored")
    
    def logout(self):
        # close the main window and open new window
        self.master.destroy()
        main()

class PasswordManager:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.salt = self.get_or_create_salt()
        self.key = derive_key(password, self.salt)
        self.passwords_file = os.path.join(CURRENT_DIR, f"{username}_passwords.json")
        self.passwords = self.load_passwords()
    
    def get_or_create_salt(self):
        salt_file = os.path.join(CURRENT_DIR, f"{self.username}_salt.bin")
        if os.path.exists(salt_file):
            #open file in binary mode
            with open(salt_file, 'rb') as file:
                return file.read()
        salt = os.urandom(SALT_SIZE)
        # write to file in binary
        with open(salt_file, 'wb') as file:
            file.write(salt)
        return salt
    
    def load_passwords(self):
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file, 'r') as file:
                encrypted_data = file.read()
                decrypted_data = decrypt(encrypted_data, self.key)
                return json.loads(decrypted_data)
        return {}
        
    def save_passwords(self):
        with open(self.passwords_file, 'w') as file:
            encrypted_data = encrypt(json.dumps(self.passwords), self.key)
            file.write(encrypted_data)
    
    def add_password(self, account, password):
        self.passwords[account] = password
        self.save_passwords()
    
    def update_password(self, account, new_password):
        if account in self.passwords:
            self.passwords[account] = new_password
            self.save_passwords()
    
    def get_password(self, account):
        return self.passwords.get(account)
    
    def delete_password(self, account):
        if account in self.passwords:
            del self.passwords[account]
            self.save_passwords()
            
    def display_all_passwords(self):
        return "\n".join(f"{account}: {password}" for account, password in self.passwords.items())
    
def main_app(username, password):
    root = tk.Tk()
    app = PasswordManagerUI(root, username, password)
    root.mainloop()

def main():
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()

if __name__ == '__main__':
    main()
