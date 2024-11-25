# About the Password Manager Project

This script implements a secure password manager with a graphical user interface (GUI) using Tkinter. The application allows users to register, log in, and manage their passwords securely. Passwords are encrypted using AES-GCM, derived from a user-provided password and a salt.

## Modules and Imports:
- `tkinter`: Provides the GUI framework.
- `messagebox`: Part of Tkinter for displaying error and information messages.
- `json`: Handles serialization and deserialization of user data.
- `os`: Provides operating system-related functionalities.
- `hashlib`: Used for hashing passwords.
- `cryptography.hazmat.primitives.kdf.pbkdf2`: Implements PBKDF2HMAC (Password-Based Key Derivation Function 2, Hash-based Message Authentication Code) for key derivation.
- `cryptography.hazmat.primitives.ciphers.aead`: Provides AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) for encryption and decryption.
- `base64`: Handles encoding and decoding of binary data to text format.

## Key Components:
1. `hash_password(password)`: Hashes a plain text password using SHA-256.
2. `derive_key(password, salt)`: Derives a cryptographic key from a password and salt using PBKDF2-HMAC with SHA-256.
3. `encrypt(data, key)`: Encrypts a string using AES-GCM with the provided key.
4. `decrypt(encrypted_data, key)`: Decrypts AES-GCM encrypted data using the provided key.

## Classes:
1. `LoginWindow`: Handles user registration and login. It loads, verifies, and saves user credentials (hashed passwords) in a JSON file.
2. `PasswordManagerUI`: Provides the main interface for managing passwords once a user is logged in. It allows adding, updating, retrieving, deleting, and displaying passwords.
3. `PasswordManager`: Manages the storage and retrieval of encrypted passwords for each user. Passwords are stored in a JSON file, encrypted using AES-GCM with a derived key from the user's password.

## Main Functions:
- `main_app(username, password)`: Initializes the password manager UI for the logged-in user.
- `main()`: Initializes the login window for the user.

The application begins execution with the `main()` function, displaying the login window. Upon successful login or registration, the password manager UI is displayed, allowing the user to securely manage their passwords.
