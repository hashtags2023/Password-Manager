# Password Manager with User Authentication and Encryption
 ## Overview
 This project is a Password Manager application built using Python and Tkinter for the GUI. The application allows users to register, log in, and manage their passwords securely. Each user's data is encrypted and stored locally on their machine to ensure privacy and security.

 ## Features
 - User Registration and Login with password hashing
 - Add, Update, Retrieve, and Delete passwords
 - Display all stored passwords
 - logout functionality
 - Persistent storage of user data and passwords using JSON files
 - encryption of password data using AES-GCM (Advanced Encryption Standard Galois/Counter Mode) for secure storage
   
## Requirements
- Python 3.x
- Tkinter
- `cryptogrgraphy` library for encryption (install using `pip`)
  - ```pip install cryptography```

## File Structure
```python
password-manager/
├── users.json                   # Stores registered users' hashed passwords
├── username_salt.bin            # Stores salt for key derivation for each user
├── username_passwords.json      # Stores encrypted password data for each user
├── password_manager.py          # Main application file
```
## Security
- **Password Hashing:** User passwords are hashed using SHA-256 before being stored in `users.json`
- **Encryption:** User password data is encrypted using AES-GCM before being stored in `{username}_passwords.json`
- **Key Derivation:** A unique salt is generated for each user and used to derive encryption keys from their passwords
