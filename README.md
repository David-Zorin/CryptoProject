## 📋 Overview
This project is developed as part of a college engineering course to explore and implement fundamental cryptographic concepts. The application provides a secure file transfer system with a user-friendly GUI, demonstrating real-world applications of cryptographic algorithms

## 🔐 Cryptographic Components

### File Encryption
- **Algorithm**: IDEA cipher with 64-bit blocks
- **Mode**: Cipher Block Chaining (CBC) for enhanced security
- **Key Size**: 128-bit session keys
- **Block Processing**: Files processed in 2MB chunks

### Key Exchange
- **System**: Merkle-Hellman Knapsack
- **Purpose**: Securely wrap/unwrap 128-bit session keys
- **Key Derivation**: Passphrase-based deterministic key generation

### Digital Signatures
- **Algorithm**: ECDSA with secp192r1 curve (192-bit)
- **Hash Function**: SHA-256 for message integrity
- **Verification**: Ensures file authenticity and tampering detection

## 🚀 How It Works

### Sender Workflow:
1. **Session Key Generation**: A random 128-bit session key is generated
2. **File Encryption**: Input file is encrypted using IDEA-CBC with the session key
3. **Key Wrapping**: Session key is encrypted using Merkle-Hellman knapsack
4. **Digital Signing**: Encrypted file is signed with ECDSA for authenticity
5. **Bundle Creation**: Ciphertext, wrapped key, and signature are packaged together

### Receiver Workflow:
1. **Bundle Parsing**: Encrypted file bundle is read and parsed
2. **Signature Verification**: ECDSA signature is verified to ensure integrity
3. **Key Unwrapping**: Session key is recovered using Merkle-Hellman decryption
4. **File Decryption**: Original file is restored using IDEA-CBC decryption


## 📖 Usage

### 1. Launch Application
```bash
python main.py
```
The GUI opens with two tabs: **Sender** and **Receiver**.

![image](https://github.com/user-attachments/assets/73fc4224-bff0-4ec7-820e-9515fb32503f)


### 2. Sender Operation
1. Navigate to the **Sender** tab
2. Click **Browse** next to "Input" to select the file to encrypt
3. Click **Browse** next to "Output" to choose where to save the encrypted bundle
4. Enter a strong passphrase in the "Pass-phrase" field
5. Click **Run** to begin the encryption process
6. Monitor progress through the progress bar and log output

### 3. Receiver Operation
1. Navigate to the **Receiver** tab
2. Click **Browse** next to "Input" to select the encrypted bundle file
3. Click **Browse** next to "Output" to choose where to save the decrypted file
4. Enter the **same passphrase** used by the sender
5. Click **Run** to decrypt and verify the file
6. The application will verify the signature and decrypt the original file

## 📁 Project Structure

```
secure-file-transfer/
├── main.py                 # Application entry point
├── core/                   # Core cryptographic modules
│   ├── file_cipher.py      # File encryption/decryption with IDEA-CBC
│   ├── key_exchange.py     # Merkle-Hellman knapsack implementation
│   ├── signature.py        # ECDSA signing and verification
│   └── secure_transfer.py  # High-level send/receive operations
├── crypto/                 # Low-level cryptographic primitives
│   ├── idea.py            # IDEA cipher implementation
│   ├── cbc.py             # CBC mode wrapper
│   └── utils.py           # Cryptographic utilities
└── gui/                   # User interface
    └── app.py             # Tkinter GUI implementation
```


## ⚠️ Educational Notice
This implementation is designed for **educational purposes** to demonstrate cryptographic concepts.
