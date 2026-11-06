# 🔐 File Encryption Tool


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/File_Encryption_Tool.git
cd File_Encryption_Tool
```

> **Author:** hemanathan115  
> **Language:** C++17  
> **Library:** OpenSSL  
> **Algorithms:** AES-256-CBC · RSA-2048 · SHA-256

---

## 📖 Overview

A command-line file encryption tool built in C++ using the OpenSSL library.  
It provides strong, industry-standard encryption for any file on your system, with built-in integrity checking so you can be sure a decrypted file has not been tampered with.

---

## 🔑 Cryptography Used

| Algorithm | Purpose | Details |
|-----------|---------|---------|
| **AES-256-CBC** | File encryption / decryption | 256-bit key, random IV, PKCS#7 padding |
| **SHA-256** | Integrity check | Hash of plaintext stored in encrypted file header |
| **PBKDF2 / HMAC-SHA-256** | Key derivation | 100 000 iterations, 16-byte random salt |
| **RSA-2048** | Asymmetric key utility | Key-pair generation helper |

---

## 📁 Project Structure

```
File_Encryption_Tool/
├── File_Encryption_Tool.cpp   # Full source code
└── README.md                  # This file
```

---

## ⚙️ Prerequisites

### Install OpenSSL development headers

**Ubuntu / Debian**
```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

**Fedora / RHEL**
```bash
sudo dnf install openssl-devel
```

**macOS (Homebrew)**
```bash
brew install openssl
```

---

## 🔨 Compile

```bash
g++ -std=c++17 -O2 File_Encryption_Tool.cpp \
    -lssl -lcrypto -o file_enc
```

On macOS you may need to point the compiler at Homebrew's OpenSSL:
```bash
g++ -std=c++17 -O2 File_Encryption_Tool.cpp \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto -o file_enc
```

---

## 🚀 Usage

### Encrypt a file
```bash
./file_enc encrypt secret.txt secret.enc
```
You will be prompted to enter and confirm a password (input is hidden).

### Decrypt a file
```bash
./file_enc decrypt secret.enc recovered.txt
```
Enter the same password used during encryption.

### Verify file integrity (SHA-256)
```bash
./file_enc verify secret.txt
```
Prints the SHA-256 hash of any file.

### Generate RSA-2048 key pair
```bash
./file_enc genrsa private.pem public.pem
```

---

## 📦 Encrypted File Format

Every `.enc` file produced by this tool has the following binary layout:

```
[ MAGIC  5 bytes  ]  "FENC1"  – identifies the file format
[ SALT   16 bytes ]  Random salt for PBKDF2 key derivation
[ HASH   32 bytes ]  SHA-256 of the original plaintext
[ CIPHER n bytes  ]  AES-256-CBC ciphertext (PKCS#7 padded)
```

---

## ✅ Features

- **File Encryption** – AES-256-CBC with a password-derived key
- **Secure Password Input** – Terminal echo is disabled while typing
- **Decryption** – Fully reverses the encryption process
- **Integrity Check** – SHA-256 hash verified on every decryption
- **RSA Key Generation** – 2048-bit key pair for asymmetric use cases
- **Cross-platform** – Linux & macOS (any POSIX system with OpenSSL)

---

## 🛡️ Security Notes

- Passwords are never stored; only the derived key (in memory) is used.
- A fresh random salt is generated for every encryption operation.
- 100 000 PBKDF2 iterations slow down brute-force attacks.
- The integrity hash is checked before the decrypted file is written, protecting against silent corruption or tampering.

---

## 🎓 Learning Goals

This project demonstrates practical cryptography concepts relevant to cybersecurity:

1. Symmetric encryption with **AES**
2. Password-based key derivation with **PBKDF2**
3. Message integrity with **SHA-256**
4. Asymmetric key generation with **RSA**
5. Secure coding practices (zeroing memory, hidden input)

---

## 📜 License

MIT License – free to use, modify, and distribute.

---

*Built with ❤️ by hemanathan115*
