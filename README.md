# File Encryption Tool

C++17 command-line file encryption using OpenSSL.

## Security design

New files use **AES-256-GCM authenticated encryption** with:
- 12-byte random nonce and 16-byte authentication tag
- 16-byte random salt
- PBKDF2-HMAC-SHA-256 with 600,000 iterations
- Authenticated file metadata (format marker, salt, and nonce)

The program verifies the GCM tag before writing decrypted plaintext. A wrong password or modified encrypted file is rejected.

## Build

Install a C++17 compiler and OpenSSL development headers.

Ubuntu / Debian:
\`\`\`bash
sudo apt-get update
sudo apt-get install -y g++ libssl-dev
\`\`\`

Compile:
\`\`\`bash
g++ -std=c++17 -O2 -Wall -Wextra File_Encryption_Tool.cpp -lssl -lcrypto -o file_enc
\`\`\`

## Commands

Encrypt a file (password entry is hidden):
\`\`\`bash
./file_enc encrypt secret.txt secret.enc
\`\`\`

Decrypt a new FENC2 file:
\`\`\`bash
./file_enc decrypt secret.enc recovered.txt
\`\`\`

Run the built-in cryptographic round-trip and tamper-detection test:
\`\`\`bash
./file_enc self-test
\`\`\`

Generate an RSA-2048 key pair:
\`\`\`bash
./file_enc genrsa private.pem public.pem
\`\`\`

Calculate a SHA-256 digest of a file:
\`\`\`bash
./file_enc verify secret.txt
\`\`\`

## Encrypted file format

FENC2 files contain:

\`\`\`
[MAGIC: 5 bytes][SALT: 16][NONCE: 12][GCM TAG: 16][CIPHERTEXT]
\`\`\`

The magic, salt, and nonce are authenticated as additional data. The plaintext hash from the old design is no longer used as an integrity mechanism.

## Legacy FENC1 files

Older FENC1 files used AES-256-CBC with an unkeyed SHA-256 checksum. That format does **not** provide authenticated integrity. Normal \`decrypt\` refuses FENC1 files. If you must recover a trusted legacy file, use:

\`\`\`bash
./file_enc decrypt-legacy old-file.enc recovered.txt
\`\`\`

This command prints a warning. Do not use legacy recovery on files from untrusted sources; a checksum match is not proof against malicious tampering. Re-encrypt recovered data into FENC2.

## Notes

- Keep a separate backup of important original files.
- Use a strong, unique password and protect it; the tool does not store passwords.
- The current implementation reads the complete file into memory and limits a single file to the OpenSSL \`int\` input-size boundary.
- RSA key generation is a separate utility; it is not used by the password-based file encryption flow.

MIT License.
