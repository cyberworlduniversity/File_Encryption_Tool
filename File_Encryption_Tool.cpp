/*
 * ============================================================
 *  File Encryption Tool
 *  Author  : hemanathan115
 *  Language: C++17
 *  Library : OpenSSL (AES-256-GCM, RSA-2048, SHA-256)
 * ============================================================
 *
 *  Compile:
 *    g++ -std=c++17 -O2 File_Encryption_Tool.cpp \
 *        -lssl -lcrypto -o file_enc
 *
 *  Usage:
 *    ./file_enc encrypt <input_file> <output_file>
 *    ./file_enc decrypt <input_file> <output_file>
 *    ./file_enc decrypt-legacy <input_file> <output_file>
 *    ./file_enc self-test
 *    ./file_enc verify  <file>
 * ============================================================
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <climits>
#include <algorithm>
#include <filesystem>
#include <cerrno>
#include <cstring>

// ─── Constants ────────────────────────────────────────────────────────────────
constexpr int AES_KEY_LEN   = 32;   // AES-256
constexpr int AES_IV_LEN    = 12;
constexpr int LEGACY_IV_LEN = 16;
constexpr int GCM_TAG_LEN   = 16;
constexpr int PBKDF2_ITERATIONS = 600000;
constexpr int SALT_LEN      = 16;
constexpr int SHA256_LEN    = 32;
constexpr int RSA_KEY_BITS  = 2048;

// Magic header written at the start of every encrypted file
const std::string MAGIC = "FENC2";
const std::string LEGACY_MAGIC = "FENC1";

// ─── Utility: print OpenSSL errors ────────────────────────────────────────────
static void ssl_error(const std::string& msg)
{
    std::cerr << "[ERROR] " << msg << "\n";
    ERR_print_errors_fp(stderr);
    throw std::runtime_error(msg);
}

// ─── Secure password input (no echo) ──────────────────────────────────────────
std::string get_password(const std::string& prompt)
{
    struct termios oldt{}, newt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
        throw std::runtime_error("Password input requires an interactive terminal.");

    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
        throw std::runtime_error("Could not disable terminal echo for password input.");

    std::cout << prompt;
    std::string password;
    const bool input_ok = static_cast<bool>(std::getline(std::cin, password));
    const int restore_status = tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";

    if (restore_status != 0)
        throw std::runtime_error("Could not restore terminal settings after password input.");
    if (!input_ok)
        throw std::runtime_error("Could not read password input.");
    return password;
}

// ─── Derive AES key + IV from password + salt (PBKDF2/SHA-256) ───────────────
void derive_key_iv(const std::string& password,
                   const unsigned char* salt,
                   unsigned char* key,
                   unsigned char* iv)
{
    if (!PKCS5_PBKDF2_HMAC(password.c_str(),
                            static_cast<int>(password.size()),
                            salt, SALT_LEN,
                            100000,          // legacy FENC1 iterations
                            EVP_sha256(),
                            AES_KEY_LEN + LEGACY_IV_LEN,
                            key))            // output buffer (key || iv)
    {
        ssl_error("PBKDF2 key derivation failed");
    }
    // Split: first AES_KEY_LEN bytes → key, next LEGACY_IV_LEN bytes → legacy IV
    std::memcpy(iv, key + AES_KEY_LEN, LEGACY_IV_LEN);
}


void derive_key(const std::string& password, const unsigned char* salt, unsigned char* key)
{
    if (password.empty() || password.size() > static_cast<size_t>(INT_MAX))
        throw std::runtime_error("Password length is invalid.");
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                           salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(),
                           AES_KEY_LEN, key))
        ssl_error("PBKDF2 key derivation failed");
}

// ─── SHA-256 hash of a file ───────────────────────────────────────────────────
std::vector<unsigned char> sha256_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file for hashing: " + path);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[4096];
    while (f.read(buf, sizeof(buf)) || f.gcount())
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));

    std::vector<unsigned char> hash(SHA256_LEN);
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string hex_string(const std::vector<unsigned char>& data)
{
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

// ─── Read entire file into vector ─────────────────────────────────────────────
std::vector<unsigned char> read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open: " + path);
    const std::streamoff size = f.tellg();
    if (size < 0 || size > INT_MAX)
        throw std::runtime_error("Input file is too large for this encryption implementation.");
    f.seekg(0);
    std::vector<unsigned char> data(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size)))
        throw std::runtime_error("Failed while reading input file: " + path);
    return data;
}

// ─── Write vector to file ─────────────────────────────────────────────────────
void write_file(const std::string& path, const std::vector<unsigned char>& data)
{
    if (path.empty()) throw std::runtime_error("Output path must not be empty.");

    const std::filesystem::path target(path);
    const std::filesystem::path parent = target.has_parent_path()
        ? target.parent_path() : std::filesystem::path(".");
    std::filesystem::path temp = parent / (target.filename().string() + ".tmp.XXXXXX");
    std::string temp_template = temp.string();
    std::vector<char> temp_name(temp_template.begin(), temp_template.end());
    temp_name.push_back('\0');

    int fd = mkstemp(temp_name.data());
    if (fd < 0)
        throw std::runtime_error("Cannot create secure temporary output file: " + std::string(std::strerror(errno)));

    const std::string temp_path(temp_name.data());
    bool committed = false;
    try {
        size_t offset = 0;
        while (offset < data.size()) {
            const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0)
                throw std::runtime_error("Failed while writing output file.");
            offset += static_cast<size_t>(written);
        }

        if (fsync(fd) != 0)
            throw std::runtime_error("Failed to flush output file.");
        if (close(fd) != 0) {
            fd = -1;
            throw std::runtime_error("Failed to close output file.");
        }
        fd = -1;

        // Atomic rename replaces a destination symlink itself instead of following it.
        if (rename(temp_path.c_str(), path.c_str()) != 0)
            throw std::runtime_error("Could not safely replace output file: " + std::string(std::strerror(errno)));
        committed = true;
    } catch (...) {
        if (fd >= 0) close(fd);
        if (!committed) unlink(temp_path.c_str());
        throw;
    }
}

// ─── Authenticated AES-256-GCM helpers ────────────────────────────────────────
std::vector<unsigned char> make_aad(const unsigned char* salt, const unsigned char* iv)
{
    std::vector<unsigned char> aad(MAGIC.begin(), MAGIC.end());
    aad.insert(aad.end(), salt, salt + SALT_LEN);
    aad.insert(aad.end(), iv, iv + AES_IV_LEN);
    return aad;
}

std::vector<unsigned char> aes_gcm_encrypt(
    const unsigned char* key,
    const unsigned char* iv,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& plaintext,
    unsigned char* tag)
{
    if (aad.size() > static_cast<size_t>(INT_MAX) ||
        plaintext.size() > static_cast<size_t>(INT_MAX))
        throw std::runtime_error("Input is too large for this encryption implementation.");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) ssl_error("Could not allocate encryption context");

    int len = 0;
    int total = 0;
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, nullptr) ||
        !EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) ||
        !EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        ssl_error("AES-GCM initialization failed");
    }

    if (!plaintext.empty())
    {
        if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                               static_cast<int>(plaintext.size())))
        {
            EVP_CIPHER_CTX_free(ctx);
            ssl_error("AES-GCM encryption failed");
        }
        total = len;
    }

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        ssl_error("AES-GCM finalization failed");
    }
    total += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
    {
        EVP_CIPHER_CTX_free(ctx);
        ssl_error("Could not obtain AES-GCM authentication tag");
    }
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<size_t>(total));
    return ciphertext;
}

bool aes_gcm_decrypt(
    const unsigned char* key,
    const unsigned char* iv,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& ciphertext,
    const unsigned char* tag,
    std::vector<unsigned char>& plaintext)
{
    if (aad.size() > static_cast<size_t>(INT_MAX) ||
        ciphertext.size() > static_cast<size_t>(INT_MAX))
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int total = 0;
    plaintext.assign(ciphertext.size() + 16, 0);

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, nullptr) ||
        !EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) ||
        !EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        plaintext.clear();
        return false;
    }

    if (!ciphertext.empty())
    {
        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                               static_cast<int>(ciphertext.size())))
        {
            EVP_CIPHER_CTX_free(ctx);
            plaintext.clear();
            return false;
        }
        total = len;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                             const_cast<unsigned char*>(tag)))
    {
        EVP_CIPHER_CTX_free(ctx);
        plaintext.clear();
        return false;
    }

    const int authenticated = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (authenticated <= 0)
    {
        plaintext.clear();
        return false;
    }

    total += len;
    plaintext.resize(static_cast<size_t>(total));
    return true;
}

// FENC2 format: MAGIC | SALT | NONCE | GCM TAG | CIPHERTEXT.
// The magic, salt, and nonce are authenticated as additional data.
void encrypt_file(const std::string& in_path, const std::string& out_path)
{
    std::string password = get_password("Enter encryption password: ");
    std::string confirm  = get_password("Confirm password         : ");
    if (password.empty() || password != confirm)
        throw std::runtime_error("A non-empty matching password is required.");

    unsigned char salt[SALT_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char key[AES_KEY_LEN];
    unsigned char tag[GCM_TAG_LEN];

    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(iv, AES_IV_LEN))
        ssl_error("Secure random generation failed");

    derive_key(password, salt, key);
    auto plaintext = read_file(in_path);
    auto aad = make_aad(salt, iv);
    auto ciphertext = aes_gcm_encrypt(key, iv, aad, plaintext, tag);

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create output file: " + out_path);

    out.write(MAGIC.data(), static_cast<std::streamsize>(MAGIC.size()));
    out.write(reinterpret_cast<const char*>(salt), SALT_LEN);
    out.write(reinterpret_cast<const char*>(iv), AES_IV_LEN);
    out.write(reinterpret_cast<const char*>(tag), GCM_TAG_LEN);
    if (!ciphertext.empty())
        out.write(reinterpret_cast<const char*>(ciphertext.data()),
                  static_cast<std::streamsize>(ciphertext.size()));
    if (!out) throw std::runtime_error("Failed while writing encrypted output.");

    std::cout << "[OK] Authenticated AES-256-GCM encryption -> " << out_path << "\n";
}

// New-format decryption refuses legacy CBC files. Use decrypt-legacy explicitly
// only when recovering a trusted FENC1 file.
void decrypt_file(const std::string& in_path, const std::string& out_path)
{
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open encrypted file: " + in_path);

    char magic_buf[6] = {0};
    in.read(magic_buf, static_cast<std::streamsize>(MAGIC.size()));
    if (std::string(magic_buf, MAGIC.size()) == LEGACY_MAGIC)
        throw std::runtime_error("Legacy FENC1 file: use decrypt-legacy only for a trusted file.");
    if (!in || std::string(magic_buf, MAGIC.size()) != MAGIC)
        throw std::runtime_error("Not a valid FENC2 encrypted file (bad magic).");

    unsigned char salt[SALT_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];
    in.read(reinterpret_cast<char*>(salt), SALT_LEN);
    in.read(reinterpret_cast<char*>(iv), AES_IV_LEN);
    in.read(reinterpret_cast<char*>(tag), GCM_TAG_LEN);
    if (!in) throw std::runtime_error("Encrypted file header is truncated.");

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    std::string password = get_password("Enter decryption password: ");
    unsigned char key[AES_KEY_LEN];
    derive_key(password, salt, key);

    auto aad = make_aad(salt, iv);
    std::vector<unsigned char> plaintext;
    if (!aes_gcm_decrypt(key, iv, aad, ciphertext, tag, plaintext))
        throw std::runtime_error("Authentication failed: wrong password or file tampering detected.");

    write_file(out_path, plaintext);
    std::cout << "[OK] Authenticated file decrypted -> " << out_path << "\n";
}

// Explicit compatibility path for older FENC1 files. CBC plus an unkeyed
// SHA-256 field is not authenticated encryption and cannot reliably detect
// malicious tampering. Do not use this path for untrusted files.
void decrypt_legacy_file(const std::string& in_path, const std::string& out_path)
{
    std::cerr << "[WARNING] FENC1 is a legacy unauthenticated format. Only recover files you trust.\n";
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open legacy encrypted file: " + in_path);

    char magic_buf[6] = {0};
    in.read(magic_buf, static_cast<std::streamsize>(LEGACY_MAGIC.size()));
    if (!in || std::string(magic_buf, LEGACY_MAGIC.size()) != LEGACY_MAGIC)
        throw std::runtime_error("Not a valid FENC1 legacy file.");

    unsigned char salt[SALT_LEN];
    unsigned char stored_hash[SHA256_LEN];
    in.read(reinterpret_cast<char*>(salt), SALT_LEN);
    in.read(reinterpret_cast<char*>(stored_hash), SHA256_LEN);
    if (!in) throw std::runtime_error("Legacy encrypted file header is truncated.");

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (ciphertext.size() > static_cast<size_t>(INT_MAX))
        throw std::runtime_error("Legacy file is too large to decrypt.");

    std::string password = get_password("Enter legacy decryption password: ");
    unsigned char key_iv[AES_KEY_LEN + LEGACY_IV_LEN];
    unsigned char iv[LEGACY_IV_LEN];
    derive_key_iv(password, salt, key_iv, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) ssl_error("Could not allocate legacy decryption context");
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_iv, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        ssl_error("Legacy CBC initialization failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int out_len1 = 0, out_len2 = 0;
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(),
                           static_cast<int>(ciphertext.size())) ||
        !EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Legacy decryption failed: wrong password or corrupted file.");
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<size_t>(out_len1 + out_len2));

    unsigned char computed_hash[SHA256_LEN];
    SHA256(plaintext.data(), plaintext.size(), computed_hash);
    if (std::memcmp(stored_hash, computed_hash, SHA256_LEN) != 0)
        throw std::runtime_error("Legacy checksum mismatch.");

    write_file(out_path, plaintext);
    std::cout << "[OK] Legacy file recovered -> " << out_path << "\n";
}

void crypto_self_test()
{
    unsigned char key[AES_KEY_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];
    if (!RAND_bytes(key, AES_KEY_LEN) || !RAND_bytes(iv, AES_IV_LEN))
        ssl_error("Self-test random generation failed");

    const std::string message = "FENC2 authenticated encryption self-test";
    std::vector<unsigned char> plaintext(message.begin(), message.end());
    const std::vector<unsigned char> aad(MAGIC.begin(), MAGIC.end());
    auto ciphertext = aes_gcm_encrypt(key, iv, aad, plaintext, tag);

    std::vector<unsigned char> recovered;
    if (!aes_gcm_decrypt(key, iv, aad, ciphertext, tag, recovered) || recovered != plaintext)
        throw std::runtime_error("AES-GCM round-trip self-test failed.");

    auto tampered_ciphertext = ciphertext;
    if (!tampered_ciphertext.empty()) tampered_ciphertext[0] ^= 0x01;
    if (aes_gcm_decrypt(key, iv, aad, tampered_ciphertext, tag, recovered))
        throw std::runtime_error("AES-GCM ciphertext tamper test failed.");

    auto tampered_aad = aad;
    tampered_aad[0] ^= 0x01;
    if (aes_gcm_decrypt(key, iv, tampered_aad, ciphertext, tag, recovered))
        throw std::runtime_error("AES-GCM metadata tamper test failed.");

    unsigned char tampered_tag[GCM_TAG_LEN];
    std::memcpy(tampered_tag, tag, GCM_TAG_LEN);
    tampered_tag[0] ^= 0x01;
    if (aes_gcm_decrypt(key, iv, aad, ciphertext, tampered_tag, recovered))
        throw std::runtime_error("AES-GCM authentication-tag tamper test failed.");

    std::cout << "[OK] AES-256-GCM round-trip, ciphertext, metadata, and tag tests passed.\n";
}

// ─── SHA-256 Verify ───────────────────────────────────────────────────────────
void verify_file(const std::string& path)
{
    auto hash = sha256_file(path);
    std::cout << "SHA-256(" << path << ") = " << hex_string(hash) << "\n";
}

// ─── RSA Key Generation Helper (bonus utility) ────────────────────────────────
void generate_rsa_keypair(const std::string& priv_path,
                          const std::string& pub_path)
{
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    if (!rsa || !bn)
    {
        RSA_free(rsa);
        BN_free(bn);
        ssl_error("RSA key allocation failed");
    }
    if (!BN_set_word(bn, RSA_F4) ||
        !RSA_generate_key_ex(rsa, RSA_KEY_BITS, bn, nullptr))
    {
        RSA_free(rsa);
        BN_free(bn);
        ssl_error("RSA key generation failed");
    }

    // Create private key files with owner-only permissions from the start.
    int priv_fd = open(priv_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (priv_fd < 0)
    {
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Cannot create private key file: " + priv_path);
    }
    if (fchmod(priv_fd, S_IRUSR | S_IWUSR) != 0)
    {
        close(priv_fd);
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Cannot restrict private key file permissions: " + priv_path);
    }
    FILE* priv_fp = fdopen(priv_fd, "wb");
    if (!priv_fp)
    {
        close(priv_fd);
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Cannot open private key stream: " + priv_path);
    }
    const int private_ok = PEM_write_RSAPrivateKey(priv_fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    const int private_close_ok = fclose(priv_fp);
    if (!private_ok || private_close_ok != 0)
    {
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Failed to write private key file: " + priv_path);
    }

    int pub_fd = open(pub_path.c_str(), O_WRONLY | O_CREAT | O_EXCL,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (pub_fd < 0)
    {
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Cannot create public key file: " + pub_path);
    }
    FILE* pub_fp = fdopen(pub_fd, "wb");
    if (!pub_fp)
    {
        close(pub_fd);
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Cannot open public key stream: " + pub_path);
    }
    const int public_ok = PEM_write_RSA_PUBKEY(pub_fp, rsa);
    const int public_close_ok = fclose(pub_fp);
    RSA_free(rsa);
    BN_free(bn);
    if (!public_ok || public_close_ok != 0)
        throw std::runtime_error("Failed to write public key file: " + pub_path);

    std::cout << "[OK] RSA-" << RSA_KEY_BITS << " key pair generated\n"
              << "     Private: " << priv_path << " (owner-only permissions)\n"
              << "     Public : " << pub_path  << "\n";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    std::cout << "================================================\n"
              << "  File Encryption Tool  |  github: hemanathan115\n"
              << "  AES-256-GCM + PBKDF2 + RSA-2048 (OpenSSL)\n"
              << "================================================\n\n";

    if (argc < 3 && !(argc == 2 && std::string(argv[1]) == "self-test"))
    {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " encrypt <input>  <output>\n"
                  << "  " << argv[0] << " decrypt <input>  <output>\n"
                  << "  " << argv[0] << " decrypt-legacy <input> <output>\n"
                  << "  " << argv[0] << " self-test\n"
                  << "  " << argv[0] << " verify  <file>\n"
                  << "  " << argv[0] << " genrsa  <priv.pem> <pub.pem>\n";
        return 1;
    }

    std::string cmd = argv[1];

    try
    {
        if (cmd == "self-test" && argc == 2)
            crypto_self_test();

        else if (cmd == "encrypt" && argc == 4)
            encrypt_file(argv[2], argv[3]);

        else if (cmd == "decrypt" && argc == 4)
            decrypt_file(argv[2], argv[3]);

        else if (cmd == "decrypt-legacy" && argc == 4)
            decrypt_legacy_file(argv[2], argv[3]);

        else if (cmd == "verify" && argc == 3)
            verify_file(argv[2]);

        else if (cmd == "genrsa" && argc == 4)
            generate_rsa_keypair(argv[2], argv[3]);

        else
        {
            std::cerr << "Unknown command or wrong argument count.\n";
            return 1;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[FATAL] " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
