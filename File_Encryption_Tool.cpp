/*
 * ============================================================
 *  File Encryption Tool
 *  Author  : hemanathan115
 *  Language: C++17
 *  Library : OpenSSL (AES-256-CBC, RSA-2048, SHA-256)
 * ============================================================
 *
 *  Compile:
 *    g++ -std=c++17 -O2 File_Encryption_Tool.cpp \
 *        -lssl -lcrypto -o file_enc
 *
 *  Usage:
 *    ./file_enc encrypt <input_file> <output_file>
 *    ./file_enc decrypt <input_file> <output_file>
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
#include <iomanip>
#include <sstream>
#include <stdexcept>

// ─── Constants ────────────────────────────────────────────────────────────────
constexpr int AES_KEY_LEN   = 32;   // AES-256
constexpr int AES_IV_LEN    = 16;
constexpr int SALT_LEN      = 16;
constexpr int SHA256_LEN    = 32;
constexpr int RSA_KEY_BITS  = 2048;

// Magic header written at the start of every encrypted file
const std::string MAGIC = "FENC1";

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
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::cout << prompt;
    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
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
                            100000,          // iterations
                            EVP_sha256(),
                            AES_KEY_LEN + AES_IV_LEN,
                            key))            // output buffer (key || iv)
    {
        ssl_error("PBKDF2 key derivation failed");
    }
    // Split: first AES_KEY_LEN bytes → key, next AES_IV_LEN bytes → iv
    std::memcpy(iv, key + AES_KEY_LEN, AES_IV_LEN);
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
    auto size = f.tellg();
    f.seekg(0);
    std::vector<unsigned char> data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// ─── Write vector to file ─────────────────────────────────────────────────────
void write_file(const std::string& path, const std::vector<unsigned char>& data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

// ─── AES-256-CBC Encrypt ──────────────────────────────────────────────────────
/*
 *  Output file layout:
 *  [ MAGIC (5 bytes) ][ SALT (16) ][ SHA256 of plaintext (32) ][ ciphertext ]
 */
void encrypt_file(const std::string& in_path, const std::string& out_path)
{
    std::string password = get_password("Enter encryption password: ");
    std::string confirm  = get_password("Confirm password         : ");
    if (password != confirm)
        throw std::runtime_error("Passwords do not match!");

    // Generate random salt
    unsigned char salt[SALT_LEN];
    if (!RAND_bytes(salt, SALT_LEN))
        ssl_error("RAND_bytes failed");

    // Derive key + IV
    unsigned char key_iv[AES_KEY_LEN + AES_IV_LEN];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(),
                            static_cast<int>(password.size()),
                            salt, SALT_LEN, 100000,
                            EVP_sha256(),
                            AES_KEY_LEN + AES_IV_LEN, key_iv))
        ssl_error("PBKDF2 failed");

    unsigned char* key = key_iv;
    unsigned char* iv  = key_iv + AES_KEY_LEN;

    // Read plaintext
    auto plaintext = read_file(in_path);

    // Compute SHA-256 integrity hash
    std::vector<unsigned char> hash(SHA256_LEN);
    SHA256(plaintext.data(), plaintext.size(), hash.data());

    // AES-256-CBC encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int out_len1 = 0, out_len2 = 0;

    EVP_EncryptUpdate(ctx,
                      ciphertext.data(), &out_len1,
                      plaintext.data(),  static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(static_cast<size_t>(out_len1 + out_len2));

    // Write output: MAGIC | SALT | HASH | CIPHERTEXT
    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create output file: " + out_path);

    out.write(MAGIC.c_str(),                             MAGIC.size());
    out.write(reinterpret_cast<char*>(salt),             SALT_LEN);
    out.write(reinterpret_cast<char*>(hash.data()),      SHA256_LEN);
    out.write(reinterpret_cast<char*>(ciphertext.data()),
              static_cast<std::streamsize>(ciphertext.size()));

    std::cout << "[OK] Encrypted -> " << out_path << "\n";
    std::cout << "     SHA-256 of original: " << hex_string(hash) << "\n";
}

// ─── AES-256-CBC Decrypt ──────────────────────────────────────────────────────
void decrypt_file(const std::string& in_path, const std::string& out_path)
{
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open encrypted file: " + in_path);

    // Read & verify magic
    char magic_buf[6] = {0};
    in.read(magic_buf, static_cast<std::streamsize>(MAGIC.size()));
    if (MAGIC != magic_buf)
        throw std::runtime_error("Not a valid encrypted file (bad magic)");

    // Read salt and stored hash
    unsigned char salt[SALT_LEN];
    unsigned char stored_hash[SHA256_LEN];
    in.read(reinterpret_cast<char*>(salt),        SALT_LEN);
    in.read(reinterpret_cast<char*>(stored_hash), SHA256_LEN);

    // Read ciphertext
    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(in)),
         std::istreambuf_iterator<char>());

    // Get password
    std::string password = get_password("Enter decryption password: ");

    // Derive key + IV
    unsigned char key_iv[AES_KEY_LEN + AES_IV_LEN];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(),
                            static_cast<int>(password.size()),
                            salt, SALT_LEN, 100000,
                            EVP_sha256(),
                            AES_KEY_LEN + AES_IV_LEN, key_iv))
        ssl_error("PBKDF2 failed");

    unsigned char* key = key_iv;
    unsigned char* iv  = key_iv + AES_KEY_LEN;

    // AES-256-CBC decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    std::vector<unsigned char> plaintext(ciphertext.size());
    int out_len1 = 0, out_len2 = 0;

    if (!EVP_DecryptUpdate(ctx,
                           plaintext.data(), &out_len1,
                           ciphertext.data(),
                           static_cast<int>(ciphertext.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed – wrong password?");
    }
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption final failed – wrong password or corrupted file");
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<size_t>(out_len1 + out_len2));

    // Integrity check: compare SHA-256
    unsigned char computed_hash[SHA256_LEN];
    SHA256(plaintext.data(), plaintext.size(), computed_hash);

    if (std::memcmp(stored_hash, computed_hash, SHA256_LEN) != 0)
        throw std::runtime_error("Integrity check FAILED! File may be corrupted or tampered.");

    write_file(out_path, plaintext);
    std::cout << "[OK] Decrypted -> " << out_path << "\n";
    std::cout << "     Integrity check: PASSED\n";
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
    RSA*    rsa  = RSA_new();
    BIGNUM* bn   = BN_new();
    BN_set_word(bn, RSA_F4);

    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, bn, nullptr))
        ssl_error("RSA key generation failed");

    // Write private key
    FILE* fp = fopen(priv_path.c_str(), "wb");
    PEM_write_RSAPrivateKey(fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);

    // Write public key
    fp = fopen(pub_path.c_str(), "wb");
    PEM_write_RSA_PUBKEY(fp, rsa);
    fclose(fp);

    RSA_free(rsa);
    BN_free(bn);

    std::cout << "[OK] RSA-" << RSA_KEY_BITS << " key pair generated\n"
              << "     Private: " << priv_path << "\n"
              << "     Public : " << pub_path  << "\n";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    std::cout << "================================================\n"
              << "  File Encryption Tool  |  github: hemanathan115\n"
              << "  AES-256-CBC + SHA-256 + RSA-2048 (OpenSSL)\n"
              << "================================================\n\n";

    if (argc < 3)
    {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " encrypt <input>  <output>\n"
                  << "  " << argv[0] << " decrypt <input>  <output>\n"
                  << "  " << argv[0] << " verify  <file>\n"
                  << "  " << argv[0] << " genrsa  <priv.pem> <pub.pem>\n";
        return 1;
    }

    std::string cmd = argv[1];

    try
    {
        if (cmd == "encrypt" && argc == 4)
            encrypt_file(argv[2], argv[3]);

        else if (cmd == "decrypt" && argc == 4)
            decrypt_file(argv[2], argv[3]);

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
