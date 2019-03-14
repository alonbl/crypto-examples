#include <exception>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "EncryptUtil.h"

static const auto SEPARATOR = '|';
static const auto SIGNATURE = "$ENC$";
static const auto VERSION = "0";

class openssl_error : public std::runtime_error {

private:
    static auto create_message(const std::string message) {

        struct BIOFreeAll { void operator() (BIO *p) { BIO_free_all(p); } };

        std::unique_ptr<BIO, BIOFreeAll> bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            throw openssl_error("create_message::BIO_new");
        }

        ERR_print_errors(bio.get());
        char *buf;
        auto len = BIO_get_mem_data(bio.get(), &buf);
        std::string err(buf, len);
        return message + ": " + err;
    }

public:
    openssl_error(const std::string message) : std::runtime_error(create_message(message)) {
    }

};

static auto split(const std::string &s, const char d) {
    std::stringstream ss(s);
    std::vector<std::string> ret;
    std::string item;

    while (getline(ss, item, d)) {
        ret.push_back(item);
    }

    return ret;
}

static auto generate_ciphers() {
    std::map<std::string, std::map<int, const EVP_CIPHER *>> ciphers;
    ciphers["AES/CBC/PKCS5Padding"][128 / 8] = EVP_aes_128_cbc();
    ciphers["AES/CBC/PKCS5Padding"][256 / 8] = EVP_aes_256_cbc();
    return ciphers;
}
static const auto CIPHERS = generate_ciphers();

static auto base64_decode(const std::string encoded)
{
    struct BIOFreeAll { void operator() (BIO *p) { BIO_free_all(p); } };

    std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    if (!b64) {
        throw openssl_error("base64_decode::BIO_new");
    }

    auto source = BIO_new_mem_buf(encoded.data(), encoded.size());
    if (!source) {
        throw openssl_error("base64_decode::BIO_new_mem_buf");
    }

    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64.get(), source);

    std::vector<unsigned char> decoded(encoded.size());
    decoded.resize(BIO_read(b64.get(), decoded.data(), decoded.size()));
    return decoded;
}

/**
 * Load error string information.
 *
 * An optional method that if called provide human readable messages.
 */
void EncryptUtil_process_init() {
    ERR_load_crypto_strings();
}

/**
 * Process termination and free resources.
 *
 * An optional method to free all reachable blocks, usable when valgrind is used.
 */
void EncryptUtil_process_terminate() {
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}

/**
 * Decrypt an envelope.
 * @param keys the keys dictionary keyid->base64(key).
 * @param envelope the envelope to decrypt.
 * @return the plaintext as a string.
 */
std::string EncryptUtil_decrypt(
    const std::map<std::string, std::string> &keys,
    const std::string &envelope
) {
    auto parts = split(envelope, SEPARATOR);
    auto i = 0;

    if (parts.size() == 0 || parts[i++] != SIGNATURE) {
        throw std::runtime_error("Expected signature not found");
    }
    if (parts.size() == 1) {
        throw std::runtime_error("Excepted version component not found");
    }
    if (parts[i] != VERSION) {
        throw std::runtime_error("Unsupported version '" + parts[i] + "'");
    }
    i++;
    if (parts.size() != 6) {
        throw std::runtime_error("Illegal format of version '" + std::string(VERSION) + "'");
    }

    auto cipher_name = parts[i++];
    auto keyid = parts[i++];
    auto iv = parts[i++];
    auto ciphered = parts[i++];

    auto keyidi = keys.find(keyid);
    if (keyidi == keys.end()) {
        throw std::runtime_error("Key id " + keyid  + " is not available");
    }

    auto iv_raw = base64_decode(iv);
    auto ciphered_raw = base64_decode(ciphered);
    auto key_raw = base64_decode(keyidi->second);

    auto ciphersi = CIPHERS.find(cipher_name);
    if (ciphersi == CIPHERS.end()) {
        throw std::runtime_error("Unsupported cipher '" + cipher_name + "'");
    }
    auto cipheri = ciphersi->second.find(key_raw.size());
    if (cipheri == ciphersi->second.end()) {
        throw std::runtime_error("Unsupported key size");
    }

    struct EVPCipherCtxFree { void operator() (EVP_CIPHER_CTX *p) { EVP_CIPHER_CTX_free(p); } };

    std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxFree> ctx(EVP_CIPHER_CTX_new());

    if (EVP_DecryptInit_ex(ctx.get(), cipheri->second, NULL, key_raw.data(), iv_raw.data()) != 1) {
        throw openssl_error("decrypt::EVP_DecryptInit_ex");
    }

    std::vector<unsigned char> ret(ciphered_raw.size());
    int retlen = 0;
    int len;

    if (EVP_DecryptUpdate(ctx.get(), &ret[retlen], &len, ciphered_raw.data(), ciphered_raw.size()) != 1) {
        throw openssl_error("decrypt::EVP_DecryptUpdate");
    }
    retlen += len;

    if (EVP_DecryptFinal_ex(ctx.get(), &ret[retlen], &len) != 1) {
        throw openssl_error("decrypt::EVP_DecryptFinal_ex");
    }
    retlen += len;
    ret.resize(retlen);

    return std::string((char *)ret.data() + ret[0], ret.size() - ret[0]);
}
