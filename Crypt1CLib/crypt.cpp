#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

int pbkdf2_sha512(const char* password, const int password_len,
    const unsigned char* salt, const int salt_len,
	int iter, int key_len,
	unsigned char* output)
{
    return PKCS5_PBKDF2_HMAC(
        password, password_len,
        salt, salt_len,
        iter,
        EVP_sha512(),
        key_len, output);
}

int rand_bytes(unsigned char* buf, int num) {
    return RAND_bytes(buf, num);
}

int aes_encrypt(const unsigned char* data, int data_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char *cipher_data)
{
    EVP_CIPHER_CTX* ctx;
    int len, cipherdata_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, cipher_data, &len, data, data_len))
        return -1;

    cipherdata_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipher_data + len, &len))
        return -1;

    cipherdata_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipherdata_len;
}

int aes_decrypt(const unsigned char* cipher_data, int cipher_data_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char* data)
{
    EVP_CIPHER_CTX* ctx;
    int len, data_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, data, &len, cipher_data, cipher_data_len)) {
        return -1;
    }

    data_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, data + len, &len)) {
        return -1;
    }

    data_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return data_len;
}

int hmac_sha256(const unsigned char* key, int key_len,
    const unsigned char* data, int data_len,
    unsigned char* hash, unsigned int* hash_len)
{
    return (HMAC(EVP_sha256(), key, key_len, data, data_len, hash, hash_len) != NULL);
}
