#pragma once

#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_encrypt(const unsigned char* data, int data_len,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* cipher_data);
int aes_decrypt(const unsigned char* cipher_data, int cipher_data_len,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* data);
int pbkdf2_sha512(const char* password, const int password_len,
	const unsigned char* salt, const int salt_len,
	int iter, int key_len,
	unsigned char* output);
int hmac_sha256(const unsigned char* key, int key_len,
	const unsigned char* data, int data_len,
	unsigned char* hash, unsigned int *hash_len);
int rand_bytes(unsigned char* buf, int num);
