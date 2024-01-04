#pragma once

#include "utils.h"

#define AES_BLOCK_SIZE_BYTES 16

inline int aes_encode_bufsz(int len)
{
	return ((len + AES_BLOCK_SIZE_BYTES) & ~(AES_BLOCK_SIZE_BYTES - 1));
}

int aes_ecb_encrypt(const uc8_t* in, size_t insz, const uc8_t* key, uc8_t* output, int* outlen);
int aes_ecb_decrypt(const uc8_t* in, size_t insz, const uc8_t* key, uc8_t* output, int* outlen);
int aes_cbc_encrypt(const uc8_t* in, size_t insz, const uc8_t* key, const uc8_t* iv, uc8_t* output, int* outlen);
int aes_cbc_decrypt(const uc8_t* in, size_t insz, const uc8_t* key, const uc8_t* iv, uc8_t* output, int* outlen);
