
#include "aes_helper.h"
#include <memory.h>

#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/crypto.h"
#include "openssl/core_names.h"

int aes_ecb_encrypt(const uc8_t* in, size_t insz, const uc8_t* key, uc8_t* output, int* outlen)
{
    EVP_CIPHER_CTX* ctx;
    EVP_CIPHER* cipher = NULL;

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        return -2;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(NULL, "AES-128-ECB", NULL)) == NULL)
        return -2;

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, /* iv */ NULL, /* params */ NULL))
        return -2;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, output, outlen, in, insz))
        return -2;

#if 1
    int tmplen = 0;
    /* Finalise: there can be some additional output from padding */
    if (!EVP_EncryptFinal_ex(ctx, output + *outlen, &tmplen))
        return -2;
    *outlen += tmplen;
#endif

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int aes_ecb_decrypt(const uc8_t* in, size_t insz, const uc8_t* key, uc8_t* output, int* outlen)
{
    EVP_CIPHER_CTX* ctx;
    EVP_CIPHER* cipher = NULL;

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        return -2;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(NULL, "AES-128-ECB", NULL)) == NULL)
        return -2;

    /*
     * Initialise a decrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    if (!EVP_DecryptInit_ex2(ctx, cipher, key, /* iv */ NULL, /* params */ NULL))
        return -2;

    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, output, outlen, in, insz))
        return -2;

    int tmplen = 0;
    /* Finalise: there can be some additional output from padding */
    if (!EVP_DecryptFinal_ex(ctx, output + *outlen, &tmplen))
        return -2;
    *outlen += tmplen;

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int aes_cbc_encrypt(const uc8_t* in, size_t insz, const uc8_t* key, const uc8_t* iv, uc8_t* output, int* outlen)
{
    int ret = 0;

    uc8_t* newin = NULL;
    size_t newinsz = 0, used;
    data_buffer_adjust(&newin, &newinsz, insz + AES_BLOCK_SIZE_BYTES);
    memcpy(newin, in, insz);
    used = pad_data_buffer(&newin, &newinsz, insz, AES_BLOCK_SIZE_BYTES);

    uc8_t scratch[AES_BLOCK_SIZE_BYTES];
    uc8_t localout[AES_BLOCK_SIZE_BYTES * 2];

    const uc8_t* xorval = iv;
    uc8_t* scratch2 = scratch;

    int tmp = 0;

    int i = 0;
    while (i + AES_BLOCK_SIZE_BYTES <= used)
    {
        xor_fixed(&newin[i], xorval, scratch, AES_BLOCK_SIZE_BYTES);

        ret = aes_ecb_encrypt(scratch, AES_BLOCK_SIZE_BYTES, key, localout, &tmp);
        if (ret < 0)
            break;
        memcpy(&output[i], localout, AES_BLOCK_SIZE_BYTES);

        xorval = &output[i];

        i += AES_BLOCK_SIZE_BYTES;
    }

    free(newin);

    *outlen = i;
    return ret;
}

int aes_cbc_decrypt(const uc8_t* in, size_t insz, const uc8_t* key, const uc8_t* iv, uc8_t* output, int* outlen)
{
    int ret = 0;

    uc8_t scratchpad[AES_BLOCK_SIZE_BYTES * 2 * 2];
    uc8_t out1[AES_BLOCK_SIZE_BYTES];

    //prepare padding buffer to be fed to the decryter
    memset(output, AES_BLOCK_SIZE_BYTES, AES_BLOCK_SIZE_BYTES);

    int tmpsz = 0;

    //encrypt the padding buffer that is fed to the decrypter
    aes_ecb_encrypt((uc8_t*)output, AES_BLOCK_SIZE_BYTES, (uc8_t*)key, scratchpad, &tmpsz);
    //use 2 alternating scratchpads, since a block needs to be xored with the previously encrypted block
    //set the iv to value 0
    memcpy(&scratchpad[AES_BLOCK_SIZE_BYTES * 2], iv, AES_BLOCK_SIZE_BYTES);
    memcpy(&scratchpad[AES_BLOCK_SIZE_BYTES * 3], scratchpad, AES_BLOCK_SIZE_BYTES);

    uc8_t* scratch1 = scratchpad;
    uc8_t* scratch2 = &scratchpad[AES_BLOCK_SIZE_BYTES * 2];
    uc8_t* stmp;

    int i = 0;
    while (i + AES_BLOCK_SIZE_BYTES <= insz)
    {
        memcpy(scratch1, &in[i], AES_BLOCK_SIZE_BYTES);

        ret = aes_ecb_decrypt((uc8_t*)scratch1, AES_BLOCK_SIZE_BYTES * 2, (uc8_t*)key, (uc8_t*)out1, &tmpsz);
        if (ret < 0)
            break;

        xor_fixed((uc8_t*)out1, (uc8_t*)scratch2, (uc8_t*)&output[i], AES_BLOCK_SIZE_BYTES);

        i += AES_BLOCK_SIZE_BYTES;

        stmp = scratch1;
        scratch1 = scratch2;
        scratch2 = stmp;
    }

    //remove padding bytes
#if 0
    stmp = (uc8_t*)&output[i - 1];
    uc8_t tval = *stmp;
    while (tval == *stmp)
    {
        *stmp = 0;
        stmp--;
        i--;
    }

    *outlen = i;
#endif
    ret = unpad_data_buffer(output, i);
    *outlen = ret > 0 ? ret : i;

    return ret;
}
