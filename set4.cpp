
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <cassert>
using std::string;
using std::cin;
using std::cout;
using std::endl;

int call_challenge25();
int call_challenge26();
int call_challenge27();
int call_challenge28();
int call_challenge29();
int call_challenge30();
int call_challenge31();
int call_challenge32();

int call_set4()
{
    int retcode = 0;
    std::cout << "This is Set 4\n";

    retcode = call_challenge25();

    return retcode;
}

static const char *chal25_key = "uSH%Ty4tNa5G8VIB";
static const uint64_t chal25_nonce = 0x9B505C5A18D520B7ULL;

static void chal25_edit_cyphertxt(uc8_t *cyphertxt, unsigned int offset, const uc8_t *newtxt)
{
    int ret = 0;

    uc8_t iv[AES_BLOCK_SIZE_BYTES];
    uc8_t local[AES_BLOCK_SIZE_BYTES * 2];
    int64_t counter = offset / AES_BLOCK_SIZE_BYTES;

    uc8_t* out = &cyphertxt[counter * AES_BLOCK_SIZE_BYTES];

    int used;
    int insz = strlen((char*)newtxt);

    memcpy(iv, &chal25_nonce, AES_BLOCK_SIZE_BYTES / 2);

    int xorsz = AES_BLOCK_SIZE_BYTES;
    int i = 0;
    while (i < insz)
    {
        memcpy(&iv[AES_BLOCK_SIZE_BYTES / 2], &counter, AES_BLOCK_SIZE_BYTES / 2);

        ret = aes_ecb_encrypt(iv, AES_BLOCK_SIZE_BYTES, (uc8_t*)chal25_key, local, &used);
        if (ret < 0)
            break;

        if (i + 16 > insz)
        {
            xorsz = insz - i;
        }

        xor_fixed(&newtxt[i], local, &out[i], xorsz);

        i += xorsz;
        counter++;
    }
}

static void chal26_prepare_cyphertxt(membuf *out)
{
    int used;
    membuf text = MEMBUF_INITIALISER;

    std::fstream xor_file;

    xor_file.open("challenge25a.txt", std::ios::in);

    if (xor_file.is_open()) {
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {
            size_t size = sa.length();

            membuf_adjust_size(&text, text.used + base64_dec_bufsz(size) + 1);
            text.used += base64tohex((uc8_t*)sa.c_str(), size, &text.data[text.used], base64_dec_bufsz(size));
        }

        // Close the file object.
        xor_file.close();
    }

    membuf_adjust_size(out, text.used);

    aes_ctr_xcrypt(text.data, text.used, (uc8_t*)chal25_key, chal25_nonce, out->data, &used);
    out->used = used;

    membuf_free(&text);
}

int call_challenge25()
{
    int used;
    membuf cyphertxt = MEMBUF_INITIALISER;
    chal26_prepare_cyphertxt(&cyphertxt);

    /**
    * x needs to be found
    * k is the keystream used to encrypt; hidden from us
    * i and j are the encrypted cyphertexts, we have access to them
    * a is the bit we control
    * 
    * x ^ k = i
    * a ^ k = j
    * i ^ j = x ^ k ^ k ^ a = x ^ a
    */

    membuf scratch = MEMBUF_INITIALISER;
    membuf_copy_auto(&scratch, &cyphertxt);

    uc8_t inbuf[AES_BLOCK_SIZE_BYTES + 1];
    memset(inbuf, 'a', sizeof(inbuf));
    inbuf[AES_BLOCK_SIZE_BYTES] = 0;
    uc8_t outbuf[AES_BLOCK_SIZE_BYTES + 1];
    outbuf[AES_BLOCK_SIZE_BYTES] = 0;

    int i = 0;
    int xorsz = AES_BLOCK_SIZE_BYTES;
    while (i < cyphertxt.used)
    {
        if (i + AES_BLOCK_SIZE_BYTES > cyphertxt.used)
        {
            xorsz = cyphertxt.used - i;
            inbuf[xorsz] = 0;
            outbuf[xorsz] = 0;
        }
        chal25_edit_cyphertxt(scratch.data, i, inbuf);
        //this gets us x ^ a
        xor_fixed(&cyphertxt.data[i], &scratch.data[i], outbuf, xorsz);
        //now xor with a and we have the plaintext
        xor_fixed(outbuf, inbuf, outbuf, xorsz);
        cout << outbuf;

        i += AES_BLOCK_SIZE_BYTES;
    }

    return 0;
}