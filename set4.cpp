
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <cassert>
#include "tcpcom.h"

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

    retcode = call_challenge32();

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

static void chal25_prepare_cyphertxt(membuf* out)
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
    chal25_prepare_cyphertxt(&cyphertxt);

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

static const char* chal26_key = "j3Q1m#4kti%oF%oW";
static const uint64_t chal26_nonce = 0xCCD9DE65D9F9E3BCULL;

static int chal26_prepare(const char* input, membuf *output)
{
    const char* prefix = "comment1=cooking%20MCs;userdata=";
    const char* suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    int newsz = strlen(input) + strlen(prefix) + strlen(suffix);

    uc8_t* newin = NULL;
    size_t newinsz = 0;

    data_buffer_adjust(&newin, &newinsz, newsz + 1);

    strcpy((char*)newin, prefix);
    //remove ; and = from input text
    uc8_t* dest = newin + strlen(prefix);
    while (*input)
    {
        if (*input == ';' || *input == '=')
        {
            *dest = '_';
        }
        else
        {
            *dest = *input;
        }
        dest++;
        input++;
    }
    strcpy((char*)dest, suffix);

    int outbytes = newsz + sizeof(uint64_t);

    membuf_adjust_size(output, outbytes);
    memcpy(output->data, &chal26_nonce, sizeof(uint64_t));
    output->used = sizeof(uint64_t);

    int used;
    aes_ctr_xcrypt(newin, newsz, (uc8_t*)chal26_key, chal26_nonce, output->data + sizeof(uint64_t), &used);
    output->used += used;

    free(newin);

    return output->used;
}

static int chal26_show(const char* input, int inputsz)
{
    char* out = NULL;
    size_t outsz = 0;

    data_buffer_adjust((uc8_t**)&out, &outsz, inputsz + 1);
    memset(out, 0, outsz);

    int used = 0;
    uint64_t nonce = 0;
    memcpy(&nonce, input, sizeof(nonce));
    aes_ctr_xcrypt((uc8_t*)input + sizeof(nonce), inputsz - sizeof(nonce), (uc8_t*)chal26_key, nonce, (uc8_t*)out, &used);

    cout << out << endl;

    int found = !! strstr(out, "admin=true");

    free(out);

    return found;
}

int call_challenge26()
{
    uc8_t prep[] = "hello ctr;admin=true";
    int sz = strlen((char*)prep) + 1;
    uc8_t* mod = (uc8_t*)malloc(sz);
    if (!mod) exit(-1);
    memset(mod, 0, sz);

    int i = 0;
    uc8_t* iter = prep;
    while (*iter)
    {
        if (*iter == ';' || *iter == '=')
        {
            *iter ^= 0x10;
            mod[i] = 0x10;
        }
        iter++;
        i++;
    }

    membuf cyphertxt = MEMBUF_INITIALISER;
    membuf scratch = MEMBUF_INITIALISER;

    int used = chal26_prepare((char*)prep, &cyphertxt);

    i = 0;
    while (i + sz <= used)
    {
        membuf_copy_auto(&scratch, &cyphertxt);
        xor_fixed(cyphertxt.data + i, mod, scratch.data + i, sz);

        if (chal26_show((char*)scratch.data, used))
            break;

        i++;
    }

    return 0;
}

static const char* chal27_key = "vq9%FC5LYfdM8aU#";

static int chal27_prepare(membuf* output)
{
    const char* url = "comment1=cooking%20MCs;userdata=aabb;comment2=%20like%20a%20pound%20of%20bacon";

    int sz = strlen(url);

    membuf_adjust_size(output, aes_encode_bufsz(sz));

    int used;
    aes_cbc_encrypt((uc8_t*)url, sz, (uc8_t*)chal27_key, (uc8_t*)chal27_key, output->data, &used);
    output->used += used;

    return output->used;
}

static int chal27_check(const membuf* input, membuf* msg)
{
    uc8_t* out = NULL;
    size_t outsz = 0;

    data_buffer_adjust(&out, &outsz, input->used + 1);
    memset(out, 0, outsz);

    int used = 0;
    aes_cbc_decrypt((uc8_t*)input->data, input->used, (uc8_t*)chal27_key, (uc8_t*)chal27_key, out, &used);

    int decode_err = 0;
    int i;
    for (i = 0; i < used; i++)
    {
        if (out[i] > 0xF)
        {
            decode_err = 1;
            break;
        }
    }

    const char* msg_ok = "receipt success";
    const char* msg_nok = "error decoding message: ";

    if (decode_err)
    {
        membuf_append_data_auto(msg, (uc8_t*)msg_nok, strlen(msg_nok));
        membuf_append_data_auto(msg, out, used);
        membuf_append_byte_auto(msg, 0);
    }
    else
    {
        membuf_append_data_auto(msg, (uc8_t*)msg_ok, strlen(msg_ok) + 1);
    }

    free(out);

    return used;
}

int call_challenge27()
{
    membuf cyphertxt = MEMBUF_INITIALISER;
    membuf scratch = MEMBUF_INITIALISER;
    membuf result = MEMBUF_INITIALISER;

    uc8_t key[AES_BLOCK_SIZE_BYTES + 1];
    memset(key, 0, sizeof key);

    chal27_prepare(&cyphertxt);
    membuf_copy_auto(&scratch, &cyphertxt);

    //mangle cyphertext
    memset(scratch.data + AES_BLOCK_SIZE_BYTES, 0, AES_BLOCK_SIZE_BYTES);
    uc8_t* src = scratch.data;
    uc8_t* dst = scratch.data + 2 * AES_BLOCK_SIZE_BYTES;
    int i = AES_BLOCK_SIZE_BYTES;
    while (i > 0)
    {
        *dst = *src;
        dst++;
        src++;
        i--;
    }
    

    chal27_check(&scratch, &result);
    if (strstr((char*)result.data, "error"))
    {
        cout << "we produced a decode error" << endl;
        cout << result.data << endl;

        const char* srchtxt = "error decoding message: ";
        uc8_t* decxkey = (uc8_t*)strstr((char*)result.data, srchtxt);
        decxkey += strlen(srchtxt);
        uc8_t* dec = decxkey + 2 * AES_BLOCK_SIZE_BYTES;

        xor_fixed(decxkey, dec, key, AES_BLOCK_SIZE_BYTES);
        cout << "Decoded key: " << key << endl;
        cout << (0 == strcmp((char*)key, chal27_key) ? "Gotcha" : "Damn") << endl;
    }
    else
    {
        cout << "no problem detected by server" << endl;
    }

    return 0;
}

static const char* chal28_key = "uF!7ycFYcWZtkAJe";

static int chal28_get_message(uc8_t* message, size_t msgsz, membuf* out)
{
    membuf local = MEMBUF_INITIALISER;

    int size = msgsz + strlen(chal28_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal28_key, strlen(chal28_key));
    membuf_append_data_auto(&local, (uc8_t*)message, msgsz);

    membuf_adjust_size(out, msgsz + SHA1_DIGEST_SZ);
    SHA1((char*)out->data, (char*)local.data, local.used);
    out->used += SHA1_DIGEST_SZ;
    membuf_append_data_auto(out, message, msgsz);

    membuf_free(&local);

    return 0;
}

static int chal28_verify_message(membuf *msg)
{
    int ret = 0;
    membuf local = MEMBUF_INITIALISER;

    int size = msg->used - SHA1_DIGEST_SZ + strlen(chal28_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal28_key, strlen(chal28_key));
    membuf_append_data_auto(&local, (uc8_t*)msg->data + SHA1_DIGEST_SZ, msg->used - SHA1_DIGEST_SZ);

    uc8_t digest[SHA1_DIGEST_SZ];
    SHA1((char*)digest, (char*)local.data, local.used);

    int count = 0;
    for (int i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        if (digest[i] == msg->data[i])
            count++;
    }
    if (count == SHA1_DIGEST_SZ)
    {
        ret = 1;
    }
    else
    {
        ret = -count;
    }

    membuf_free(&local);

    return ret;
}

static void print_progress(int val, int limit)
{
    static int store = 0;
    if (limit == 0)
    {
        store = 0;
        return;
    }
    int percent = val * 10 / limit;
    if (percent > store)
    {
        store = percent;
        cout << percent << " ";
    }
}

int call_challenge28()
{
    membuf msg_valid = MEMBUF_INITIALISER;

    const char* message = "Hello Alice! This is an untampered message.";
    chal28_get_message((uc8_t*)message, strlen(message), &msg_valid);

    membuf msg_tamper = MEMBUF_INITIALISER;
    membuf_copy_auto(&msg_tamper, &msg_valid);
    if (!chal28_verify_message(&msg_tamper))
    {
        cout << "Failed to validate original msg!" << endl;
        return -2;
    }

    membuf_adjust_size(&msg_tamper, msg_tamper.size + 4);
    membuf_append_data_auto(&msg_tamper, (uc8_t*)"\x0\x0\x0\x0", 4);

    char *tmp = strstr((char*)msg_tamper.data + 20, "Alice");
    if (!tmp) return -2;
    memcpy(tmp, "Bobby", 5);
    tmp = strchr((char*)msg_tamper.data + 20, '.');
    if (!tmp) return -2;
    tmp++;

    int found = 0;
    int i, j, k;

    //goto try2;

    for (i = 0; i <= 0xff && found != 1; i++)
    {
        tmp[0] = i;
        for (j = 0; j <= 0xff && found != 1; j++)
        {
            tmp[1] = j;
            for (k = 0; k <= 0xff && found != 1; k++)
            {
                tmp[2] = k;
                int ercd = chal28_verify_message(&msg_tamper);
                if (ercd < found) found = ercd;
                if (ercd > 0)
                {
                    found = 1;
                    cout << endl << "Tampered! " << msg_tamper.data + 20 << endl;
                }
            }
        }
        print_progress(i, 0xff);
    }
    cout << "ercd: " << found << endl;

    //modifying just 3 bytes of the digest is obviously not enough, i'm just curious how much time it takes
    print_progress(0, 0);
    found = 0;
    membuf_copy_auto(&msg_tamper, &msg_valid);
    tmp = strstr((char*)msg_tamper.data + 20, "Alice");
    if (!tmp) return -2;
    memcpy(tmp, "Bobby", 5);
    tmp = (char*)msg_tamper.data;
    for (i = 0; i <= 0xff && found != 1; i++)
    {
        tmp[0] = i;
        for (j = 0; j <= 0xff && found != 1; j++)
        {
            tmp[1] = j;
            for (k = 0; k <= 0xff && found != 1; k++)
            {
                tmp[2] = k;
                int ercd = chal28_verify_message(&msg_tamper);
                if (ercd < found) found = ercd;
                if (ercd > 0)
                {
                    found = 1;
                    cout << endl << "Tampered! " << msg_tamper.data + 20 << endl;
                }
            }
        }
        print_progress(i, 0xff);
    }
    cout << "ercd: " << found << endl;

    return 0;
}

static char chal29_key[20];
const char *chal29_url = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
const char* chal29_admin = ";admin=true";


static int chal29_prepare_message(membuf* out)
{
    membuf local = MEMBUF_INITIALISER;

    memset(chal29_key, 0, sizeof(chal29_key));
    random_init();
    random_text((uc8_t*)chal29_key, rand() % 19 + 1);

    int size = strlen(chal29_url) + strlen(chal29_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal29_key, strlen(chal29_key));
    membuf_append_data_auto(&local, (uc8_t*)chal29_url, strlen(chal29_url));

    membuf_clear(out);
    membuf_adjust_size(out, strlen(chal29_url) + SHA1_DIGEST_SZ);
    SHA1((char*)out->data, (char*)local.data, local.used);
    out->used += SHA1_DIGEST_SZ;
    membuf_append_data_auto(out, (uc8_t*)chal29_url, strlen(chal29_url));

    membuf_free(&local);

    return 0;
}

static int chal29_verify_message(membuf* msg)
{
    int ret = 0;
    membuf local = MEMBUF_INITIALISER;

    int size = msg->used - SHA1_DIGEST_SZ + strlen(chal29_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal29_key, strlen(chal29_key));
    membuf_append_data_auto(&local, (uc8_t*)msg->data + SHA1_DIGEST_SZ, msg->used - SHA1_DIGEST_SZ);

    uc8_t digest[SHA1_DIGEST_SZ];
    SHA1((char*)digest, (char*)local.data, local.used);

    membuf_free(&local);

    int count = 0;
    for (int i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        if (digest[i] == msg->data[i])
            count++;
    }
    if (count == SHA1_DIGEST_SZ)
    {
        ret = 1;
    }
    else
    {
        ret = -count;
    }

    return ret;
}

static uint64_t chal29_addpad(membuf* msg, uint32_t len)
{
    int addsz = ((len + 8) / 64 + 1) * 64;
    addsz -= len;
    membuf_adjust_size(msg, msg->used + addsz);

    uint64_t databits = ((uint64_t)len * 8);

    memset(msg->data + msg->used, 0, addsz);
    msg->data[msg->used] = 0x80;
    msg->data[msg->used + addsz - 8] = (databits >> 56 & 0xFF);
    msg->data[msg->used + addsz - 7] = (databits >> 48 & 0xFF);
    msg->data[msg->used + addsz - 6] = (databits >> 40 & 0xFF);
    msg->data[msg->used + addsz - 5] = (databits >> 32 & 0xFF);
    msg->data[msg->used + addsz - 4] = (databits >> 24 & 0xFF);
    msg->data[msg->used + addsz - 3] = (databits >> 16 & 0xFF);
    msg->data[msg->used + addsz - 2] = (databits >> 8 & 0xFF);
    msg->data[msg->used + addsz - 1] = (databits >> 0 & 0xFF);
    msg->used += addsz;

    return ((uint64_t)len + addsz) * 8;
}

int call_challenge29()
{
    membuf working = MEMBUF_INITIALISER;
    membuf store = MEMBUF_INITIALISER;
    chal29_prepare_message(&store);
    membuf_copy_auto(&working, &store);
    if (0 < chal29_verify_message(&working))
    {
        cout << "check\n";
    }

    for (int i = 1; i < 20; i++)
    {
        membuf_copy(&working, &store);
        uint64_t count = chal29_addpad(&working, strlen(chal29_url) + i);
        SHA1_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        uc8_t* digest = working.data;
        for (int i = 0; i < 5; i++)
        {
            ctx.state[i] = (digest[0] << 24) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
            digest += 4;
        }
        ctx.count[1] = count >> 32;
        ctx.count[0] = count & 0xFFFFFFFF;
#if 1
        int offset = working.used;
        membuf_append_data_auto(&working, (uc8_t*)chal29_admin, strlen(chal29_admin));

        uc8_t* tmp = working.data + offset;
        int len = strlen(chal29_admin);
        for (int ii = 0; ii < len; ii += 1)
            SHA1Update(&ctx, (const unsigned char*)tmp + ii, 1);
        SHA1Final((unsigned char*)working.data, &ctx);
#endif
        if (0 < chal29_verify_message(&working))
        {
            cout << "found passlen: " << i << " vs " << strlen(chal29_key) << endl;
            for (int i = SHA1_DIGEST_SZ; i < working.used; i++)
            {
                if (working.data[i] == 0)
                    working.data[i] = ' ';
            }
            membuf_append_byte_auto(&working, 0);
            cout << working.data + SHA1_DIGEST_SZ << endl;
        }
    }
    return 0;
}

static int chal30_prepare_message(membuf* out)
{
    membuf local = MEMBUF_INITIALISER;

    memset(chal29_key, 0, sizeof(chal29_key));
    random_init();
    random_text((uc8_t*)chal29_key, rand() % 19 + 1);

    int size = strlen(chal29_url) + strlen(chal29_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal29_key, strlen(chal29_key));
    membuf_append_data_auto(&local, (uc8_t*)chal29_url, strlen(chal29_url));

    membuf_clear(out);
    membuf_adjust_size(out, strlen(chal29_url) + MD4_DIGEST_SZ);
    MD4((char*)out->data, (char*)local.data, local.used);
    out->used += MD4_DIGEST_SZ;
    membuf_append_data_auto(out, (uc8_t*)chal29_url, strlen(chal29_url));

    membuf_free(&local);

    return 0;
}

static int chal30_verify_message(membuf* msg)
{
    int ret = 0;
    membuf local = MEMBUF_INITIALISER;

    int size = msg->used - MD4_DIGEST_SZ + strlen(chal29_key);

    membuf_adjust_size(&local, size);
    membuf_append_data_auto(&local, (uc8_t*)chal29_key, strlen(chal29_key));
    membuf_append_data_auto(&local, (uc8_t*)msg->data + MD4_DIGEST_SZ, msg->used - MD4_DIGEST_SZ);

    uc8_t digest[MD4_DIGEST_SZ];
    MD4((char*)digest, (char*)local.data, local.used);

    membuf_free(&local);

    int count = 0;
    for (int i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        if (digest[i] == msg->data[i])
            count++;
    }
    if (count == MD4_DIGEST_SZ)
    {
        ret = 1;
    }
    else
    {
        ret = -count;
    }

    return ret;
}

static uint64_t chal30_addpad(membuf* msg, uint32_t len)
{
    int addsz = ((len + 8) / 64 + 1) * 64;
    addsz -= len;
    membuf_adjust_size(msg, msg->used + addsz);

    uint64_t databits = ((uint64_t)len * 8);

    memset(msg->data + msg->used, 0, addsz);
    msg->data[msg->used] = 0x80;
    msg->data[msg->used + addsz - 8] = (databits >> 0 & 0xFF);
    msg->data[msg->used + addsz - 7] = (databits >> 8 & 0xFF);
    msg->data[msg->used + addsz - 6] = (databits >> 16 & 0xFF);
    msg->data[msg->used + addsz - 5] = (databits >> 24 & 0xFF);
    msg->data[msg->used + addsz - 4] = (databits >> 32 & 0xFF);
    msg->data[msg->used + addsz - 3] = (databits >> 40 & 0xFF);
    msg->data[msg->used + addsz - 2] = (databits >> 48 & 0xFF);
    msg->data[msg->used + addsz - 1] = (databits >> 56 & 0xFF);
    msg->used += addsz;

    return ((uint64_t)len + addsz) * 8;
}

int call_challenge30()
{
    membuf working = MEMBUF_INITIALISER;
    membuf store = MEMBUF_INITIALISER;
    chal30_prepare_message(&store);
    membuf_copy_auto(&working, &store);
    if (0 < chal30_verify_message(&working))
    {
        cout << "check\n";
    }

    for (int i = 1; i < 20; i++)
    {
        membuf_copy(&working, &store);
        uint64_t count = chal30_addpad(&working, strlen(chal29_url) + i);
        MD4_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        uc8_t* digest = working.data;
        ctx.a = (digest[3] << 24) + (digest[2] << 16) + (digest[1] << 8) + digest[0];
        digest += 4;
        ctx.b = (digest[3] << 24) + (digest[2] << 16) + (digest[1] << 8) + digest[0];
        digest += 4;
        ctx.c = (digest[3] << 24) + (digest[2] << 16) + (digest[1] << 8) + digest[0];
        digest += 4;
        ctx.d = (digest[3] << 24) + (digest[2] << 16) + (digest[1] << 8) + digest[0];
        digest += 4;
        ctx.hi = count >> 32;
        ctx.lo = count & 0xFFFFFFFF;
        ctx.lo >>= 3;
#if 1
        int offset = working.used;
        membuf_append_data_auto(&working, (uc8_t*)chal29_admin, strlen(chal29_admin));

        uc8_t* tmp = working.data + offset;
        int len = strlen(chal29_admin);
        for (int ii = 0; ii < len; ii += 1)
            MD4_Update(&ctx, (const unsigned char*)tmp + ii, 1);
        MD4_Final((unsigned char*)working.data, &ctx);
#endif
        if (0 < chal30_verify_message(&working))
        {
            cout << "found passlen: " << i << " vs " << strlen(chal29_key) << endl;
            membuf_append_byte_auto(&working, 0);
            make_printable(working.data, working.used - 1);
            cout << working.data + MD4_DIGEST_SZ << endl;
        }
    }
    return 0;
}

static int hmac_sha1(uc8_t *message, int msglen, uc8_t *key, int keylen, membuf *out)
{
    const uc8_t ipad_byte = 0x36;
    const uc8_t opad_byte = 0x5c;
    const int block_size = 64;

    membuf local = MEMBUF_INITIALISER;
    membuf_adjust_size(&local, block_size + max(msglen, SHA1_DIGEST_SZ));

    uc8_t *scratch = local.data;
    for (int i = 0; i < block_size; i++)
    {
        uc8_t val = (i < keylen) ? key[i] : 0;
        scratch[i] = val ^ ipad_byte;
    }
    local.used = block_size;
    membuf_append_data_auto(&local, message, msglen);

    membuf_adjust_size(out, SHA1_DIGEST_SZ + msglen);
    SHA1((char*)out->data, (char*)local.data, local.used);
    scratch = local.data;
    for (int i = 0; i < block_size; i++)
    {
        uc8_t val = (i < keylen) ? key[i] : 0;
        scratch[i] = val ^ opad_byte;
    }
    local.used = block_size;
    membuf_append_data_auto(&local, out->data, SHA1_DIGEST_SZ);

    membuf_adjust_size(out, SHA1_DIGEST_SZ + msglen);
    SHA1((char*)out->data, (char*)local.data, block_size + SHA1_DIGEST_SZ);
    out->used = SHA1_DIGEST_SZ;
    membuf_append_data_auto(out, message, msglen);

    membuf_free(&local);

    return 0;
}

  /**
    * NOTE: wbpy server commands
    * $> python -m venv .\webpy\venv           #creates the python virtual environment in webpy subfolder
    * $> .\webpy\venv\Scripts\activate.bat     #enters the virtual environment
    * $> python -m pip install web.py          #installs the webpy framework
    * $> python app.py                         #starts the webserver application
    */

int call_challenge31()
{
    membuf out = MEMBUF_INITIALISER;
    uc8_t key[20] = "hurray-for-fingers";
    //memset(key, 0, sizeof key);
    //random_init();
    //random_text(key, rand() % 19 + 1);

    const char *msg = "foo";
    hmac_sha1((uc8_t*)msg, strlen(msg), key, strlen((char*)key), &out);

    char local[SHA1_DIGEST_SZ * 2 + 1];
    memset(local, 0, sizeof local);
    bytes_to_hexstring(out.data, SHA1_DIGEST_SZ, (uc8_t*)local, SHA1_DIGEST_SZ * 2);

    cout << local << endl;
    membuf_free(&out);

    char guess[SHA1_DIGEST_SZ];

    membuf url = MEMBUF_INITIALISER;
    membuf_adjust_size(&url, 2048);
    membuf httpget = MEMBUF_INITIALISER;
    membuf_adjust_size(&httpget, 2048);

    memset(local, 0, sizeof local);

    const char* address = "localhost";
    const char* port = "8080";

    void* tcpcom_ctx = NULL;
    tcpcom_init(&tcpcom_ctx, address, port);

    float avg = 140.0;
    int samples = 9;
    int max_confirmations = 5;

    for (int i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        int found = 0;
        int confirm = 0;
        for (int j = 0; j <= 0xFF && !found; j++)
        {
            guess[i] = j;
            bytes_to_hexstring((uc8_t*)guess, i+1, (uc8_t*)local, SHA1_DIGEST_SZ * 2);
            int used = snprintf((char*)url.data, url.size, "test?file=%s&signature=", msg);
            url.used = used;
            membuf_append_data_auto(&url, (uc8_t*)local, (i + 1) * 2);
            membuf_append_byte_auto(&url, 0);
            used = snprintf((char*)httpget.data, httpget.size, tcpcom_httpget, url.data, address, port);
            httpget.used = used;

            confirm:
            uint32_t timespent = 0;
            tcpcom_request(&tcpcom_ctx, (char*)httpget.data, httpget.used, &timespent);

            if (((float)timespent - avg) > 30)
            {
                cout << "+time: " << timespent << " avg: " << avg << " val: " << j << endl;
                confirm++;
                if (confirm < max_confirmations) goto confirm;
                //found
                found = 1;
                avg = timespent;
                cout << "----- " << std::hex << j << std::dec << endl;
            }
            else
            {
                //cout << "-time: " << timespent << " avg: " << avg << " val: " << j << endl;
                confirm = 0;
                avg = (avg * samples + timespent) / (samples + 1);
            }
        }
    }

    tcpcom_close(&tcpcom_ctx);

    return 0;
}


const char* chal32_address = "localhost";
const char* chal32_port = "8080";
const char* chal32_msg = "foo";
const char* chal32_key = "yellow submarine";


char chal32_scratch[SHA1_DIGEST_SZ * 2 + 1];
membuf chal32_url = MEMBUF_INITIALISER;
membuf chal32_httpget = MEMBUF_INITIALISER;
float chal32_base_avg = 0.0;

static int chal32_extract_high_value(uint32_t times[0x100], int clear)
{
    uint32_t highest = 0;
    int idx = -1;
    for (int i = 0; i < 0x100; i++)
    {
        if (times[i] > highest)
        {
            highest = times[i];
            idx = i;
        }
    }

    if (idx >= 0 && clear)
    {
        times[idx] = 0;
    }
    return idx;
}

static float chal32_calc_average(uint32_t times[0x100])
{
    float ret = 0.0;
    int totals = 0;

    for (int i = 0; i < 0x100; i++)
    {
        uint32_t val = times[i];
        if (val)
        {
            ret += times[i];
            totals++;
        }
    }

    return ret / totals;
}

static float chal32_calc_standard_deviation(uint32_t times[0x100], float avg)
{
    float ret = 0.0;
    int totals = 0;

    for (int i = 0; i < 0x100; i++)
    {
        uint32_t val = times[i];
        if (val)
        {
            float dev = (float)times[i] - avg;
            ret += dev * dev;
            totals++;
        }
    }

    ret /= totals;

    return sqrtf(ret);
}

static int chal32_should_abort(int pos, float averages[SHA1_DIGEST_SZ])
{
    int streak_limit = 3;
    int streak = 0;
    int negative = 0;
    int i = pos;
    while(i > 0)
    {
        float now = averages[i];
        float prev = i > 0 ? averages[i - 1] : chal32_base_avg;
        float dif = now - prev;
        if (dif < -5.0)
        {
            negative = 1;
            break;
        }
        if (dif < 5.0)
        {
            streak++;
        }
        else
        {
            streak = 0;
        }
        if (streak >= streak_limit)
        {
            break;
        }
        i--;
    }

#if 1
    return (negative != 0) || (streak >= streak_limit);
#else
    return 1;
#endif
}

//adds a new byte to the buffer, sends it to the server and records the time taken for the roundtrip
static uint32_t chal32_test_value(int pos, int val, uc8_t buf[SHA1_DIGEST_SZ], void** ctx)
{
    if (pos < SHA1_DIGEST_SZ)
    {
        buf[pos] = val;
        pos++;
        int i = pos; while (i < SHA1_DIGEST_SZ) { buf[i] = 0; i++; }
    }
    int used = snprintf((char*)chal32_url.data, chal32_url.size, "test?file=%s&signature=", chal32_msg);
    chal32_url.used = used;

    bytes_to_hexstring((uc8_t*)buf, SHA1_DIGEST_SZ, (uc8_t*)chal32_scratch, SHA1_DIGEST_SZ * 2);
    membuf_append_data_auto(&chal32_url, (uc8_t*)chal32_scratch, SHA1_DIGEST_SZ * 2);
    membuf_append_byte_auto(&chal32_url, 0);

    //prepare the http GET request
    used = snprintf((char*)chal32_httpget.data, chal32_httpget.size, tcpcom_httpget, chal32_url.data, chal32_address, chal32_port);
    chal32_httpget.used = used;

    uint32_t timespent;
    //use a retry mechanism in case the send fails
    int attempts = 2;
    while (attempts > 0)
    {
        timespent = 0;
        int ercd = tcpcom_request(ctx, (char*)chal32_httpget.data, chal32_httpget.used, &timespent);
        if (ercd >= 0) break;
        if (ercd < 0 && attempts)
        {
            attempts--;
            tcpcom_close(ctx);
            tcpcom_init(ctx, chal32_address, chal32_port);
        }
    }


    return timespent;
}

float chal32_explore_guess(int pos, int val, uc8_t guess[SHA1_DIGEST_SZ], float averages[SHA1_DIGEST_SZ], void** ctx)
{
    if (pos >= SHA1_DIGEST_SZ)
    {   //we always explore pos+1, therefore this is the end
        return -100.0;
    }
    if (pos >= 0)
    {
        guess[pos] = val;

        chal32_scratch[(pos+1) * 2] = 0;
        bytes_to_hexstring(guess, pos+1, (uc8_t*)chal32_scratch, SHA1_DIGEST_SZ * 2);
        cout << "explore: " << chal32_scratch << endl;
    }
    else
    {   //on first call there is no hint which byte to explore, so 'val' is ignored
        pos = -1;
        cout << "starting.." << endl;
    }

    //an array to hold the time spent to query each possible byte (256) at the current position
    uint32_t *overall_times = (uint32_t*)malloc(0x100 * sizeof uint32_t);
    if (!overall_times) exit(-1);
    memset(overall_times, 0, 0x100 * sizeof uint32_t);

    //test all the possible values for this byte and record the time spent
    for (int j = 0; j <= 0xFF; j++)
    {
        uint32_t timespent = chal32_test_value(pos + 1, j, guess, ctx);
        overall_times[j] = timespent;

        //cout << "value: " << std::hex << j << std::dec << " time: " << timespent << endl;
    }

    float avg_crt = chal32_calc_average(overall_times);

#if 1
    //to improve accuracy, retest values outside the standard deviation
    float devi = 2 * chal32_calc_standard_deviation(overall_times, avg_crt);
    //cout << " sd:" << avg_crt - sd << " " << avg_crt + sd << endl;
    for (int k = 0; k <= 0xFF; k++)
    {
        int val = overall_times[k];
        if (val > 0 && (((float)val > avg_crt + devi) || ((float)val < avg_crt - devi)))
        {
            uint32_t timespent = chal32_test_value(pos + 1, k, guess, ctx);
            //cout << "value: " << std::hex << k << std::dec << " time: " << timespent << " " << overall_times[k] << endl;
            if (timespent < overall_times[k])
            {
                overall_times[k] = timespent;
            }
        }
    }
    avg_crt = chal32_calc_average(overall_times);
#endif

    //account for the first call to this function (pos = -1)
    if (pos >= 0)
        averages[pos] = avg_crt;
    else
        chal32_base_avg = avg_crt;
    float avg_prev = pos > 0 ? averages[pos - 1] : chal32_base_avg;
    float avg_diff = avg_crt - avg_prev;

    cout << "v: " << std::hex << val << std::dec << " a: " << avg_crt << " d: " << avg_diff << endl;

    //check if this avenue should be aborted; i.e. it has no increase in time spent
    if (chal32_should_abort(pos, averages))
    {
        cout << "v: " << std::hex << val << std::dec << " aborting" << endl;
    }
    else
    {
        int negative = 0;
        int streak = 0;
        int streak_limit = 3;
        for (int k = 0; k <= 0xFF; k++)
        {
            float res = chal32_explore_guess(pos + 1, chal32_extract_high_value(overall_times, 1), guess, averages, ctx);
            //if it was incloncusive to abort at the current byte, it mayb be decided to abort at greter indexes;
            //take that into account and abort at this level if necessary
            if (res < -5.0)
            {
                negative = 1;
                break;
            }
            if (res < 5)
            {   //we allow a couple of tries that do not increase the time taken
                streak++;
            }
            if (streak >= streak_limit)
            {   //a number of 'streak_limit' non-consecutive results causes an abort
                break;
            }
            if (res > avg_diff * 0.75)
            {   //found what we were looking for, exit the recursion
                break;
            }
        }
        if ((negative == 1) || (streak >= streak_limit))
        {
            cout << "v: " << std::hex << val << std::dec << " aborting" << endl;
        }

    }

    free(overall_times);
    return avg_diff;
}

static tcpcom_msgcb_ret chal32_incoming_message_cb(const membuf* incoming, membuf* outgoing);

/**
  * NOTE: we're now using simplehttp server, since webpy had weird variations in timing (every third correct byte
  *   there was no/neg increase in time to validate followed by a big increase on the next byte, this caused alot of trial and error) 
  * $> python -m venv .\webpy\venv           #creates the python virtual environment in webpy subfolder
  * $> .\webpy\venv\Scripts\activate.bat     #enters the virtual environment
  * $> python appsimple.py                   #starts the webserver application
  */

int call_challenge32()
{
    membuf out = MEMBUF_INITIALISER;

    hmac_sha1((uc8_t*)chal32_msg, strlen(chal32_msg), (uc8_t*)chal32_key, strlen((char*)chal32_key), &out);

    char local[SHA1_DIGEST_SZ * 2 + 1];
    memset(local, 0, sizeof local);
    bytes_to_hexstring(out.data, SHA1_DIGEST_SZ, (uc8_t*)local, SHA1_DIGEST_SZ * 2);

    cout << local << endl;
    //membuf_free(&out);

    //we can use our own basic http server implementation or use the python server
    //tcpcom_server("127.0.0.1", "8080", chal32_incoming_message_cb);

    uc8_t guess[SHA1_DIGEST_SZ];
    float averages[SHA1_DIGEST_SZ];

    memset(guess, 0, sizeof guess);
    memset(averages, 0, sizeof averages);
    memset(local, 0, sizeof local);
    memset(chal32_scratch, 0, sizeof chal32_scratch);

    membuf_adjust_size(&chal32_url, 2048);
    membuf_adjust_size(&chal32_httpget, 2048);

    void* tcpcom_ctx = NULL;
    tcpcom_init(&tcpcom_ctx, chal32_address, chal32_port);

#if 0
    //problematic steps for webpy, no change in time spent; not clear why these behave differently
    int i;
    i = 1;
    chal32_explore_guess(i, out.data[i], guess, averages, &tcpcom_ctx);
    i = 2;
    chal32_explore_guess(i, out.data[i], guess, averages, &tcpcom_ctx);
    i = 3;
    chal32_explore_guess(i, out.data[i], guess, averages, &tcpcom_ctx);
#endif
#if 0
    //just check if each new correct byte causes an increase in time spent to validate
    //NOTE: also needs the should_abort function to return 1
    for (int i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        averages[i] = 0.0;
        chal32_explore_guess(i, out.data[i], guess, averages, &tcpcom_ctx);
    }
#endif
#if 1
    //recursive solution
    chal32_explore_guess(-1, 0xF00, guess, averages, &tcpcom_ctx);
#endif

    tcpcom_close(&tcpcom_ctx);

    membuf_free(&chal32_url);
    membuf_free(&chal32_httpget);
    membuf_free(&out);

    return 0;
}

static tcpcom_msgcb_ret chal32_incoming_message_cb(const membuf* incoming, membuf* outgoing)
{
    tcpcom_msgcb_ret ret = TCPCOM_RETVAL_CONTINUE;
    const char* rcvbuf = (char*)incoming->data;

    const char* check;
    if ((check = strstr(rcvbuf, "Connection")) == NULL)
        check = strstr(rcvbuf, "connection");

    if (check)
    {
        const char* clos;
        if ((clos = strstr(check, "Close")) == NULL)
            clos = strstr(check, "close");

        if(clos && (clos - check < 15))
            ret = TCPCOM_RETVAL_CLOSE;
    }

    char file[100];
    uc8_t sig[SHA1_DIGEST_SZ];
    memset(file, 0, sizeof(file));

    //search for: file=%s&signature=%s
    if ((check = strstr(rcvbuf, "file=")) != NULL)
    {
        const char* limit = strchr(check, '&');
        if (limit)
        {
            int tocopy = limit - check - strlen("file=");
            tocopy = tocopy < sizeof(file) ? tocopy : sizeof(file) - 1;
            strncpy(file, check + strlen("file="), tocopy);
        }
    }
    if ((check = strstr(rcvbuf, "signature=")) != NULL)
    {
        const char* limit = strchr(check, ' ');
        if (limit)
        {
            int tocopy = limit - check - strlen("signature=");
            hexstring_to_bytes(check + strlen("signature="), tocopy, sig, SHA1_DIGEST_SZ);
        }
    }

    membuf out = MEMBUF_INITIALISER;

    hmac_sha1((uc8_t*)file, strlen(file), (uc8_t*)chal32_key, strlen((char*)chal32_key), &out);

    const char* resp = tcpcom_httpresp200;

    int i;
    for (i = 0; i < SHA1_DIGEST_SZ; i++)
    {
        if (sig[i] != out.data[i])
        {
            resp = tcpcom_httpresp500;
            break;
        }
        Sleep(1);
    }

    membuf_adjust_size(outgoing, strlen(tcpcom_httpresponse) + strlen(tcpcom_httpresp200) + strlen(tcpcom_httpresp400) + strlen(tcpcom_httpresp500));
    outgoing->used = snprintf((char*)outgoing->data, outgoing->size, tcpcom_httpresponse, resp);

    membuf_free(&out);

    return ret;
}