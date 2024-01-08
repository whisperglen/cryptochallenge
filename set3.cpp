
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include <iostream>
#include <string>
#include <fstream>

using std::string;
using std::cin;
using std::cout;
using std::endl;

int call_challenge17();
int call_challenge18();
int call_challenge19();
int call_challenge20();
int call_challenge21();
int call_challenge22();
int call_challenge23();
int call_challenge24();

int call_set3()
{
    int retcode = 0;
    std::cout << "This is Set 3\n";

    retcode = call_challenge19();

    return retcode;
}

const char *chal17_key = "$Lh3lb778%bX7gX6";

int chal17_encrypt(membuf *output)
{
    int ret = 0;
    const char* mystrings[] = {
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    };

    random_seed_init();

    int selected = rand() % 10;

    const char* text = mystrings[selected];

    membuf mbin = MEMBUF_INITIALISER;
    membuf_adjust_size(&mbin, base64_dec_bufsz(strlen(text)));

    mbin.used = base64tohex((uc8_t*)text, strlen(text), mbin.data, mbin.size);

    membuf_adjust_size(output, AES_BLOCK_SIZE_BYTES + aes_encode_bufsz(mbin.used));
    random_keygen(output->data, AES_BLOCK_SIZE_BYTES);
    output->used = AES_BLOCK_SIZE_BYTES;

    int used = 0;
    aes_cbc_encrypt(mbin.data, mbin.used, (uc8_t*)chal17_key, output->data, &output->data[AES_BLOCK_SIZE_BYTES], &used);
    output->used += used;

    membuf_free(&mbin);

    return ret;
}

int chal17_check_padding(membuf* cyphertxt)
{
    static membuf mbout = MEMBUF_INITIALISER;

    membuf_adjust_size(&mbout, cyphertxt->used);

    int used = 0;
    int ret = aes_cbc_decrypt(&cyphertxt->data[AES_BLOCK_SIZE_BYTES], cyphertxt->used - AES_BLOCK_SIZE_BYTES, (uc8_t*)chal17_key, cyphertxt->data, mbout.data, &used);

    return ret < 0 ? 0 : 1;
}

int call_challenge17()
{
    membuf cyphertxt = MEMBUF_INITIALISER;
    membuf scratch = MEMBUF_INITIALISER;
    membuf knowndata = MEMBUF_INITIALISER;

    chal17_encrypt(&cyphertxt);
    membuf_adjust_size(&scratch, cyphertxt.used);
    membuf_copy(&scratch, &cyphertxt);

    int i, j, k, p;
    int found = 0;
    //find padding bytes
	//we start changing one byte previous to the last
    uc8_t* tmp = &scratch.data[scratch.used - AES_BLOCK_SIZE_BYTES - 1 - 1];
    for (p = 1; p <= 16; p++, tmp--)
    {
        *tmp ^= 1;

        int valid = chal17_check_padding(&scratch);
        if (valid)
        {
            cout << "valid padding for " << p << endl;
            found = 1;
			break;
        }

        //revert the modification
        *tmp ^= 1;
    }

	uc8_t workingblk[AES_BLOCK_SIZE_BYTES];

	for (i = 0; i < AES_BLOCK_SIZE_BYTES; i++)
	{
		workingblk[i] = i < AES_BLOCK_SIZE_BYTES - p ? 0 : p;
	}

    int howmanyblocks = cyphertxt.used / AES_BLOCK_SIZE_BYTES;
    int blockidx = howmanyblocks - 1 - 1;

    if (p == 16)
    {
        blockidx--;
        p = 0;
        scratch.used -= AES_BLOCK_SIZE_BYTES;
    }

    membuf_append_byte_auto(&knowndata, 0);

    while (blockidx >= 0)
    {

		tmp = &scratch.data[AES_BLOCK_SIZE_BYTES * blockidx];

        for (j = p + 1; j <= 16; j++)
        {
			for (k = AES_BLOCK_SIZE_BYTES - j + 1; k < AES_BLOCK_SIZE_BYTES; k++) {
				tmp[k] ^= workingblk[k] ^ j;
			}

            for (i = 0; i <= 0xFF; i++)
            {
				tmp[AES_BLOCK_SIZE_BYTES - j] = i;
                int valid = chal17_check_padding(&scratch);
                if (valid)
                {
					uc8_t *org = &cyphertxt.data[AES_BLOCK_SIZE_BYTES * blockidx];
                    uc8_t value = j ^ i ^ org[AES_BLOCK_SIZE_BYTES - j];
                    //cout << "found " << j << " " << i << " " << (char)(value) << endl;
					workingblk[AES_BLOCK_SIZE_BYTES - j] = value;
                    memcpy(tmp, org, AES_BLOCK_SIZE_BYTES);
                    membuf_prepend_byte_auto(&knowndata, value);
                    break;
                }
            }
        }

		blockidx--;
		p = 0;
        scratch.used -= AES_BLOCK_SIZE_BYTES;
		memset(workingblk, 0, sizeof(workingblk));

    };

    cout << "final " << knowndata.data << endl;

    return 0;
}



static int aes_ctr_xcrypt(const uc8_t* in, size_t insz, const uc8_t* key, uint64_t nonce, uc8_t* output, int* outlen)
{
    int ret = 0;

    uc8_t iv[AES_BLOCK_SIZE_BYTES];
    uc8_t local[AES_BLOCK_SIZE_BYTES * 2];
    int64_t counter = 0;

    int used;

    memcpy(iv, &nonce, AES_BLOCK_SIZE_BYTES / 2);

    int xorsz = AES_BLOCK_SIZE_BYTES;
    int i = 0;
    while (i < insz)
    {
        memcpy(&iv[AES_BLOCK_SIZE_BYTES / 2], &counter, AES_BLOCK_SIZE_BYTES / 2);

        ret = aes_ecb_encrypt(iv, AES_BLOCK_SIZE_BYTES, key, local, &used);
        if (ret < 0)
            break;

        if (i + 16 > insz)
        {
            xorsz = insz - i;
        }

        xor_fixed(&in[i], local, &output[i], xorsz);

        i += xorsz;
        counter++;
    }

    *outlen = i;

    return ret;
}

int call_challenge18()
{
    const char *key = "YELLOW SUBMARINE";
    uint64_t nonce = 0;
    const char *cyphertxtb64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    membuf cyphertxt = MEMBUF_INITIALISER;
    membuf plaintxt = MEMBUF_INITIALISER;
    membuf_adjust_size(&cyphertxt, base64_dec_bufsz(strlen(cyphertxtb64)));

    cyphertxt.used = base64tohex((uc8_t*)cyphertxtb64, strlen(cyphertxtb64), cyphertxt.data, cyphertxt.size);

    int used;
    membuf_adjust_size(&plaintxt, cyphertxt.used + 1);
    aes_ctr_xcrypt(cyphertxt.data, cyphertxt.used, (uc8_t*)key, nonce, plaintxt.data, &used);
    plaintxt.used = used;

    membuf_append_byte_auto(&plaintxt, 0);

    cout << plaintxt.data << endl;

    return 0;
}

static int str_istext(const uc8_t* data, int len)
{
    int ret = 1;

    if (len < 0)
        len = strlen((char*)data);

    for (int i = 0; i < len; i++)
    {
        if (!istext(data[i]))
        {
            ret = 0;
            break;
        }
    }

    return ret;
}

static int memiszero(uc8_t* data, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        if (data[i] != 0)
            break;
    }
    return (i == size);
}

void memadd(uc8_t* dst, int val, int size)
{
    for (int i = 0; i < size; i++)
    {
        dst[i] += val;
    }
}

static void chal19_possible_key(int pos, const uc8_t* data, int size, uc8_t* storage, int levels, int stride)
{
    int useful = 0;

    for (int i = 0; i < levels; i++)
    {
        uc8_t *weights = &storage[stride * (i * 2)];
        uc8_t* keystr = &storage[stride * (i * 2 + 1)];

        if (memiszero(&weights[pos], size))
        {
            memcpy(&keystr[pos], data, size);
            memadd(&weights[pos], 1, size);
            useful = 1;
            break;
        }

        if (0 == memcmp(&keystr[pos], data, size))
        {
            memadd(&weights[pos], 1, size);
            useful = 1;
            break;
        }
    }

    if (useful == 0)
    {
        cout << "abandon\n";
    }
}

static void chal19_mod_storage(int pos, uc8_t val, uc8_t* storage, int levels, int stride)
{
    uc8_t* keystr = &storage[stride * (0 * 2 + 1)];
    keystr[pos] = val;
}

static void chal19_list_key(uc8_t* storage, int levels, int stride)
{
    int useful = 0;

    uc8_t* printme = (uc8_t*)malloc(stride * 2 + 1);
    if (!printme) exit(-1);
    memset(printme, 0, stride * 2 + 1);

    cout << "These are the found keystream bytes\n";

    for (int i = 0; i < levels; i++)
    {
        uc8_t* weights = &storage[stride * (i * 2)];
        uc8_t* keystr = &storage[stride * (i * 2 + 1)];

        bytes_to_hexstring(weights, stride, printme, stride * 2);
        cout << printme << endl;

        bytes_to_hexstring(keystr, stride, printme, stride * 2);
        cout << printme << endl << endl;
    }

    free(printme);
}

static void chal19_do_search(const char* patterns[], membuf* texts, int datanum, uc8_t* storage, int storagelevels, int maxtxtlen);

int call_challenge19()
{
    const char* chal19_key = "F6n^DMDHpRgHs19l";

    const char* quadrigrams[] = { "that", "ther", "with", "tion", "here", "ould", "ight", "have", "hich", "whic", "this", "thin", "they", "atio", "ever", "from", "ough", "were", "hing", "ment", NULL };
    const char* trigrams[] = { "the", "and", "tha", "ent", "ing", "ion", "tio", "for", "nde", "has", "nce", "edt", "tis", "oft", "sth", "men", NULL };
    const char* bigrams[] = { "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es", "on", "at", "se", "nd", "or", "ar", "al", "te", "co", "de", "to", "ra", "et", "ed", "it", "sa", "em", "ro", NULL };

    membuf line = MEMBUF_INITIALISER;

    membuf* texts = NULL;
    membuf* memiter = NULL;
    size_t datasz = 0;
    int datanum = 0;
    data_buffer_adjust((uc8_t**)&texts, &datasz, 40 * sizeof(membuf));
    memset(texts, 0, datasz);

    int used; 

    std::fstream xor_file;

    xor_file.open("challenge19.txt", std::ios::in);

    if (xor_file.is_open()) {
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {
            data_buffer_adjust((uc8_t**)&texts, &datasz, (datanum + 1) * sizeof(uc8_t*));
            memiter = &texts[datanum];
            membuf_init(memiter);

            size_t size = sa.length();

            membuf_adjust_size(&line, base64_dec_bufsz(size) + 1);
            line.used = base64tohex((uc8_t*)sa.c_str(), size, line.data, line.size);
            membuf_adjust_size(memiter, line.used);
            aes_ctr_xcrypt(line.data, line.used, (uc8_t*)chal19_key, 0, memiter->data, &used);
            memiter->used = used;

            datanum++;
        }

        // Close the file object.
        xor_file.close();
    }

    int i, j, k;
    int mintxtlen = 1000;
    int maxtxtlen = 0;
    for (i = 0; i < datanum; i++, memiter++)
    {
        int len = texts[i].used;
        
        if (len > 0 && len < mintxtlen)
            mintxtlen = len;

        if (len > maxtxtlen)
            maxtxtlen = len;
    }

    character_frequency_table_init();

    const int storagelevels = 10;
    uc8_t* storage = (uc8_t*)malloc(maxtxtlen * 2 * storagelevels);
    if (!storage) exit(-1);
    memset(storage, 0, maxtxtlen * 2 * storagelevels);
    uc8_t* xordest = (uc8_t*)malloc(maxtxtlen + 1);
    if (!xordest) exit(-1);

    chal19_do_search(quadrigrams, texts, datanum, storage, storagelevels, maxtxtlen);
    chal19_do_search(trigrams, texts, datanum, storage, storagelevels, maxtxtlen);
    chal19_do_search(bigrams, texts, datanum, storage, storagelevels, maxtxtlen);

    chal19_mod_storage(10, texts[0].data[10] ^ ' ', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(18, texts[0].data[18] ^ ' ', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(23, texts[0].data[23] ^ 'e', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(30, texts[0].data[30] ^ 'y', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(31, texts[6].data[31] ^ 'd', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(32, texts[27].data[32] ^ 'd', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(33, texts[4].data[33] ^ 'e', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(34, texts[4].data[34] ^ 'a', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(35, texts[4].data[35] ^ 'd', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(36, texts[37].data[36] ^ 'n', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(37, texts[37].data[37] ^ ',', storage, storagelevels, maxtxtlen);
    chal19_mod_storage(0, texts[0].data[0] ^ 'I', storage, storagelevels, maxtxtlen);

    chal19_list_key(storage, storagelevels, maxtxtlen);

    for (i = 0; i < datanum; i++)
    {
        memset(xordest, 0, maxtxtlen + 1);
        xor_fixed(texts[i].data, &storage[maxtxtlen * (0 * 2 + 1)], xordest, texts[i].used);

        cout << xordest << endl;
    }

    return 0;
}

static void chal19_do_search(const char* patterns[], membuf* texts, int datanum, uc8_t* storage, int storagelevels, int maxtxtlen)
{
    int i, j, k;
    uc8_t* xordest = (uc8_t*)malloc(maxtxtlen + 1);
    if (!xordest) exit(-1);
    membuf tested = MEMBUF_INITIALISER;

    uc8_t locals[4];

    int count = 0;
    do {
        const char* artifact = patterns[count++];
        if (artifact == NULL) break;
        int artlen = strlen(artifact);
        cout << "Testing for: " << artifact << endl;

        int text_ok = 0;

        for (i = 0; i < datanum; i++)
        {
            int sz1 = texts[i].used;

            for (k = 0; k < sz1 - artlen; k++)
            {
                membuf_clear(&tested);
                text_ok = 0;

                for (j = 0; j < datanum; j++)
                {
                    if (j == i) continue;

                    int sz = texts[j].used;
                    if (sz1 < sz) sz = sz1;
                    xor_fixed(texts[i].data, texts[j].data, xordest, sz);

                    if (k + artlen > sz)
                    {
                        continue;
                    }

                    //check
                    xor_fixed(&xordest[k], (uc8_t*)artifact, &xordest[k], artlen);

                    text_ok = str_istext(&xordest[k], artlen);
                    if (!text_ok)
                    {
                        break;
                    }
                    membuf_append_data_auto(&tested, &xordest[k], artlen);

                    //xor_fixed(&xordest[k], (uc8_t*)artifact, xordest, artlen);
                }

                if (text_ok)
                {
                    float check = character_frequency_calculate(tested.data, tested.used);
                    //if (check < 0.4f)
                    {
                        membuf_append_byte_auto(&tested, 0);
                        cout << "found " << i << " at pos: " << k << " " << check << " " << tested.data << endl;
                    }
                    xor_fixed(&(texts[i].data[k]), (uc8_t*)artifact, locals, artlen);
                    chal19_possible_key(k, locals, artlen, storage, storagelevels, maxtxtlen);
                }
            }
        }

    } while (1);

    free(xordest);
}