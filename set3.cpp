
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>

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

    retcode = call_challenge23();

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
        if (!istext_r(data[i]))
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

int call_challenge20()
{
    const char* chal20_key = "By*4m@&uuRne5mwk";

    membuf line = MEMBUF_INITIALISER;

    membuf* texts = NULL;
    membuf* memiter = NULL;
    size_t datasz = 0;
    int datanum = 0;
    data_buffer_adjust((uc8_t**)&texts, &datasz, 60 * sizeof(membuf));
    memset(texts, 0, datasz);

    int used;

    std::fstream xor_file;

    xor_file.open("challenge20.txt", std::ios::in);

    if (xor_file.is_open()) {
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {
            size_t size = sa.length();
            if (size <= 0) break;

            data_buffer_adjust((uc8_t**)&texts, &datasz, (datanum + 1) * sizeof(uc8_t*));
            memiter = &texts[datanum];
            membuf_init(memiter);

            membuf_adjust_size(&line, base64_dec_bufsz(size) + 1);
            line.used = base64tohex((uc8_t*)sa.c_str(), size, line.data, line.size);
            membuf_adjust_size(memiter, line.used);
            aes_ctr_xcrypt(line.data, line.used, (uc8_t*)chal20_key, 0, memiter->data, &used);
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

    uc8_t* keystrm = (uc8_t*)malloc(maxtxtlen);
    if (!keystrm) exit(-1);
    memset(keystrm, 0, maxtxtlen);
    uc8_t* xordest = (uc8_t*)malloc(maxtxtlen + 1);
    if (!xordest) exit(-1);
    uc8_t* local = (uc8_t*)malloc(datanum);
    if (!local) exit(-1);

    for (j = 0; j < maxtxtlen; j++)
    {
        float freq = 10.0f;
        int count = 0;
        for (i = 0; i < datanum; i++)
        {
            if (j < texts[i].used)
            {
                local[count] = texts[i].data[j];
                count++;
            }
        }

        for (k = 0; k <= 0xff; k++)
        {
            memset(xordest, k, datanum + 1);
            xor_fixed(local, xordest, xordest, count);
            float temp = character_frequency_calculate(xordest, count);
            if (0.0f < temp && temp < freq)
            {
                //if(j == 0)
                //    cout << temp << " " << xordest << endl;
                freq = temp;
                keystrm[j] = k;
            }
        }
    }

    if (maxtxtlen >= 117)
    {
        keystrm[91] = 's' ^ texts[2].data[91];
        keystrm[94] = 'c' ^ texts[4].data[94];
        keystrm[95] = 'k' ^ texts[2].data[95];
        keystrm[101] = 'p' ^ texts[21].data[101];
        keystrm[105] = 'e' ^ texts[21].data[105];
        keystrm[106] = 'h' ^ texts[26].data[106];
        keystrm[107] = 'o' ^ texts[26].data[107];
        keystrm[108] = 'l' ^ texts[26].data[108];
        keystrm[109] = 'e' ^ texts[26].data[109];
        keystrm[110] = ' ' ^ texts[26].data[110];
        keystrm[111] = 's' ^ texts[26].data[111];
        keystrm[112] = 'c' ^ texts[26].data[112];
        keystrm[113] = 'e' ^ texts[26].data[113];
        keystrm[114] = 'n' ^ texts[26].data[114];
        keystrm[115] = 'e' ^ texts[26].data[115];
        keystrm[116] = 'r' ^ texts[26].data[116];
        keystrm[117] = 'y' ^ texts[26].data[117];
    }

    for (i = 0; i < datanum; i++)
    {
        memset(xordest, 0, maxtxtlen + 1);
        xor_fixed(texts[i].data, keystrm, xordest, texts[i].used);

        cout << xordest << endl;
    }

    return 0;
}

int call_challenge21()
{
    int seed = 1704893663;// time(NULL);
    cout << "mt19937 seed: " << seed << endl;

    mt19937_seed(seed);

    for (int i = 0; i < 10; i++)
    {
        cout << mt19937_gen() << endl;
    }

    return 0;
}

int call_challenge22()
{
#define CHAL22_NUM_STEPS 5

    int i = 0;
    unsigned int seeds[CHAL22_NUM_STEPS];
    unsigned int vals[CHAL22_NUM_STEPS];

    random_seed_init();

    for (i = 0; i < CHAL22_NUM_STEPS; i++)
    {
        int towait = (int)rand() % 260 + 40; //upto 5min
        cout << "Waiting for a couple of seconds..\n";
        Sleep(towait * 1000);

        seeds[i] = (unsigned int)time(NULL);
        towait = (int)rand() % 10 + 5;
        Sleep(towait * 1000);

        mt19937_seed(seeds[i]);
        vals[i] = mt19937_gen();
        cout << i << ". generated value is " << vals[i] << endl;
    }

    unsigned int now = (unsigned int)time(NULL);
    for (i = CHAL22_NUM_STEPS - 1; i >= 0; i--)
    {
        cout << "Trying to find seed " << i << " .. ";
        while (1)
        {
            mt19937_seed(now);
            if (mt19937_gen() == vals[i])
            {
                cout << now << (now == seeds[i] ? " ok" : " nok") << endl;
                break;
            }
            now--;
        }
    }

    return 0;
}

static unsigned int mt_19937_untemper(unsigned int val)
{
    int i;
    uint32_t res;
    int shiftv;
    uint32_t andv;
    /*
    y = y ^ ((y >> 11) & 0xFFFFFFFF);
    y = y ^ ((y << 7) & 0x9D2C5680U);
    y = y ^ ((y << 15) & 0xEFC60000U);
    y = y ^ (y >> 18);
    */
    //reverse y ^ (y >> 18) -> bit[n] = bit[n+18] ^ bit[n]
    res = 0;
    shiftv = 18;
    for (i = 31; i >= 0; i--)
    {
        uint32_t bitn = (val >> i) & 1;
        uint32_t bitn1 = (res >> (i + shiftv)) & 1;
        bitn = bitn ^ bitn1;
        bitn = bitn << i;
        res = res | bitn;
    }
    //reverse  y ^ ((y << 15) & 0xEFC60000U) -> bit[n] = bit[n-18] & andv[n]
    val = res;
    res = 0;
    shiftv = 15;
    andv = 0xEFC60000U;
    for (i = 0; i <= 31; i++)
    {
        uint32_t bitn = (val >> i) & 1;
        uint32_t bitn1 = ((res << shiftv) >> i) & 1;
        uint32_t andvn1 = ((andv) >> i) & 1;
        bitn1 = bitn1 & andvn1;
        bitn = bitn ^ bitn1;
        bitn = bitn << i;
        res = res | bitn;
    }
    //reverse  y ^ ((y << 7) & 0x9D2C5680) -> bit[n] = bit[n-7] & andv[n]
    val = res;
    res = 0;
    shiftv = 7;
    andv = 0x9D2C5680U;
    for (i = 0; i <= 31; i++)
    {
        uint32_t bitn = (val >> i) & 1;
        uint32_t bitn1 = ((res << shiftv) >> i) & 1;
        uint32_t andvn1 = ((andv) >> i) & 1;
        bitn1 = bitn1 & andvn1;
        bitn = bitn ^ bitn1;
        bitn = bitn << i;
        res = res | bitn;
    }
    //reverse  y ^ (y >> 11) -> bit[n] = bit[n+11] ^ bit[n]
    val = res;
    res = 0;
    shiftv = 11;
    for (i = 31; i >= 0; i--)
    {
        uint32_t bitn = (val >> i) & 1;
        uint32_t bitn1 = (res >> (i + shiftv)) & 1;
        bitn = bitn ^ bitn1;
        bitn = bitn << i;
        res = res | bitn;
    }

    return res;
}

static void mt_19937_permute(uint32_t* mt_buf, uint32_t numvals);

int call_challenge23()
{
#define MT_19937_NUM_VALS 624

    uint32_t val = 1628626723U;
    if (mt_19937_untemper(2293680981U) == val)
    {
        cout << "untemper ok\n";
    }

    uint32_t* mt_data = (uint32_t*)malloc(MT_19937_NUM_VALS * sizeof(uint32_t));
    if (!mt_data) exit(E_OUTOFMEMORY);

    random_seed_init();
    int i = rand() % 5000;

    mt19937_seed((int)time(NULL));

    for (; i > 0; i--)
        mt19937_gen();

    for (i = 0; i < MT_19937_NUM_VALS; i++)
    {
        mt_data[i] = mt_19937_untemper(mt19937_gen());
    }
    mt_19937_permute(mt_data, MT_19937_NUM_VALS);

    for (i = 0; i < MT_19937_NUM_VALS; i++)
    {
        if (mt_19937_untemper(mt19937_gen()) != mt_data[i])
        {
            cout << "nooooo...\n";
        }
    }

    return 0;
}

static void mt_19937_permute(uint32_t *mt_buf, uint32_t numvals)
{
    for (uint32_t i = 0; i < numvals; i++)
    {
        uint32_t x = (mt_buf[i] & 0x80000000U) |
            (mt_buf[(i + 1) % numvals] & 0x7FFFFFFFU);
        uint32_t xA = x >> 1;
        if ((x & 1) != 0) // lowest bit of x is 1
        {
            xA = xA ^ 0x9908B0DFU;
        }
        mt_buf[i] = mt_buf[(i + 397) % numvals] ^ xA;
    }
}