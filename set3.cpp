
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

    retcode = call_challenge17();

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

    int ret = aes_cbc_decrypt(&cyphertxt->data[AES_BLOCK_SIZE_BYTES], cyphertxt->used - AES_BLOCK_SIZE_BYTES, (uc8_t*)chal17_key, cyphertxt->data, mbout.data, &mbout.used);

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

    do {

		tmp = &scratch.data[AES_BLOCK_SIZE_BYTES * blockidx];

        for (j = p + 1; j <= 16; j++)
        {
			for (k = AES_BLOCK_SIZE_BYTES - j + 1; k < AES_BLOCK_SIZE_BYTES; k++) {
				tmp[k] ^= workingblk[k] ^ j;
			}

            for (i = 1; i <= 0xFF; i++)
            {
				tmp[AES_BLOCK_SIZE_BYTES - j] = i;
                int valid = chal17_check_padding(&scratch);
                if (valid)
                {
					tmp = &cyphertxt.data[AES_BLOCK_SIZE_BYTES * blockidx];
                    cout << "found " << j << " " << i << " " << (char)(j ^ i ^ tmp[AES_BLOCK_SIZE_BYTES - j]) << endl;
					workingblk[AES_BLOCK_SIZE_BYTES - j] = j ^ i ^ tmp[AES_BLOCK_SIZE_BYTES - j];
                    membuf_append_byte_auto(&knowndata, j ^ i);
                }
            }
        }

		p++;

		if (p == 16)
		{
			blockidx--;
			p = 0;
			memset(workingblk, 0, sizeof(workingblk));
		}

    } while (blockidx >= 0);

    return 0;
}