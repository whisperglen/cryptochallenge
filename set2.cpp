
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

int call_challenge9();
int call_challenge10();
int call_challenge11();
int call_challenge12();
int call_challenge13();
int call_challenge14();
int call_challenge15();
int call_challenge16();

int call_set2()
{
    int retcode = 0;
    std::cout << "This is Set 2\n";

    retcode = call_challenge16();

    return retcode;
}

int call_challenge9()
{
    uc8_t* data = NULL;
    size_t datasz = 0;

    data_buffer_adjust(&data, &datasz, 20);

    memset(data, 0, datasz);

    const char* mystring = "YELLOW SUBMARINE";

    strcpy((sc8_t*)data, mystring);

    pad_data_buffer(&data, &datasz, strlen(mystring), 20);

    return 0;
}

int call_challenge10()
{
    //read file in memory
    unsigned char* data = NULL;
    size_t datasz = 0, used = 0;

    std::fstream xor_file;

    xor_file.open("challenge10.txt", std::ios::in);

    if (xor_file.is_open()) {
        int count = 0;
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {

            count++;

            size_t size = sa.length();

            data_buffer_adjust(&data, &datasz, used + size + 1);
            data[datasz - 1] = 0;

            used += base64tohex((uc8_t*)sa.c_str(), size, &data[used], datasz - used);
            data[used] = 0;

        }

        // Close the file object.
        xor_file.close();
    }

    if (data == NULL) exit(-1);

    const char* key = "YELLOW SUBMARINE";

    uc8_t scratchpad[64];

    char out1[32], *out2 = NULL;
    int out1len = sizeof(out1);
    size_t out2len = 0;

    data_buffer_adjust((uc8_t**)&out2, &out2len, used + 1);

    memset(out1, 0, out1len);
    memset(out2, 0, out2len);

    //prepare padding buffer to be fed to the decryter
    memset(out1, 16, 16);

    int tmpsz = 0;

    //encrypt the padding buffer that is fed to the decrypter
    aes_ecb_encrypt((uc8_t*)out1, 16, (uc8_t*)key, scratchpad, &tmpsz);
    //use 2 alternating scratchpads, since a block needs to be xored with the previously encrypted block
    //set the iv to value 0
    memset(&scratchpad[32], 0, 16);
    memcpy(&scratchpad[48], scratchpad, 16);

    uc8_t* scratch1 = scratchpad;
    uc8_t* scratch2 = &scratchpad[32];
    uc8_t* stmp;

    int i = 0;
    while (i + 16 <= used)
    {
        memcpy(scratch1, &data[i], 16);

        aes_ecb_decrypt((uc8_t*)scratch1, 32, (uc8_t*)key, (uc8_t*)out1, &tmpsz);

        xor_fixed((uc8_t*)out1, (uc8_t*)scratch2, (uc8_t*)&out2[i], 16);

        i += 16;

        stmp = scratch1;
        scratch1 = scratch2;
        scratch2 = stmp;
    }

    //remove padding bytes
    stmp = (uc8_t*)&out2[used - 1];
    uc8_t tval = *stmp;
    while (tval == *stmp)
    {
        *stmp = 0;
        stmp--;
    }

    cout << out2 << endl;

    return 0;
}

static void init_random_seed()
{
    static int initialised = 0;
    if (initialised == 0)
    {
        unsigned int seed = time(NULL);
        srand(seed);
        initialised = 1;
        cout << "seed: " << seed << endl;
    }
}

void gen_random_key(uc8_t* out, int size)
{
    init_random_seed();

    int i;
    for (i = 0; i < size; i++)
    {
        out[i] = rand() % 0xFF + 1;
    }
}

int encryption_oracle(uc8_t* in, size_t insz, uc8_t** out, size_t* outsz, int method)
{
    uc8_t randkey[AES_BLOCK_SIZE_BYTES +1];
    gen_random_key(randkey, AES_BLOCK_SIZE_BYTES);
    randkey[AES_BLOCK_SIZE_BYTES] = 0;

    uc8_t randiv[AES_BLOCK_SIZE_BYTES];

    init_random_seed();
    int extras1 = rand() % 6 + 5;
    int extras2 = rand() % 6 + 5;
    uc8_t prefix_bytes[10], suffix_bytes[10];
    gen_random_key(prefix_bytes, extras1);
    gen_random_key(suffix_bytes, extras2);

    int datasz = insz + extras1 + extras2;
    uc8_t* data = (uc8_t*)malloc(datasz);
    if (data == NULL) exit(-1);

    memcpy(data, prefix_bytes, extras1);
    memcpy(&data[extras1], in, insz);
    memcpy(&data[extras1 + insz], suffix_bytes, extras2);

    data_buffer_adjust(out, outsz, datasz + AES_BLOCK_SIZE_BYTES);

    int used = 0;
    if (method == 2)
    {
        method = rand() % 2;
    }
    if (method)
    {
        aes_ecb_encrypt(data, datasz, randkey, *out, &used);
    }
    else
    {
        gen_random_key(randiv, AES_BLOCK_SIZE_BYTES);
        aes_cbc_encrypt(data, datasz, randkey, randiv, *out, &used);
    }
    cout << "method " << (method ? "ecb" : "cbc") << endl;

    free(data);
    return used;
}

int const bar_max_size = 32;

void print_bar(int len)
{
    int i;
    for (i = 0; i < bar_max_size; i++)
    {
        cout << (i < len ? "=" : " ");
    }
}

int call_challenge11()
{

    char text1[] = "Ehrsam, Meyer, Smith and Tuchman invented the cipher block chaining(CBC) mode of operation in 1976.";
    char key[] = "YELLOW SUBMARINE";
    uc8_t iv[AES_BLOCK_SIZE_BYTES];

    char text2[] = "CBC has been the most commonly used mode of operation. Its main drawbacks are that encryption is sequential (i.e., it cannot be parallelized), and that the message must be padded to a multiple of the cipher block size. One way to handle this last issue is through the method known as ciphertext stealing. Note that a one-bit change in a plaintext or initialization vector (IV) affects all following ciphertext blocks."
                    "Decrypting with the incorrect IV causes the first block of plaintext to be corrupt but subsequent plaintext blocks will be correct.This is because each block is XORed with the ciphertext of the previous block, not the plaintext, so one does not need to decrypt the previous block before using it as the IV for the decryption of the current one.This means that a plaintext block can be recovered from two adjacent blocks of ciphertext.As a consequence, decryption can be parallelized.Note that a one - bit change to the ciphertext causes complete corruption of the corresponding block of plaintext, and inverts the corresponding bit in the following block of plaintext, but the rest of the blocks remain intact.This peculiarity is exploited in different padding oracle attacks, such as POODLE.";

    //min 5 bytes of padding means extra 11 to fill a block, the two blocks of 16
    char text[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char assert_text_size[sizeof(text) - 1 == 43];

    memset(iv, '0', sizeof(iv));

    uc8_t enc_out[1024];
    char output[1024];
    int enc_outlen, outputlen;

    aes_cbc_encrypt((uc8_t*)text, strlen(text), (uc8_t*)key, iv, enc_out, &enc_outlen);

    aes_cbc_decrypt(enc_out, enc_outlen, (uc8_t*)key, iv, (uc8_t*)output, &outputlen);

    cout << output << endl;
    cout << strcmp(text, output) << " " << strlen(text) << " " << outputlen << endl;


    uc8_t* data = NULL;
    size_t datasz = 0;

    int used = encryption_oracle((uc8_t*)text2, strlen(text2), &data, &datasz, 0);

    int i, j, found;
    for (i = 0; i + 16 <= used; i += 16)
    {
        uc8_t *block = &data[i];

        for (j = i + 16; j + 16 <= used; j += 16)
        {
            if (0 == memcmp(block, &data[j], 16))
            {
                cout << "found one " << i << " " << j << endl;
                found = 1;
            }
        }
    }

    int counts1[256], counts2[256], counts3[256];

    memset(counts1, 0, sizeof(counts1));
    memset(counts2, 0, sizeof(counts2));
    memset(counts3, 0, sizeof(counts3));

    for (i = 0; i < strlen(text2); i++)
    {
        counts1[text2[i]]++;
    }

    for (i = 0; i < used; i++)
    {
        counts2[data[i]]++;
    }

    used = encryption_oracle((uc8_t*)text2, strlen(text2), &data, &datasz, 1);

    for (i = 0; i < used; i++)
    {
        counts3[data[i]]++;
    }

    for (i = 0; i < 256; i++)
    {
        cout << i << " : | ";
        print_bar(counts1[i]);
        cout << " | ";
        print_bar(counts2[i]);
        cout << " | ";
        print_bar(counts3[i]);
        cout << endl;
    }

    return 0;
}

int chal12_enc(const uc8_t* phrase, const char* append, uc8_t** out, size_t* outsz)
{
    const char* pass = "rK^84de%lF1gW#Di";

    int insznew = strlen((char*)phrase) + (((strlen(append) + 1) * 3) / 4);

    uc8_t* input = NULL;
    size_t inputsz = 0;

    data_buffer_adjust(&input, &inputsz, insznew + 1);

    strcpy((char*)input, (char*)phrase);
    base64tohex((uc8_t*)append, strlen(append), &input[strlen((char*)phrase)], inputsz - strlen((char*)phrase));

    input[insznew] = 0;

    data_buffer_adjust(out, outsz, insznew + 16 + 1);
    memset(*out, 0, *outsz);

    int used = 0;
    aes_ecb_encrypt(input, insznew, (const uc8_t*)pass, *out, &used);

    free(input);

    return used;
}

const char* chal12_data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                        "YnkK";

int call_challenge12()
{

    uc8_t* data = NULL;
    size_t datasz = 0;

    int used;

    /*
    const uc8_t* myphrase = NULL;
    while (1)
    {
        string line;
        cin >> line;
        if (line.compare("q") == 0)
            break;

        myphrase = (const uc8_t*)line.c_str();
        used = chal12_enc(myphrase, add_data, &data, &datasz);

        char printme[1024];
        memset(printme, 0, sizeof(printme));
        bytes_to_hexstring(data, used, (uc8_t*)printme, sizeof(printme));
        cout << printme << endl;
    }
    */

    uc8_t dictionary[16 * 256];

    uc8_t myphrase[16 + 1];
    myphrase[16] = 0;
    uc8_t knowndata[1024];
    memset(knowndata, 0, sizeof(knowndata));

    int knowndatabytes = 0;
    int workingblock;
    int reqpadding;

    int i = 1;
    int end = 0;

    do
    {
        end = 1;
        workingblock = knowndatabytes / 16;
        reqpadding = 16 - 1 - (knowndatabytes % 16);

        //construct dictionary
        memset(myphrase, 'A', 15);
        int takeoffset = 0;
        if (knowndatabytes > 15)
        {
            takeoffset = knowndatabytes - 15;
            memcpy(myphrase, &knowndata[takeoffset], 15);
        }
        else
        {
            int seek = 15 - knowndatabytes;
            memcpy(&myphrase[seek], knowndata, knowndatabytes);
        }


        int j;
        for (j = 1; j <= 0xFF; j++)
        {
            myphrase[15] = j;
            used = chal12_enc(myphrase, chal12_data, &data, &datasz);

            memcpy(&dictionary[j * 16], data, 16);
        }

        if (reqpadding)
        {
            memset(myphrase, 'A', reqpadding);
            myphrase[reqpadding] = 0;
        }
        else
        {
            myphrase[0] = 0;
        }

        used = chal12_enc(myphrase, chal12_data, &data, &datasz);

        for (j = 1; j <= 0xFF; j++)
        {
            if (0 == memcmp(&data[workingblock * 16], &dictionary[j * 16], 16))
            {
                cout << j << " " << (j == '\n' || j == '\r' ? '\\' : (char)j) << " " << used << " " << reqpadding + knowndatabytes + 1 << endl;
                knowndata[knowndatabytes] = j;
                knowndatabytes++;
                end = 0;
            }
        }

        i++;

    } while (used > reqpadding + knowndatabytes);

    unpad_data_buffer(knowndata, knowndatabytes);

    cout << knowndata << endl;

    return 0;
}

static void print_profile(const char *text)
{
    char* local = (char*)malloc(strlen(text));
    if (local == NULL) exit(-1);

    int first = 1;
    cout << "{\n";

    while (1)
    {
        const char* find_equals = strchr(text, '=');
        const char* find_ampersand = strchr(text, '&');

        if (find_equals == NULL)
            break;

        if (find_ampersand == NULL)
            find_ampersand = text + strlen(text);

        if (find_equals < find_ampersand)
        {
            if (first == 0) { cout << ",\n"; }
            else { first = 0; }
            int sz = find_equals - text;
            memcpy(local, text, sz);
            local[sz] = 0;
            cout << "  " << local << ": ";
            sz = find_ampersand - find_equals - 1;
            memcpy(local, find_equals + 1, sz);
            local[sz] = 0;
            cout << "'" << local << "'";
        }

        if (*find_ampersand == 0)
            break;

        text = find_ampersand + 1;
    }

    cout << "\n}\n";

    free(local);
}

static int profile_for(const char *email, char **out, size_t *outsz)
{
    const char* start = "email=";
    const char* end = "&uid=10&role=user";
    const int startsz = strlen(start);
    const int endsz = strlen(end);

    int emailsz = strlen(email);

    const char* find_equals = strchr(email, '=');
    const char* find_ampersand = strchr(email, '&');

    if (find_equals == NULL)
        find_equals = email + emailsz;
    if (find_ampersand == NULL)
        find_ampersand = email + emailsz;
    
    const char* choose = find_equals < find_ampersand ? find_equals : find_ampersand;
    int choosesz = choose - email;

    int newsz = choosesz + startsz + endsz;
    data_buffer_adjust((uc8_t**)out, outsz, newsz + 1);
    memcpy(*out, start, startsz);
    memcpy((*out) + startsz, email, choosesz);
    memcpy((*out) + startsz + choosesz, end, endsz);
    (*out)[newsz] = 0;

    return newsz;
}


const char* chal13_key = "8jHTSi%V35$H7Lzy";

int chal13_prepare(const char* in, uc8_t** out, size_t* outsz)
{
    char* profile = NULL;
    size_t profilesz = 0;

    int used = profile_for(in, &profile, &profilesz);

    int requiredsz = (used + AES_BLOCK_SIZE_BYTES) / AES_BLOCK_SIZE_BYTES;
    requiredsz *= AES_BLOCK_SIZE_BYTES;
    data_buffer_adjust(out, outsz, requiredsz);

    int ercd = aes_ecb_encrypt((uc8_t*)profile, used, (uc8_t*)chal13_key, *out, &used);

    free(profile);

    if (ercd != 0)
        return -1;

    return used;
}

int chal13_result(uc8_t* in, size_t insz)
{
    char* data = NULL;
    size_t datasz = 0;
    data_buffer_adjust((uc8_t**)&data, &datasz, insz + 1);

    int used = 0;
    aes_ecb_decrypt(in, insz, (uc8_t*)chal13_key, (uc8_t*)data, &used);
    data[used] = 0;

    print_profile(data);

    free(data);

    return 0;
}

int call_challenge13()
{
    print_profile("foo=bar&baz=qux&zap=zazzle");

    char* output = NULL;
    size_t outputsz = 0;

    profile_for("foo@bar.com", &output, &outputsz);
    cout << output << endl;
    profile_for("foosneaky@bar.com&role=admin", &output, &outputsz);
    cout << output << endl;
    profile_for("&role=admin", &output, &outputsz);
    cout << output << endl;

    //first get the encrypted blocks containing: email=foo22@bar.com&uid=10&role=
    //then get an encrypted block starting with admin then padding: email=foo2222222admin\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb@bar.com
    //assemble those and see what we get

    uc8_t assemble[AES_BLOCK_SIZE_BYTES * 3];

    chal13_prepare("foo22@bar.com", (uc8_t**)&output, &outputsz);
    memcpy(assemble, output, AES_BLOCK_SIZE_BYTES * 2);

    chal13_prepare("foo2222222admin\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb@bar.com", (uc8_t**)&output, &outputsz);
    memcpy(&assemble[AES_BLOCK_SIZE_BYTES * 2], &output[AES_BLOCK_SIZE_BYTES], AES_BLOCK_SIZE_BYTES);

    chal13_result(assemble, AES_BLOCK_SIZE_BYTES * 3);
    return 0;
}

int chal14_enc(const uc8_t* phrase, int phrasesz, const char* append, uc8_t** out, size_t* outsz)
{
    const char* pass = "jL4%1XfiEQYNDP1S";

    init_random_seed();

    int prefixsz = rand() % 100;

    int insznew = prefixsz + phrasesz + (((strlen(append) + 1) * 3) / 4);

    uc8_t* input = NULL;
    size_t inputsz = 0;

    data_buffer_adjust(&input, &inputsz, insznew + 1);

    uc8_t* dest = input;

    gen_random_key(dest, prefixsz);
    dest += prefixsz;
    memcpy(dest, phrase, phrasesz);
    dest += phrasesz;
    base64tohex((uc8_t*)append, strlen(append), dest, insznew - phrasesz - prefixsz);

    input[insznew] = 0;

    data_buffer_adjust(out, outsz, insznew + 16 + 1);
    memset(*out, 0, *outsz);

    int used = 0;
    aes_ecb_encrypt(input, insznew, (const uc8_t*)pass, *out, &used);

    free(input);

    return used;
}

int chal14_encode_until_pattern_is_visible(const uc8_t* phrase, int phrasesz, const uc8_t* pattern, uc8_t** data, uc8_t** out, size_t* outsz)
{
    int used = 0;
    int found = 0;
    while (!found) {
        used = chal14_enc(phrase, phrasesz, chal12_data, out, outsz);
        int xx;
        uc8_t* search = *out;
        for (xx = 0; xx + 16 <= used; xx += 16, search += 16)
        {
            if (0 == memcmp(search, pattern, 16))
            {
                *data = search + 16;
                used -= xx + 16;
                found = 1;
                break;
            }
        }
    }

    return used;
}

int call_challenge14()
{
    uc8_t* out = NULL;
    size_t outsz = 0;
    int used = 0;

    //we'll play the odds: only the cases where the random-prefix data is a multiple of 16 will be useful to us;
    //we first need to detect how an ecrypted block of all 'A's look like, then use it a s a pattern to discover
    //the useful cases

    uc8_t phrase[AES_BLOCK_SIZE_BYTES * 3 + 1];
    uc8_t pattern[AES_BLOCK_SIZE_BYTES];

    memset(phrase, 'B', AES_BLOCK_SIZE_BYTES * 3);

    used = chal14_enc(phrase, AES_BLOCK_SIZE_BYTES * 3, chal12_data, &out, &outsz);

    //find pattern
    int i, j, found = 0;
    for (i = 0; i + 16 <= used; i += 16)
    {
        uc8_t* block = &out[i];

        if (0 == memcmp(block, &block[16], 16))
        {
            cout << "found pattern at " << i << endl;
            memcpy(pattern, block, AES_BLOCK_SIZE_BYTES);
            found = 1;
            break;
        }
    }

    if (!found) return -100;

    //update: we search for the B x16 block, bu we should make sure that the random data before the block does not contain any Bs
    //I've had thia happen quite frequently (1 in 5-7 runs): random data is not multiple of 16, it has one byte missing and that byte could be B
    //as a result 2-3 dictionary entries are broken, and out of the 256 entries it happened that the letter we searched for was one of them
    //talk about luck; now that is a serious talk!
    memset(phrase, 'C', AES_BLOCK_SIZE_BYTES);

    uc8_t dictionary[16 * 256];
    uc8_t* myphrase = &phrase[AES_BLOCK_SIZE_BYTES*2];
    myphrase[AES_BLOCK_SIZE_BYTES] = 0;
    uc8_t knowndata[1024];
    memset(knowndata, 0, sizeof(knowndata));

    char show[1024];

    memset(show, 0, sizeof(show));
    bytes_to_hexstring(pattern, 16, (uc8_t*)show, sizeof(show));
    cout << "pattern: " << show << endl;

    //we have the pattern which shall be the first block; we will use the second block for decrypting
    int knowndatabytes = 0;
    int workingblock;
    int reqpadding;

    int end = 0;
    i = 0;

    do
    {
        end = 1;
        workingblock = knowndatabytes / 16;
        reqpadding = 16 - 1 - (knowndatabytes % 16);

        //construct dictionary
        memset(myphrase, 'A', 15);
        int takeoffset = 0;
        if (knowndatabytes > 15)
        {
            takeoffset = knowndatabytes - 15;
            memcpy(myphrase, &knowndata[takeoffset], 15);
        }
        else
        {
            int seek = 15 - knowndatabytes;
            memcpy(&myphrase[seek], knowndata, knowndatabytes);
        }

        uc8_t* data = 0;
        for (j = 1; j <= 0xFF; j++)
        {
            if (i == 12 && j == 10)
            {
                cout << "j stop\n";
            }
            myphrase[15] = j;
            used = chal14_encode_until_pattern_is_visible(phrase, 3 * AES_BLOCK_SIZE_BYTES, pattern, &data, &out, &outsz);

            if (i == 12) {/*
                cout << "dict: " << j << " " << phrase << endl;
                memset(show, 0, sizeof(show));
                bytes_to_hexstring(out, outsz, (uc8_t*)show, sizeof(show));
                cout << "  out: " << show << endl;
                memset(show, 0, sizeof(show));
                bytes_to_hexstring(data, used, (uc8_t*)show, sizeof(show));
                cout << "  data: " << show << endl;*/
            }

            memcpy(&dictionary[j * 16], data, 16);
        }

        if (reqpadding)
        {
            memset(myphrase, 'A', reqpadding);
            myphrase[reqpadding] = 0;
        }
        else
        {
            myphrase[0] = 0;
        }

#if 1
        used = chal14_encode_until_pattern_is_visible(phrase, strlen((char*)phrase), pattern, &data, &out, &outsz);
#else  

        found = 0;
        while (!found) {
            used = chal14_enc(phrase, strlen((char*)phrase), chal12_data, &out, &outsz);
            int xx;
            for (xx = 0; xx + 16 <= used; xx += 16)
            {
                data = &out[xx];
                if (0 == memcmp(data, pattern, 16))
                {
                    data += 16;
                    used -= data - out;
                    found = 1;
                    break;
                }
            }
        }
#endif
        if (i == 12) {/*
            cout << endl;
            memset(show, 0, sizeof(show));
            bytes_to_hexstring(out, outsz, (uc8_t*)show, sizeof(show));
            cout << "out: " << show << endl;
            memset(show, 0, sizeof(show));
            bytes_to_hexstring(data, used, (uc8_t*)show, sizeof(show));
            cout << "data: " << show << endl;*/
        }

        for (j = 1; j <= 0xFF; j++)
        {
            if (0 == memcmp(&data[workingblock * 16], &dictionary[j * 16], 16))
            {
                cout << j << " " << (j == '\n' || j == '\r' ? '\\' : (char)j) << " " << used << " " << reqpadding + knowndatabytes + 1 << endl;
                knowndata[knowndatabytes] = j;
                knowndatabytes++;
                end = 0;
            }
        }

        if (end)
        {
            cout << "end\n";
        }
        else
        {
            i++;
        }

    } while (used > reqpadding + knowndatabytes && end == 0);

    unpad_data_buffer(knowndata, knowndatabytes);

    cout << knowndata << endl;

    return 0;
}

int call_challenge15()
{
    char text1[] = "ICE ICE BABY\x04\x04\x04\x04";
    char text2[] = "ICE ICE BABY\x05\x05\x05\x05";
    char text3[] = "ICE ICE BABY\x01\x02\x03\x04";

    unpad_data_buffer((uc8_t*)text1, strlen(text1));
    cout << text1 << endl;
    unpad_data_buffer((uc8_t*)text2, strlen(text2));
    cout << text2 << endl;
    unpad_data_buffer((uc8_t*)text3, strlen(text3));
    cout << text3 << endl;

    return 0;
}

const char* chal16_key = "V9eS!1#xQPZtBo7V";

int chal16_prepare(const char *input, uc8_t **out, size_t *outsz)
{
    const char* prefix = "comment1=cooking%20MCs;userdata=";
    const char* suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    int newsz = strlen(input) + strlen(prefix) + strlen(suffix);

    uc8_t* newin = NULL;
    size_t newinsz = 0;

    data_buffer_adjust(&newin, &newinsz, newsz + 1);

    newin[0] = 0;
    strcat((char*)newin, prefix);
    strcat((char*)newin, input);
    strcat((char*)newin, suffix);

    uc8_t iv[AES_BLOCK_SIZE_BYTES];
    gen_random_key(iv, AES_BLOCK_SIZE_BYTES);

    int outbytes = (newsz + AES_BLOCK_SIZE_BYTES) / AES_BLOCK_SIZE_BYTES;
    outbytes *= AES_BLOCK_SIZE_BYTES;
    outbytes += AES_BLOCK_SIZE_BYTES; //for iv

    data_buffer_adjust(out, outsz, outbytes);
    memcpy(*out, iv, AES_BLOCK_SIZE_BYTES);

    int used;
    aes_cbc_encrypt(newin, newsz, (uc8_t*)chal16_key, iv, (*out)+AES_BLOCK_SIZE_BYTES, &used);

    free(newin);

    return used + AES_BLOCK_SIZE_BYTES;
}

int chal16_show(const char* input, int inputsz)
{
    char* out = NULL;
    size_t outsz = 0;

    data_buffer_adjust((uc8_t**)&out, &outsz, inputsz +1);
    memset(out, 0, outsz);

    int used = 0;
    aes_cbc_decrypt((uc8_t*)&input[AES_BLOCK_SIZE_BYTES], inputsz-AES_BLOCK_SIZE_BYTES, (uc8_t*)chal16_key, (uc8_t*)input, (uc8_t*)out, &used);

    cout << out << endl;

    free(out);

    return used;
}

int call_challenge16()
{
    //we want to have this decrypted text: bbbbbbbbbbbbbbbbaaaaa;admin=true
    uc8_t prep[AES_BLOCK_SIZE_BYTES * 2 + 1];
    memcpy(prep, "bbbbbbbbbbbbbbbbaaaaa;admin=true", sizeof(prep));

    uc8_t mod[AES_BLOCK_SIZE_BYTES];
    memset(mod, 0, sizeof(mod));

    char* t = strchr((char*)prep, ';');
    *t ^= 0x10;
    mod[t - (char*)prep - AES_BLOCK_SIZE_BYTES] = 0x10;
    t = strchr((char*)prep, '=');
    *t ^= 0x10;
    mod[t - (char*)prep - AES_BLOCK_SIZE_BYTES] = 0x10;


    uc8_t* data = NULL;
    size_t datasz = 0;

    int used = chal16_prepare((char*)prep, &data, &datasz);

    xor_fixed(&data[AES_BLOCK_SIZE_BYTES * 3], mod, &data[AES_BLOCK_SIZE_BYTES * 3], AES_BLOCK_SIZE_BYTES);

    chal16_show((char*)data, used);

    return 0;
}