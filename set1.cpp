
#include "hextobase64.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <fstream>

using std::string;
using std::cin;
using std::cout;
using std::endl;

int call_challenge1();
int call_challenge2();
int call_challenge3();
int call_challenge4();
int call_challenge5();
int call_challenge6();
int call_challenge7();
int call_challenge8();

int call_set1()
{
    int retcode = 0;
    std::cout << "This is Set 1\n";

    retcode = call_challenge8();

    return retcode;
}

int call_challenge1()
{
    //test hextobase64
    std::string input;
    std::cin >> input;

    int insize = input.length() / 2;
    int outsize = ((insize + 2) / 3) * 4;
    unsigned char* true_input = (unsigned char*)malloc(insize + 1);
    unsigned char* output = (unsigned char*)malloc(outsize + 1);
    if ((output == NULL) || (true_input == NULL)) exit(-1);


    memset(true_input, 0, insize + 1);
    memset(output, 0, outsize + 1);

    const char* in_buf = input.c_str();

    hexstring_to_bytes(input.c_str(), input.length(), true_input, insize);

    hextobase64((const unsigned char*)true_input, insize, output, outsize);

    std::cout << std::endl;
    std::cout << output;

    return 0;
}

int call_challenge2()
{
    std::string input1, input2;

    std::cin >> input1;
    std::cin >> input2;

    int insz1 = input1.length() / 2, insz2 = input2.length() / 2;

    unsigned char* in1 = (unsigned char*)malloc(insz1 + 1);
    unsigned char* in2 = (unsigned char*)malloc(insz2 + 1);
    if (in1 == NULL || in2 == NULL) exit(-1);

    memset(in1, 0, insz1 + 1);
    memset(in2, 0, insz2 + 1);

    hexstring_to_bytes(input1.c_str(), input1.length(), in1, insz1);
    hexstring_to_bytes(input2.c_str(), input2.length(), in2, insz2);

    int insz = insz1 < insz2 ? insz1 : insz2;
    xor_fixed(in1, in2, in2, insz1);

    unsigned char* out = (unsigned char*)malloc(insz2 * 2 + 1);
    if (out == NULL) return -1;

    memset(out, 0, insz * 2 + 1);
    bytes_to_hexstring(in2, insz1, out, insz2 * 2);


    std::cout << out;

    return 0;
}

int call_challenge3()
{
    std::string input;
    std::cin >> input;

    int insize = input.length() / 2;
    unsigned char* true_input = (unsigned char*)malloc(insize + 1);
    if (true_input == NULL) exit(-1);

    memset(true_input, 0, insize + 1);

    hexstring_to_bytes(input.c_str(), input.length(), true_input, insize);

    unsigned char* cypher = (unsigned char*)malloc(insize + 1);
    if (cypher == NULL) exit(-1);

    memset(cypher, 0, insize + 1);

    character_frequency_table_init();

    float found = 1000.0f;
    int i = 0xff;
    while (i >= 0)
    {
        memset(cypher, i, insize);
        xor_fixed(true_input, cypher, cypher, insize);
        float t = character_frequency_calculate(cypher, insize);

        if (t < found)
        {
            found = t;
            std::cout << t << " " << i << " ";
            std::cout << cypher;
            std::cout << std::endl;
        }
        i--;
    }

    return 0;
}

void manage_my_input_memory(unsigned char** memory, size_t * allocatedsz, size_t newsize)
{

    if (newsize + 1 > *allocatedsz)
    {
        if (*memory == NULL)
        {
            *memory = (unsigned char*)malloc(newsize + 1);
            if (*memory == NULL) exit(-1);
        }
        else
        {
            unsigned char* t = (unsigned char*)realloc(*memory, newsize + 1);
            if (t == NULL) exit(-1);
            *memory = t;
        }
        *allocatedsz = newsize + 1;
    }
}

int call_challenge4()
{
    unsigned char* true_line = NULL, *cypher = NULL, *backup = NULL;
    size_t linesz = 0, cyphersz = 0, backupsz = 0;
    float backupratio = 1000.0f;
    std::fstream xor_file;

    xor_file.open("challenge4.txt", std::ios::in);

    if (xor_file.is_open()) {
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {
            
            manage_my_input_memory(&true_line, &linesz, sa.length() / 2);
            manage_my_input_memory(&cypher, &cyphersz, sa.length() / 2);
            manage_my_input_memory(&backup, &backupsz, sa.length() / 2);

            memset(cypher, 0, cyphersz);
            memset(backup, 0, backupsz);

            hexstring_to_bytes(sa.c_str(), sa.length(), true_line, sa.length() / 2);

            character_frequency_table_init();

            int i = 0xff;
            while (i >= 0)
            {
                memset(cypher, i, cyphersz -1);
                xor_fixed(true_line, cypher, cypher, sa.length() / 2);
                float t = character_frequency_calculate(cypher, sa.length() / 2);

                if (t < backupratio)
                {
                    backupratio = t;
                    strcpy((char*)backup, (char*)cypher);

                    std::cout << backupratio << " ";
                    std::cout << backup;
                    std::cout << std::endl;
                }
                i--;
            }

        }

        // Close the file object.
        xor_file.close();
    }

    return 0;
}

int call_challenge5()
{
    const char* phrase = "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    const char* key = "ICE";

    int phrasesz = strlen(phrase);
    int keysz = strlen(key);

    size_t ressz = 0;
    unsigned char* result = NULL;
    manage_my_input_memory(&result, &ressz, phrasesz);

    result[ressz - 1] = 0;

    xor_key((uc8_t*)phrase, phrasesz, (uc8_t*)key, keysz, result, ressz);

    int i = 0, j = 0;
    while (i < phrasesz)
    {
        result[i] = phrase[i] ^ key[j];
        i++;
        j++;
        if (j >= keysz) j = 0;
    }

    size_t res2sz = 0;
    unsigned char* result2 = NULL;
    manage_my_input_memory(&result2, &res2sz, phrasesz*2);

    bytes_to_hexstring(result, ressz, result2, res2sz);

    result2[res2sz - 1] = 0;

    cout << result << endl;
    cout << result2 << endl;

    return 0;
}


unsigned char find_most_likely_xorkey(unsigned char *text, size_t textsz)
{
    unsigned char* xortbl = NULL;
    size_t xortblsz = 0;

    manage_my_input_memory(&xortbl, &xortblsz, textsz);

    float foundratio = 100.0f;
    uc8_t found = 0;

    int i = 0xff;
    while (i >= 0)
    {
        memset(xortbl, i, xortblsz);
        xor_fixed(text, xortbl, xortbl, textsz);
        float t = character_frequency_calculate(xortbl, xortblsz);

        if (t < foundratio)
        {
            foundratio = t;
            found = i;
        }
        i--;
    }

    free(xortbl);

    return found;
}

int call_challenge6()
{
    char first[] = "this is a test";
    char second[] = "wokka wokka!!!";
    char firstmod[sizeof(first)];
    char secondmod[sizeof(second)];

    cout << "hammingdist " << calc_hamming_distance_sc8(first, second, sizeof(first) - 1) << endl;

    char key[] = "ICE";
    xor_key_sc8(first, sizeof(first) - 1, key, sizeof(key) - 1, firstmod, sizeof(firstmod));
    xor_key_sc8(second, sizeof(second) - 1, key, sizeof(key) - 1, secondmod, sizeof(secondmod));

    cout << "hammingdist mod " << calc_hamming_distance_sc8(firstmod, secondmod, sizeof(firstmod) - 1) << endl;

    //read file in memory
    unsigned char* data = NULL;
    size_t datasz = 0, used = 0;
    unsigned char* scratch = NULL;
    size_t scratchsz = 0;

    std::fstream xor_file;

    xor_file.open("challenge6.txt", std::ios::in);

    if (xor_file.is_open()) {
        int count = 0;
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {

            count++;

            size_t size = sa.length();

            manage_my_input_memory(&data, &datasz, used + size);
            data[datasz - 1] = 0;

            used += base64tohex((uc8_t*)sa.c_str(), size, &data[used], datasz - used);
            data[used] = 0;

        }

        // Close the file object.
        xor_file.close();
    }

    if (data == NULL) exit(-1);

    int keysz = 2, maxkeysize = 40;
    float diff = 10.0;
    int found;
    while (keysz <= maxkeysize)
    {
        int distance = 0;
        int offset = 1;
        int steps = 0;
        while (offset * keysz + keysz < used)
        {
            distance += hamming_distance_calculate(&data[0], &data[offset * keysz], keysz);
            offset++;
            steps++;
        }

        //cout << "keysize " << keysz << " hamming val" << (float)distance/(steps*keysz) << endl;

        if (diff > (float)distance / (steps * keysz))
        {
            diff = (float)distance / (steps * keysz);
            found = keysz;
        }

        keysz++;
    }

    //found = 29;

    //for (found = 0; found < maxkeysize; found++)
    //{
        cout << "keysize " << found << " hamming " << diff << endl;

        int blksz = (used + found - 1) / found;

        uc8_t* key2 = NULL; size_t key2sz = 0;
        manage_my_input_memory(&key2, &key2sz, found);
        memset(key2, 0, key2sz);
        manage_my_input_memory(&scratch, &scratchsz, blksz);
        character_frequency_table_init();

        int i = 0, j = 0, k = 0;
        while (k < found)
        {
            i = k; j = 0;
            while (i < used)
            {
                scratch[j] = data[i];
                i += found;
                j++;
            }

            key2[k] = find_most_likely_xorkey(scratch, j);
            k++;
        }

        cout << "key step " << key2 << endl;
    //}

    xor_key(data, used, key2, found, data, datasz);

    cout << endl << data;

    return 0;
}

#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/crypto.h"
#include "openssl/core_names.h"

int call_challenge7()
{
    //read file in memory
    unsigned char* data = NULL;
    size_t datasz = 0, used = 0;

    std::fstream xor_file;

    xor_file.open("challenge7.txt", std::ios::in);

    if (xor_file.is_open()) {
        int count = 0;
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {

            count++;

            size_t size = sa.length();

            manage_my_input_memory(&data, &datasz, used + size);
            data[datasz - 1] = 0;

            used += base64tohex((uc8_t*)sa.c_str(), size, &data[used], datasz - used);
            data[used] = 0;

        }

        // Close the file object.
        xor_file.close();
    }

    if (data == NULL) exit(-1);

    const unsigned char key[] = "YELLOW SUBMARINE";
    uc8_t* outbuf = NULL;
    size_t outbufsz = 0;
    manage_my_input_memory(&outbuf, &outbufsz, used + 128);
    memset(outbuf, 0, outbufsz);
    int outlen = 0, tmplen = 0;

    OSSL_LIB_CTX* libctx = NULL;

    EVP_CIPHER_CTX* ctx;
    EVP_CIPHER* cipher = NULL;

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-128-ECB", NULL)) == NULL)
        goto err;

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    if (!EVP_DecryptInit_ex2(ctx, cipher, key, /* iv */ NULL, /* params */ NULL))
        goto err;

    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, data, used))
        goto err;

    /* Finalise: there can be some additional output from padding */
    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen))
        goto err;
    outlen += tmplen;

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    cout << outbuf << endl;

    return 0;
err:
    return -2;
}

static int encrypt(const uc8_t* in, size_t insz, const uc8_t* key, uc8_t* output, int *outlen, OSSL_LIB_CTX** libctx)
{
    EVP_CIPHER_CTX* ctx;
    EVP_CIPHER* cipher = NULL;

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        return -2;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(*libctx, "AES-128-ECB", NULL)) == NULL)
        return -2;

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, /*iv*/NULL, /* params */ NULL))
        return -2;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, output, outlen, in, insz))
        return -2;

    int tmplen = 0;
    /* Finalise: there can be some additional output from padding */
    if (!EVP_EncryptFinal_ex(ctx, output + *outlen, &tmplen))
        return -2;
    *outlen += tmplen;

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int call_challenge8()
{
    OSSL_LIB_CTX* libctx = NULL;

    const unsigned char key[] = "YELLOW SUBMARINE";

    const unsigned char text1[] = "qrstuvwxyz012345";
    unsigned char text2[]       = "abcdefghijklmnop";
    const uc8_t text3[] = "1234567890123456abcdefghijklmnop";

    unsigned char output[1024];
    unsigned char output2[1024];
    unsigned char outputscreen[1024];
    memset(output, 0, sizeof(output));
    memset(outputscreen, 0, sizeof(outputscreen));
    int outlen = 0, outlen2 = 0;


    encrypt(text1, strlen((char*)text1), key, output, &outlen, &libctx);

    bytes_to_hexstring(output, outlen, outputscreen, sizeof(outputscreen) - 1);

    cout << outputscreen << endl;

    memset(output2, 0, sizeof(output2));
    memset(outputscreen, 0, sizeof(outputscreen));
    outlen2 = 0;

    encrypt(text2, strlen((char*)text2), key, output2, &outlen2, &libctx);

    bytes_to_hexstring(output2, outlen2, outputscreen, sizeof(outputscreen) - 1);

    cout << outputscreen << endl;

    int i = 0, j;

    cout << "step " << i << " dist " << hamming_distance_calculate(output, output2, outlen) << endl;

    int offset = 4;
    const uc8_t sim[] = "uvwxyz0";
    for (i = 1; i < sizeof(sim); i++)
    {
        memset(output2, 0, sizeof(output2));
        memset(outputscreen, 0, sizeof(outputscreen));
        outlen2 = 0;

        memcpy(&text2[offset], sim, i);

        encrypt(text2, strlen((char*)text2), key, output2, &outlen2, &libctx);

        cout << "step " << i << " dist " << hamming_distance_calculate(output, output2, outlen) << endl;
    }

    cout << text1 << endl << text2 << endl;

    //return 0;

    //read file in memory
    unsigned char* data = NULL;
    size_t datasz = 0, used = 0;

    uc8_t block[16];
    int found = 0;

    std::fstream xor_file;

    xor_file.open("challenge8.txt", std::ios::in);

    if (xor_file.is_open()) {
        int count = 0;
        string sa;
        // Read data from the file object and put it into a string.
        while (std::getline(xor_file, sa)) {

            count++;
            found = 0;

            size_t size = sa.length();

            manage_my_input_memory(&data, &datasz, size / 2);
            data[datasz - 1] = 0;

            used = hexstring_to_bytes(sa.c_str(), size, data, size / 2);
            data[used] = 0;

            for (i = 0; i + 16 <= size / 2; i += 16)
            {
                memcpy(block, &data[i], 16);

                for (j = i + 16; j + 16 <= size / 2; j += 16)
                {
                    if (0 == memcmp(block, &data[j], 16))
                    {
                        cout << "found one " << count << " " << i << " " << j << endl;
                        found = 1;
                    }
                }
            }

            if (found)
            {
                //hmm
            }
        }

        // Close the file object.
        xor_file.close();
    }

    return 0;
}

