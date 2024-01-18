
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <iostream>
#include <time.h>

int istext_r(int val)
{
    return isalnum(val) || isspace(val) || val == ',' ||
        val == '!' || val == '-' || val == '.' || val == ';';
}

int istext(int val)
{
    return isalnum(val) || isspace(val) || ispunct(val);
}

unsigned int chartoi(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 0xa;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 0xa;
    }
    return 0;
}

unsigned char itochar(int c)
{
    if (c >= 0 && c <= 9)
    {
        return c + '0';
    }
    if (c >= 0xa && c <= 0xf)
    {
        return c - 0xa + 'a';
    }
    return 0;
}

int hexstring_to_bytes(const char* in, size_t insz, unsigned char* out, size_t outsz)
{
    int i = 0;

    while (i < outsz && 2*i+1 < insz)
    {
        if (in[i] == 0) break;

        out[i] = (chartoi(in[2 * i]) << 4) + chartoi(in[2 * i + 1]);
        i++;
    }

    return i;
}

int bytes_to_hexstring(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz)
{
    int i = 0;

    while (2 * i + 1 < outsz && i < insz)
    {
        out[2 * i] = itochar(in[i] >> 4);
        out[2 * i + 1] = itochar(in[i] & 0xf);
        i++;
    }

    return i;
}

int xor_fixed(const unsigned char* first, const unsigned char* second, unsigned char* out, size_t sz)
{
    int i = 0;

    while (i < sz)
    {
        out[i] = first[i] ^ second[i];
        i++;
    }

    return i;
}

int xor_key(const unsigned char* phrase, size_t phrasesz, const unsigned char* key, size_t keysz, unsigned char* out, size_t outsz)
{
    int i = 0, j = 0;
    size_t limit = phrasesz < outsz ? phrasesz : outsz;

    while (i < limit)
    {
        out[i] = phrase[i] ^ key[j];
        i++;
        j++;
        if (j >= keysz) j = 0;
    }

    return i;
}

static float en_freq_tbl[256];

void character_frequency_table_init()
{
    memset(en_freq_tbl, 0, sizeof(en_freq_tbl));

    const char text[] = "the cryptopals crypto challenges"
        "Challenges Set 1 Challenge 3"
        "Single - byte XOR cipher"
        "The hex encoded string :"
        "... has been XOR'd against a single character. Find the key, decrypt the message."
        "You can do this by hand.But don't: write code to do it for you."
        "How ? Devise some method for \"scoring\" a piece of English plaintext.Character frequency is a good metric.Evaluate each output and choose the one with the best score."
        "Achievement Unlocked"
        "You now have our permission to make \"ETAOIN SHRDLU\" jokes on Twitter."
        "Cryptography Services | NCC Group";

    int i = 0;
#if 1
    const float increment = 1.0f / (sizeof(text) - 1);
    while (i < sizeof(text) - 1)
    {
        int a = tolower(text[i]);

        en_freq_tbl[a] += increment;

        i++;
    }
#endif

#if 0
    en_freq_tbl['a'] = 0.08167f;
    en_freq_tbl['b'] = 0.01492f;
    en_freq_tbl['c'] = 0.02782f;
    en_freq_tbl['d'] = 0.04253f;
    en_freq_tbl['e'] = 0.12702f;
    en_freq_tbl['f'] = 0.02228f;
    en_freq_tbl['g'] = 0.02015f;
    en_freq_tbl['h'] = 0.06094f;
    en_freq_tbl['i'] = 0.06966f;
    en_freq_tbl['j'] = 0.00153f;
    en_freq_tbl['k'] = 0.00772f;
    en_freq_tbl['l'] = 0.04025f;
    en_freq_tbl['m'] = 0.02406f;
    en_freq_tbl['n'] = 0.06749f;
    en_freq_tbl['o'] = 0.07507f;
    en_freq_tbl['p'] = 0.01929f;
    en_freq_tbl['q'] = 0.00095f;
    en_freq_tbl['r'] = 0.05987f;
    en_freq_tbl['s'] = 0.06327f;
    en_freq_tbl['t'] = 0.09056f;
    en_freq_tbl['u'] = 0.02758f;
    en_freq_tbl['v'] = 0.00978f;
    en_freq_tbl['w'] = 0.02360f;
    en_freq_tbl['x'] = 0.00150f;
    en_freq_tbl['y'] = 0.01974f;
    en_freq_tbl['z'] = 0.00074f;
#endif

#if 0
    std::cout << "\nFrequency table english text\n";
    float xx = 0;
    i = 0;
    while (i < sizeof(en_freq_tbl)/ sizeof(en_freq_tbl[0]))
    {
        float val = en_freq_tbl[i];
        if (val)
        {
            xx += val;
            std::cout << (char)i << ": " << val << std::endl;
        }

        i++;
    }
    std::cout << "totals: " << xx << std::endl;
#endif
}

float character_frequency_calculate(const unsigned char* input, size_t insz)
{
    float *local_tbl = (float*)malloc(sizeof(en_freq_tbl));
    if (local_tbl == NULL) return -1;

    memset(local_tbl, 0, sizeof(en_freq_tbl));

    const float increment = 1.0f / insz;
    int i = 0;
    while (i < insz)
    {
        local_tbl[tolower(input[i])] += increment;

        i++;
    }

#if 0
    std::cout << "\nFrequency table NEW text\n";
    float xx = 0;
    i = 0;
    while (i < sizeof(en_freq_tbl) / sizeof(en_freq_tbl[0]))
    {
        float val = local_tbl[i];
        if (val != 0.0f)
        {
            xx += val;
            std::cout << (char)i << ": " << val << std::endl;
        }

        i++;
    }
    std::cout << "totals: " << xx << std::endl;
#endif

    float count = 0;

    i = sizeof(en_freq_tbl)/sizeof(en_freq_tbl[0]) -1;
    while (i >= 0)
    {
        if (/*en_freq_tbl[i] != 0 &&*/ local_tbl[i] != 0.0f)
        {
            count += fabs(en_freq_tbl[i] - local_tbl[i]);
        }
        i--;
    }

    free(local_tbl);

    return count;
}

int hamming_distance_calculate(const unsigned char* first, const unsigned char* second, size_t sz)
{
    int ret = 0;

    int i = 0;

    while (i < sz)
    {
        unsigned int val = first[i] ^ second[i];
        i++;

        int j;
        for(j = 0; j < 8; j++)
        {
            unsigned int bitval = val & 1;
            val = val >> 1;

            if (bitval) ret++;
        }
    }

    return ret;
}

void data_buffer_adjust(uc8_t ** memory, size_t* allocatedsz, size_t newsize)
{
    if (newsize > *allocatedsz)
    {
        if (*memory == NULL)
        {
            *memory = (uc8_t*)malloc(newsize);
            if (*memory == NULL) exit(-1);
        }
        else
        {
            uc8_t * t = (uc8_t*)realloc(*memory, newsize);
            if (t == NULL) exit(-1);
            *memory = t;
        }
        *allocatedsz = newsize;
    }
}

void random_seed_init()
{
    static int initialised = 0;
    if (initialised == 0)
    {
        unsigned int seed = (unsigned int)time(NULL);
        srand(seed);
        initialised = 1;
        std::cout << "seed: " << seed << std::endl;
    }
}

void random_keygen(uc8_t* out, int size)
{
    random_seed_init();

    int i;
    for (i = 0; i < size; i++)
    {
        out[i] = rand() % 0xFF + 1;
    }
}

void membuf_init(membuf* mb)
{
    mb->data = NULL;
    mb->size = 0;
    mb->used = 0;
}

void membuf_adjust_size(membuf* mb, size_t newsize)
{
    if (newsize > mb->size)
    {
        if (mb->data == NULL)
        {
            mb->data = (uc8_t*)malloc(newsize);
            if (mb->data == NULL) exit(-1);
        }
        else
        {
            uc8_t* t = (uc8_t*)realloc(mb->data, newsize);
            if (t == NULL) exit(-1);
            mb->data = t;
        }
        mb->size = newsize;
    }
}

void membuf_yield(membuf* mb, uc8_t **recipient)
{
    if (mb->data && recipient)
    {
        *recipient = mb->data;
        mb->data = NULL;
    }
    mb->size = 0;
    mb->used = 0;
}

void membuf_free(membuf* mb)
{
    if (mb->data)
    {
        free(mb->data);
        mb->data = NULL;
    }
    mb->size = 0;
    mb->used = 0;
}

void membuf_clear(membuf* mb)
{
    mb->used = 0;
}

void membuf_copy(membuf* dst, membuf* src)
{
    size_t size = dst->size < src->used ? dst->size : src->used;

    memcpy(dst->data, src->data, size);
    dst->used = size;
}

void membuf_copy_auto(membuf* dst, membuf* src)
{
    membuf_adjust_size(dst, src->used);
    membuf_copy(dst, src);
}

void membuf_append_byte_auto(membuf* mb, uc8_t value)
{
    int used = mb->used;
    if (used + 1 > mb->size)
        membuf_adjust_size(mb, used + 1);

    mb->data[used] = value;
    mb->used++;
}

void membuf_append_data_auto(membuf* mb, uc8_t *data, size_t sz)
{
    int used = mb->used;
    if (used + sz > mb->size)
        membuf_adjust_size(mb, used + sz);

    memcpy(&(mb->data[used]), data, sz);
    mb->used += sz;
}

void membuf_prepend_byte_auto(membuf* mb, uc8_t value)
{
    int used = mb->used;
    if (used + 1 > mb->size)
        membuf_adjust_size(mb, used + 1);

    uc8_t* tmp = &mb->data[used];
    for (int i = 0; i < used; i++, tmp--)
    {
        *tmp = *(tmp - 1);
    }

    mb->data[0] = value;
    mb->used++;
}

size_t pad_data_buffer(uc8_t** memory, size_t* memsz, size_t used_size, size_t block_size)
{
    size_t requiredsz = (used_size + block_size) / block_size;
    requiredsz *= block_size;

    data_buffer_adjust(memory, memsz, requiredsz);

    int padval = requiredsz - used_size;

    if (padval < requiredsz)
        memset(&(*memory)[used_size], padval, padval);

    return requiredsz;
}

size_t unpad_data_buffer(uc8_t* data, size_t used_size)
{
    size_t ret = used_size;

    uc8_t* iter = &data[used_size - 1];
    int padval = *iter;

    if (padval >= used_size)
        return -1;

    int found = 1;
    iter--;

    int i;
    for (i = 1; i < padval; i++, iter--)
    {
        if (*iter == padval)
            found++;
    }

    if (found != padval)
    {
        //std::cout << "problem with padding " << found << " " << padval << std::endl;
        ret = -2;
    }
    else
    {
        iter[1] = 0;
        ret -= padval;
    }

    return ret;
}