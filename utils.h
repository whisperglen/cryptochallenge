#pragma once

typedef unsigned char uc8_t;
typedef char sc8_t;

#define xor_key_sc8(A, ASZ, B, BSZ, C, CSZ) xor_key((uc8_t*)(A), (ASZ), (uc8_t*)(B), (BSZ), (uc8_t*)(C), CSZ)
#define calc_hamming_distance_sc8(A, B, SZ) hamming_distance_calculate((uc8_t*)(A), (uc8_t*)(B), SZ)

int istext(int val);

unsigned int chartoi(char c);

int hexstring_to_bytes(const char* in, size_t insz, unsigned char* out, size_t outsz);
int bytes_to_hexstring(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz);

int xor_fixed(const unsigned char* first, const unsigned char* second, unsigned char* out, size_t sz);
int xor_key(const unsigned char* phrase, size_t phrasesz, const unsigned char* key, size_t keysz, unsigned char* out, size_t outsz);

void character_frequency_table_init();
float character_frequency_calculate(const unsigned char* input, size_t insz);

int hamming_distance_calculate(const unsigned char* first, const unsigned char* second, size_t sz);

void data_buffer_adjust(uc8_t** memory, size_t* allocatedsz, size_t newsize);

void random_seed_init();
void random_keygen(uc8_t* out, int size);

typedef struct MEMBUF
{
	uc8_t* data;
	size_t size;
	size_t used;
} membuf;

#define MEMBUF_INITIALISER {NULL,0,0}

void membuf_init(membuf* mb);
void membuf_clear(membuf* mb);
void membuf_adjust_size(membuf* mb, size_t newsize);
void membuf_free(membuf* mb);
void membuf_copy(membuf* dst, membuf* src);
void membuf_append_byte_auto(membuf* mb, uc8_t value);
void membuf_append_data_auto(membuf* mb, uc8_t* data, size_t sz);
void membuf_prepend_byte_auto(membuf* mb, uc8_t value);
void membuf_yield(membuf* mb, uc8_t** recipient);

size_t pad_data_buffer(uc8_t** memory, size_t* memsz, size_t used_size, size_t block_size);
size_t unpad_data_buffer(uc8_t* data, size_t used_size);