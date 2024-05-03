
#include "utils.h"
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "bignum.h"
//#include <cassert>

using std::string;
using std::cin;
using std::cout;
using std::endl;

static int tests_total = 0;
static int tests_ok = 0;

static void xassert_str(int success, const char* expression, const char* function, unsigned line, const char* file)
{
	tests_total++;
	if (success) tests_ok++;
	else
	{
		const char* fn = strrchr(file, '\\');
		if (!fn) fn = strrchr(file, '/');
		if (!fn) fn = "fnf";

		cout << "assert failed: " << expression << " in " << function << ":" << line << " " << fn << endl;
	}
}

static void xassert_int(int success, int printval, const char* function, unsigned line, const char* file)
{
	tests_total++;
	if (success) tests_ok++;
	else
	{
		const char* fn = strrchr(file, '\\');
		if (!fn) fn = strrchr(file, '/');
		if (!fn) fn = "fnf";

		cout << "assert failed: " << std::hex << printval << std::dec << " in " << function << ":" << line << " " << fn << endl;
	}
}

#define assertx(expression) (void)(                                                             \
            (xassert_str((!!(expression)), _CRT_STRINGIZE(#expression), (__func__), (unsigned)(__LINE__), (__FILE__)), 0) \
        )


#define assertxiter(expression, iter) (void)(                                                             \
            (xassert_int((!!(expression)), (iter), (__func__), (unsigned)(__LINE__), (__FILE__)), 0) \
        )


static int run_base64_tests()
{
	assertx(base64_dec_bufsz(2) >= 1);
	assertx(base64_dec_bufsz(3) >= 2);
	assertx(base64_dec_bufsz(4) >= 3);

	assertx(base64_enc_bufsz(3) >= 4);
	assertx(base64_enc_bufsz(2) >= 4);
	assertx(base64_enc_bufsz(1) >= 4);

	const char* in, *out;

	char local[9];
	size_t localsz = 4;
	int used;

	in = "Man";
	out = "TWFu";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	in = "Ma";
	out = "TWE=";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	in = "M";
	out = "TQ==";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	localsz = 8;

	in = "xYzMan";
	out = "eFl6TWFu";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	in = "xYzMa";
	out = "eFl6TWE=";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	in = "xYzM";
	out = "eFl6TQ==";

	memset(local, 0, sizeof(local));
	used = hextobase64((uc8_t*)in, strlen(in), (uc8_t*)local, localsz);
	assertx(0 == strcmp(out, local));
	assertx(strlen(out) == used);

	memset(local, 0, sizeof(local));
	used = base64tohex((uc8_t*)out, strlen(out), (uc8_t*)local, localsz);
	assertx(0 == strcmp(in, local));
	assertx(strlen(in) == used);

	return 0;
}

static int run_aes_tests()
{
	assertx(aes_encode_bufsz(0) == AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(1) == AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(AES_BLOCK_SIZE_BYTES/2) == AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(AES_BLOCK_SIZE_BYTES-1) == AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(AES_BLOCK_SIZE_BYTES) == 2*AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(AES_BLOCK_SIZE_BYTES+1) == 2 * AES_BLOCK_SIZE_BYTES);

	assertx(aes_encode_bufsz(13 * AES_BLOCK_SIZE_BYTES) == 14 * AES_BLOCK_SIZE_BYTES);
	assertx(aes_encode_bufsz(13 * AES_BLOCK_SIZE_BYTES + 7) == 14 * AES_BLOCK_SIZE_BYTES);

	return 0;
}

static int run_utils_tests()
{
	assertx(! istext_r(0));
	assertx(! istext_r(1));
	assertx(istext_r(' '));
	assertx(istext_r('!'));
	assertx(istext_r(','));
	assertx(istext_r('.'));
	assertx(istext_r(0xa));
	assertx(istext_r(0xd));
	assertx(istext_r('-'));
#if 1
	assertx(istext('('));
	assertx(istext('+'));
	assertx(istext('@'));
	assertx(istext('#'));
	assertx(istext('%'));
	assertx(istext('^'));
	assertx(istext('&'));
	assertx(istext('*'));
	assertx(istext('"'));
	assertx(istext('|'));
	assertx(istext('\\'));
	assertx(istext('/'));
	assertx(istext('>'));
	assertx(istext('~'));
	assertx(istext('`'));
	assertx(istext('\''));
#endif

#if 0
	char someText[10];
	char hexText[19];
	hexText[18] = 0;
	someText[9] = 0;
	for (int i = 0; i < 20; i++)
	{
		random_text((uc8_t*)someText, 9);
		bytes_to_hexstring((uc8_t*)someText, 9, (uc8_t*)hexText, 18);
		cout << someText << " <-> " << hexText << endl;
	}
#endif
#if 0
	char txt[3] = { 0,0,0 };
	for (int i = 0; i <= 0xFF; i++)
	{
		bytes_to_hexstring((uc8_t*)&i, 1, (uc8_t*)txt, 2);
		cout << txt << " " << (isspace(i) ? "s" : "") << (ispunct(i) ? "p" : "") << (isalnum(i) ? "a" : "") << (isprint(i) ? "r" : "") << endl;
	}
	uc8_t bytes[0x100];
	for (int i = 0; i <= 0xFF; i++)
	{
		bytes[i] = (uc8_t)i;
	}
	char converted[0x100 * 2 + 1];
	memset(converted, 0, sizeof converted);
	bytes_to_hexstring(bytes, sizeof bytes, (uc8_t*)converted, 0x100 * 2);
	cout << converted << endl;
#endif

	return 0;
}

static int run_mt19937_tests()
{
	mt19937_seed(1705044000);
	mt19937_gen();

	return 0;
}

static uint32_t assemble_one(uint32_t store, uint32_t val, uint32_t vsz)
{
	uint32_t mask = 0;
	uint32_t shift = 0;
	for (int i = vsz; i > 0; i--)
	{
		shift += 4;
		mask <<= 4;
		mask += 0xF;
	}
	return (store << shift) + (val & mask);
}

/** combine 2 or more numbers in a sigle value to be printed as hex
 * size represents number of nibbles
 */
static uint32_t assemble_vals(uint32_t a, uint32_t b, uint32_t asz, uint32_t bsz)
{
	uint32_t result = 0;
	result = assemble_one(result, a, asz);
	result = assemble_one(result, b, bsz);
	return result;
}

static int run_bignum_tests()
{
	membuf bn = MEMBUF_INITIALISER;

	bnum_from_int(&bn, 0);
	assertx(bnum_to_int(&bn) == 0);
	bnum_from_int(&bn, 185);
	assertx(bnum_to_int(&bn) == 185);
	bnum_from_int(&bn, 43763456);
	assertx(bnum_to_int(&bn) == 43763456);
	bnum_from_int(&bn, -1000);
	assertx(bnum_to_int(&bn) == -1000);

	bnum_from_chars(&bn, "-1000", 10);
	assertx(bnum_to_int(&bn) == -1000);
	bnum_from_chars(&bn, "1000", 10);
	assertx(bnum_to_int(&bn) == 1000);

	bnum_from_chars(&bn, "-1000", 16);
	assertx(bnum_to_int(&bn) == -4096);
	bnum_from_chars(&bn, "1000", 16);
	assertx(bnum_to_int(&bn) == 4096);

	membuf a = MEMBUF_INITIALISER, b = MEMBUF_INITIALISER,
		c = MEMBUF_INITIALISER, d = MEMBUF_INITIALISER;

	bnum_from_int(&a, 4027);
	bnum_from_int(&b, -4017);
	bnum_from_int(&c, 10);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, -4017);
	bnum_from_int(&b, 4027);
	bnum_from_int(&c, 10);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 111);
	bnum_from_int(&b, 222);
	bnum_from_int(&c, 333);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 10);
	bnum_from_int(&b, -11);
	bnum_from_int(&c, -1);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, -11);
	bnum_from_int(&b, 10);
	bnum_from_int(&c, -1);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	int16_t x1 = -1000;
	int16_t x2 = 1000;

	bnum_from_int(&a, x1);
	bnum_from_int(&b, x2);
	bnum_from_int(&c, x1 + x2);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	x1 = 1000;
	x2 = -1000;

	bnum_from_int(&a, x1);
	bnum_from_int(&b, x2);
	bnum_from_int(&c, x1 + x2);
	bnum_add(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 121);
	bnum_from_int(&b, 14);
	bnum_from_int(&c, 1694);
	bnum_mul(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 99);
	bnum_from_int(&b, 99);
	bnum_from_int(&c, 9801);
	bnum_mul(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 899);
	bnum_from_int(&b, -899);
	bnum_from_int(&c, -808201);
	bnum_mul(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, -899);
	bnum_from_int(&b, 899);
	bnum_from_int(&c, -808201);
	bnum_mul(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, -1);
	bnum_from_int(&b, 0);
	bnum_from_int(&c, 0);
	bnum_mul(&a, &b, &a);
	assertx(0 == bnum_compare(&a, &c));

	bnum_from_int(&a, 491);
	bnum_from_int(&b, 13);
	bnum_from_int(&c, 37);
	bnum_from_int(&d, 10);
	bnum_div(&a, &b, &a, &b);
	assertx(0 == bnum_compare(&a, &c));
	assertx(0 == bnum_compare(&b, &d));

	bnum_from_int(&a, 250);
	bnum_from_int(&b, 6);
	bnum_from_int(&c, 41);
	bnum_from_int(&d, 4);
	bnum_div(&a, &b, &a, &b);
	assertx(0 == bnum_compare(&a, &c));
	assertx(0 == bnum_compare(&b, &d));

	bnum_from_int(&a, 246875);
	bnum_from_int(&b, 27);
	bnum_from_int(&c, 9143);
	bnum_from_int(&d, 14);
	bnum_div(&a, &b, &a, &b);
	assertx(0 == bnum_compare(&a, &c));
	assertx(0 == bnum_compare(&b, &d));

	bnum_from_int(&a, -27);
	bnum_from_int(&b, 5);
	bnum_from_int(&c, -5);
	bnum_from_int(&d, -2);
	bnum_div(&a, &b, &a, &b);
	assertx(0 == bnum_compare(&a, &c));
	assertx(0 == bnum_compare(&b, &d));

	bnum_from_int(&a, 27);
	bnum_from_int(&b, -5);
	bnum_from_int(&c, -5);
	bnum_from_int(&d, 2);
	bnum_div(&a, &b, &a, &b);
	assertx(0 == bnum_compare(&a, &c));
	assertx(0 == bnum_compare(&b, &d));

#define BNUM_ALL_TESTS 0

#if 0 || BNUM_ALL_TESTS
	for (int i = -1000; i <= 1000; i++)
	{
		bnum_from_int(&a, i);
		assertxiter(i == bnum_to_int(&a), assemble_vals(i, 0, 4, 0));
	}

	for (int i = -1000; i <= 1000; i++)
	{
		char str[10];
		snprintf(str, sizeof(str), "%x", i);
		bnum_from_chars(&a, str);
		assertxiter(i == (int)bnum_to_int(&a), assemble_vals(i, 0, 4, 0));
	}
#endif

#if 0 || BNUM_ALL_TESTS
	for (int i = -1000; i <= 1000; i++)
		for (int j = -1000; j <= 1000; j++)
		{

			bnum_from_int(&a, i);
			bnum_from_int(&b, j);
			bnum_from_int(&c, i + j);
			bnum_add(&a, &b, &a);
			assertxiter(0 == bnum_compare(&a, &c), assemble_vals(i, j, 4, 4));
		}
#endif

#if 0 || BNUM_ALL_TESTS
	for(int i = -1000; i <= 1000; i++)
		for(int j = -1000; j <= 1000; j++)
		{

			bnum_from_int(&a, i);
			bnum_from_int(&b, j);
			bnum_from_int(&c, i * j);
			bnum_mul(&a, &b, &a);
			assertxiter(0 == bnum_compare(&a, &c), assemble_vals(i, j, 4, 4));
		}
#endif

	return 0;
}

int run_tests()
{
	run_mt19937_tests();
	run_utils_tests();
	run_base64_tests();
	run_aes_tests();
	run_bignum_tests();

	cout << "Tests result: " << tests_ok << "/" << tests_total << endl;
	return 0;
}