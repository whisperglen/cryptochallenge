
#include "utils.h"
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
//#include <cassert>

using std::string;
using std::cin;
using std::cout;
using std::endl;

static int tests_total = 0;
static int tests_ok = 0;

static void xassert(int success, const char* expression, const char* function, unsigned line, const char* file)
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

#define assertx(expression) (void)(                                                             \
            (xassert((!!(expression)), _CRT_STRINGIZE(#expression), (__func__), (unsigned)(__LINE__), (__FILE__)), 0) \
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

int run_tests()
{
	run_mt19937_tests();
	run_utils_tests();
	run_base64_tests();
	run_aes_tests();

	cout << "Tests result: " << tests_ok << "/" << tests_total << endl;
	return 0;
}