#pragma once

#include "utils.h"

void bnum_from_int(membuf* dest, int64_t value);
int64_t bnum_to_int(const membuf* bn);
void bnum_from_chars(membuf* dest, const char* data, int base);

const membuf* bnum_negate(membuf* bnum);
void bnum_set_zero(membuf* bn);
int bnum_is_zero(const membuf* bn);
int bnum_compare(const membuf* first, const membuf* second);

void bnum_add(const membuf* first, const membuf* second, membuf* result);
void bnum_mul(const membuf* first, const membuf* second, membuf* result);
void bnum_div(const membuf* first, const membuf* second, membuf* result, membuf* remainder);

void bnum_modexp(const membuf* base, const membuf* exponent, const membuf* modulus, membuf* result);