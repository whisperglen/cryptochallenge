
#include "bignum.h"
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <iostream>


#define BNUM_DIGITS_OFFSET 1
#define BNUM_NUMBER_BASE 16
#define BNUM_DIGITS_IN_64BITS 16
#define BNUM_NUMBER_BASE_RE_LOG 0.8305 //reciprocal log base

static int bnum_get_sign(const membuf* bn);
static int bnum_get_digit_value(const membuf* bn, int pos);
static int bnum_get_digit_value(const membuf* bn, int index);
static void bnum_set_digit_value(membuf* bn, int val, int index);

static void bnum_do_add(const membuf* first, const membuf* second, membuf* result);
static void bnum_do_subtract(const membuf* first, const membuf* second, membuf* result);

static int bnum_count_digits(const membuf* mb)
{
	int count = 0;

	if (mb && mb->used)
	{
		count = mb->used - 1; //sign byte
		int i = mb->used - 1;
		while ((i > 1) && (mb->data[i] == 0 || mb->data[i] == '0'))
		{
			i--;
			count--;
		}
	}

	return count;
}

void bnum_from_int(membuf* dest, int64_t value)
{
	int size = BNUM_DIGITS_IN_64BITS + 2; //digits for max_int64, 1 for sign, 1 for zero term
	membuf_adjust_size(dest, size);
	membuf_clear(dest);

	char sign = '+';
	if (value < 0)
	{
		sign = '-';
		value = -value;
	}
	membuf_append_byte_auto(dest, sign);
	if (value == 0)
	{
		membuf_append_byte_auto(dest, '0');
	}
	else
	{
		int i = 0;
		unsigned digit = 0;
		while (value)
		{
			digit = value % BNUM_NUMBER_BASE;
			value = value / BNUM_NUMBER_BASE;
			bnum_set_digit_value(dest, digit, i);
			i++;
		}
	}
	membuf_append_byte_auto(dest, 0);
}

int64_t bnum_to_int(const membuf* bn)
{
	int64_t val = 0;
	int numdigits = bnum_count_digits(bn);

	if (numdigits <= BNUM_DIGITS_IN_64BITS)
	{
		for (int i = numdigits; i >= 0; i--)
		{
			val *= BNUM_NUMBER_BASE;
			val += bnum_get_digit_value(bn, i);
		}
	}

	if (bn->data[0] == '-')
		val = -val;

	return val;
}

void bnum_from_chars(membuf* dest, const char* data, int base)
{
	membuf_clear(dest);
	char sign = '+';
	if (data[0] == '-')
	{
		sign = '-';
	}

	int count = strlen(data);
	if (base == BNUM_NUMBER_BASE)
	{
		membuf_adjust_size(dest, count + 2); //sgn anz zeroterm
		dest->used = 1;//for sign, which will be filled later

		const char* iter = &data[count - 1];

		while (iter >= data)
		{
			if (!isxdigit(*iter))
				break;

			membuf_append_byte_auto(dest, *iter);
			iter--;
		}
	}
	else
	{
		int chars = 1 + ((count * log(base)) * BNUM_NUMBER_BASE_RE_LOG); //chars in base * log base * (1 / log BNUM_NUMBER_BASE)
		membuf_adjust_size(dest, count + 2);

		membuf mag = MEMBUF_INITIALISER, scratch = MEMBUF_INITIALISER;
		bnum_from_int(&mag, base);
		bnum_set_zero(&scratch);

		int i = 0;
		if (data[0] == '-') i = 1;
		for ( ; i < count; i++)
		{
			bnum_mul(dest, &mag, dest);
			bnum_set_digit_value(&scratch, hexchartoi(data[i]), 0);
			bnum_do_add(dest, &scratch, dest);
		}

		membuf_free(&mag);
		membuf_free(&scratch);
	}

	membuf_set_byte_auto(dest, sign, 0, '0');
	membuf_append_byte_auto(dest, 0);
}

const membuf* bnum_negate(membuf* bnum)
{
	char sign = '+';
	if (bnum_get_sign(bnum) > 0)
	{
		sign = '-';
	}
	membuf_set_byte_auto(bnum, sign, 0, '0');

	return bnum;
}

int static bnum_get_sign(const membuf* bn)
{
	int ret = 1;
	if (bn && bn->used > 1)
		if (bn->data[0] == '-')
			ret = -1;
	return ret;
}

static int bnum_is_negative(const membuf* bn)
{
	return bnum_get_sign(bn) == -1;
}

static int bnum_compare_sgn(const membuf* first, const membuf* second, int look_at_sign)
{
	if (look_at_sign)
	{
		if (bnum_get_sign(first) != bnum_get_sign(second))
		{
			if (bnum_is_negative(first))
				return -1;
			else
				return 1;
		}
	}
	//they have the same sign now
	int numdigits_first = bnum_count_digits(first);
	int numdigits_second = bnum_count_digits(second);
	if (numdigits_first != numdigits_second)
	{
		if (numdigits_first < numdigits_second)
			return -1;
		else
			return 1;
	}
	//they are of equal length
	for (int i = numdigits_first; i > 0; i--)
	{
		if (first->data[i] == second->data[i])
		{
			//continue;
		}
		else
		{
			int sign = look_at_sign ? bnum_get_sign(first) : 1;
			if ((first->data[i] - second->data[i]) < 0)
				sign = -sign;
			return sign;
		}
	}
	return 0;
}

int bnum_compare(const membuf* first, const membuf* second)
{
	return bnum_compare_sgn(first, second, 1);
}

void bnum_add(const membuf* first, const membuf* second, membuf* result)
{
	const membuf *a, * b;
	char result_sign = '+';
	int do_add = 1;
	a = first;
	b = second;
	if (bnum_get_sign(first) == bnum_get_sign(second))
	{
		if (bnum_is_negative(first))
			result_sign = '-';
	}
	else //different signs
	{
		do_add = 0;
		//different signs
		int comp = bnum_compare_sgn(first, second, 0);
		if (comp < 0)
		{
			b = first;
			a = second;
			if (bnum_is_negative(second))
				result_sign = '-';
		}
		else if (comp == 0)
		{   //if they are equal and have different signs, result is +0
			bnum_set_zero(result);
			return;
		}
		else
		{
			if (bnum_is_negative(first))
				result_sign = '-';
		}
	}

	int resultsz = max_int(bnum_count_digits(first), bnum_count_digits(second));
	resultsz += 3; //add can increase digits by one, plus sign plus zero termination

	membuf_adjust_size(result, resultsz);
	membuf_set_byte_auto(result, result_sign, 0, '0');
	if (do_add)
		bnum_do_add(a, b, result);
	else
		bnum_do_subtract(a, b, result);

	//at this point result->used should be correct and excluding leading zeroes
	//this clears leading zeroes
	membuf_append_byte_auto(result, 0);
}

static int bnum_get_digit_value(const membuf* bn, int index)
{
	int ret = 0;
	int pos = index + BNUM_DIGITS_OFFSET;
	if (bn && bn->data && (pos < bn->used))
		if(isxdigit(bn->data[pos]))
			ret = hexchartoi(bn->data[pos]);
	return ret;
}

static void bnum_set_digit_value(membuf* bn, int val, int index)
{
	val = itohexchar(val);
	membuf_set_byte_auto(bn, val, index + BNUM_DIGITS_OFFSET, '0');
}

static void bnum_update_used_digits(membuf* bn, int numdigits)
{
	int used = numdigits + BNUM_DIGITS_OFFSET;
	for (int i = used - 1; i > 1; i--)
	{
		if (bn->data[i] == '0' || bn->data[i] == 0)
			used--;
		else
			break;
	}
	bn->used = used;
}

static void bnum_do_add(const membuf* first, const membuf* second, membuf* result)
{
	int upto = max_int(bnum_count_digits(first), bnum_count_digits(second));
	upto ++; //result of add may have an extra digit
	int carry = 0;
	for (int i = 0; i < upto; i++)
	{
		int val = carry + bnum_get_digit_value(first, i) + bnum_get_digit_value(second, i);
		if (val >= BNUM_NUMBER_BASE)
		{
			bnum_set_digit_value(result, val % BNUM_NUMBER_BASE, i);
			carry = 1;
		}
		else
		{
			bnum_set_digit_value(result, val, i);
			carry = 0;
		}
	}

	bnum_update_used_digits(result, upto);
}

static void bnum_do_subtract(const membuf* first, const membuf* second, membuf* result)
{
	int upto = max_int(bnum_count_digits(first), bnum_count_digits(second));
	int carry = 0;
	for (int i = 0; i < upto; i++)
	{
		int val = carry + bnum_get_digit_value(first, i) - bnum_get_digit_value(second, i);
		if (val < 0)
		{
			bnum_set_digit_value(result, BNUM_NUMBER_BASE + val, i);
			carry = -1;
		}
		else
		{
			bnum_set_digit_value(result, val, i);
			carry = 0;
		}

	}

	bnum_update_used_digits(result, upto);	
}

void bnum_mul(const membuf* first, const membuf* second, membuf* result)
{
	int upto = max_int(bnum_count_digits(first), bnum_count_digits(second));
	upto *= 2; //no of digits can be increase twofold
	upto += 2; //sign and zero termination

	if (bnum_is_zero(first) || bnum_is_zero(second))
	{
		bnum_set_zero(result);
		return;
	}

	char result_sign = '+';
	if (bnum_get_sign(first) != bnum_get_sign(second))
	{
		result_sign = '-';
	}

	membuf accum = MEMBUF_INITIALISER;
	membuf scratch = MEMBUF_INITIALISER;
	membuf_adjust_size(&accum, upto);
	membuf_adjust_size(&scratch, upto);
	bnum_set_zero(&accum);
	bnum_set_zero(&scratch);

	const membuf* a = first, * b = second;
	if (bnum_count_digits(first) < bnum_count_digits(second))
	{
		a = second;
		b = first;
	}

	int outerloops = bnum_count_digits(b);
	int innerloops = 1 + bnum_count_digits(a); //there may be an extra digit after add
	for (int i = 0; i < outerloops; i++)
	{
		int carry = 0;
		for (int j = 0; j < innerloops; j++)
		{
			int val = carry + bnum_get_digit_value(a, j) * bnum_get_digit_value(b, i);
			if (val >= BNUM_NUMBER_BASE)
			{
				bnum_set_digit_value(&scratch, val % BNUM_NUMBER_BASE, j + i);
				carry = val / BNUM_NUMBER_BASE;
			}
			else
			{
				bnum_set_digit_value(&scratch, val, j + i);
				carry = 0;
			}
		}
		bnum_update_used_digits(&scratch, innerloops + i);
		bnum_do_add(&accum, &scratch, &accum);

		bnum_set_zero(&scratch);
	}

	membuf_adjust_size(result, accum.used + 1);
	membuf_copy_auto(result, &accum);
	membuf_append_byte_auto(result, 0);
	membuf_set_byte_auto(result, result_sign, 0, '0');

	membuf_free(&accum);
	membuf_free(&scratch);
}

static void bnum_do_division_naive(const membuf* first, const membuf* second, membuf* result, membuf *remainder)
{
	int64_t count = 0;
	membuf minuend = MEMBUF_INITIALISER;
	membuf quotient = MEMBUF_INITIALISER;
	membuf one = MEMBUF_INITIALISER;
	bnum_set_zero(&quotient);
	membuf_copy_auto(&minuend, first);
	while (0 < bnum_compare_sgn(&minuend, second, 0))
	{
		bnum_do_subtract(&minuend, second, &minuend);
		if (count < INT64_MAX)
		{
			count++;
		}
		else
		{
			if (bnum_is_zero(&quotient))
			{
				bnum_from_int(&quotient, count);
				bnum_from_int(&one, 1);
			}
			bnum_do_add(&quotient, &one, &quotient);
		}
	}
	
	if (bnum_is_zero(&quotient))
	{
		bnum_from_int(&quotient, count);
	}

	if (result->data == NULL)
		membuf_move(result, &quotient);
	else
		membuf_copy_auto(result, &quotient);

	if (remainder->data == NULL)
		membuf_move(remainder, &minuend);
	else
		membuf_copy_auto(remainder, &minuend);

	membuf_free(&minuend);
	membuf_free(&quotient);
	membuf_free(&one);
}

static void bnum_extract_digits(membuf* dest, const membuf* src, int numdigits)
{
	int total = bnum_count_digits(src);
	int start = numdigits <= total ? total - numdigits : 0;

	for (int i = 0, j = start; i < numdigits; i++, j++)
		bnum_set_digit_value(dest, bnum_get_digit_value(src, j), i);
}

void bnum_div(const membuf* first, const membuf* second, membuf* result, membuf *remainder)
{
	if (bnum_is_zero(first) || bnum_is_zero(second))
	{
		if (result) bnum_set_zero(result);
		if (remainder) bnum_set_zero(remainder);
		return;
	}

	char div_sign = '+';
	char rem_sign = '+';
	if (bnum_get_sign(first) != bnum_get_sign(second))
	{
		div_sign = '-';
		if (bnum_get_sign(first) == -1)
			rem_sign = '-';
	}

	int fsz = bnum_count_digits(first);
	int ssz = bnum_count_digits(second);
	if (fsz < ssz)
	{
		if (result) bnum_set_zero(result);
		if (remainder)
		{
			membuf_adjust_size(remainder, first->used + 1);
			membuf_copy_auto(remainder, first);
			membuf_set_byte_auto(remainder, rem_sign, 0, '0');
		}
		return;
	}

	membuf dividend = MEMBUF_INITIALISER, quotient = MEMBUF_INITIALISER,
		tmprem = MEMBUF_INITIALISER, mag = MEMBUF_INITIALISER,
		scratch = MEMBUF_INITIALISER;
	bnum_from_int(&mag, BNUM_NUMBER_BASE);

	bnum_extract_digits(&dividend, first, ssz);

	int next_digit = fsz - ssz;
	int loops = fsz - ssz + 1;
	for (int i = loops - 1; i >= 0; i--)
	{
		bnum_do_division_naive(&dividend, second, &scratch, &tmprem);
		bnum_mul(&quotient, &mag, &quotient);
		bnum_do_add(&quotient, &scratch, &quotient);
		if (i > 0)
		{
			bnum_set_zero(&scratch);
			bnum_set_digit_value(&scratch, bnum_get_digit_value(first, i - 1), 0);
			bnum_mul(&tmprem, &mag, &dividend);
			bnum_do_add(&dividend, &scratch, &dividend);
		}
	}

	if (result)
	{
		membuf_adjust_size(result, quotient.used + 1);
		membuf_copy_auto(result, &quotient);
		membuf_append_byte_auto(result, 0);
		membuf_set_byte_auto(result, div_sign, 0, '0');
	}

	if (remainder)
	{
		membuf_adjust_size(remainder, tmprem.used + 1);
		membuf_copy_auto(remainder, &tmprem);
		membuf_append_byte_auto(remainder, 0);
		membuf_set_byte_auto(remainder, rem_sign, 0, '0');
	}

	membuf_free(&dividend);
	membuf_free(&quotient);
	membuf_free(&tmprem);
	membuf_free(&mag);
	membuf_free(&scratch);
}

void bnum_set_zero(membuf* bn)
{
	membuf_adjust_size(bn, 3);
	membuf_clear(bn);
	membuf_set_byte_auto(bn, '+', 0, '0');
	membuf_set_byte_auto(bn, '0', 1, '0');
}

int bnum_is_zero(const membuf* bn)
{
	int ret = 0;

	if (bnum_count_digits(bn) == 1)
		if (bnum_get_digit_value(bn, 0) == 0)
			ret = 1;

	return ret;
}

static int bnum_lsb(const membuf* bn)
{
	//works only in base16
	int val = bnum_get_digit_value(bn, 0);
	return (val & 1);
}

static void bnum_shr(membuf* bn)
{
	//works only in base16
	int a, b;

	a = bnum_get_digit_value(bn, 0);

	int size = bnum_count_digits(bn);
	for (int i = 0; i < size; i++)
	{
		b = bnum_get_digit_value(bn, i + 1);
		int val = ((b << 3) + (a >> 1)) & 0xF;
		a = b;
		bnum_set_digit_value(bn, val, i);
	}

	bnum_update_used_digits(bn, size);
}

static void print_progress(int val, int limit)
{
	static int store = 0;
	if (limit == 0)
	{
		store = 0;
		std::cout << std::endl;
		return;
	}
	int percent = val * 10 / limit;
	if (percent > store)
	{
		store = percent;
		std::cout << percent << " ";
	}
}

void bnum_modexp(const membuf* base, const membuf* exponent, const membuf* modulus, membuf* result)
{
	membuf binexp = MEMBUF_INITIALISER;
	bnum_from_int(&binexp, 1);
	if (0 == bnum_compare(modulus, &binexp))
	{
		bnum_set_zero(result);
		return;
	}

	membuf_copy_auto(&binexp, exponent);

	membuf product = MEMBUF_INITIALISER;
	bnum_from_int(&product, 1);

	membuf power = MEMBUF_INITIALISER;
	bnum_div(base, modulus, NULL, &power);

	print_progress(0, 0);
	int limit = bnum_count_digits(&binexp);
	int count = 0;

	while (!bnum_is_zero(&binexp))
	{
		if (bnum_lsb(&binexp))
		{
			bnum_mul(&product, &power, &product);
			bnum_div(&product, modulus, NULL, &product);
		}
		bnum_shr(&binexp);
		print_progress(limit - bnum_count_digits(&binexp), limit);

		bnum_mul(&power, &power, &power);
		bnum_div(&power, modulus, NULL, &power);
		count++;
	}

	membuf_copy_auto(result, &product);
	membuf_free(&binexp);
	membuf_free(&product);
	membuf_free(&power);
}