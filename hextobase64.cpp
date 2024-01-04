
#include "hextobase64.h"

#include <iostream>

static const unsigned char alphabet[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

int hextobase64(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz)
{
	int ret = 0;

	int i = 0, j = 0;

	while ((i + 3 <= insz) && (j + 4 <= outsz))
	{
		unsigned int combined = ((unsigned int)in[i] << 16) + ((unsigned int)in[i + 1] << 8) + (unsigned int)in[i + 2];
		i += 3;

		int k = 3;
		unsigned int mask = 0x3F << (6 * 3);
		while (k >= 0)
		{
			unsigned int extract = (combined & mask) >> (6 * k);
			mask = mask >> 6;
			k--;

			out[j] = alphabet[extract];
			j++;
		}
	}

	int remain = insz - i;
	if ((remain == 1 || remain == 2) && (j + 4 <= outsz))
	{
		int steps = 2; //process 2 base64 values

		unsigned int combined = (unsigned int)in[i] << 16;

		if (remain == 2)
		{
			combined = combined + ((unsigned int)in[i + 1] << 8);
			steps = 3; //process 3 base64 values
		}

		int k = 3;
		unsigned int mask = 0x3F << (6 * 3);
		while (steps > 0)
		{
			steps--;
			unsigned int extract = (combined & mask) >> (6 * k);
			mask = mask >> 6;
			k--;

			out[j] = alphabet[extract];
			j++;
		}

		out[j++] = '=';
		if (remain == 1)
		{
			out[j++] = '=';
		}
	}

	return j;
}

static unsigned int find_in_alphabet(unsigned int val)
{
	int ret = 0;

	if (val != '=')
	{
		int i;
		for (i = 0; i < sizeof(alphabet) / sizeof(alphabet[0]); i++)
		{
			if (alphabet[i] == val)
			{
				ret = i;
				break;
			}
		}
	}

	return ret;
}

int base64tohex(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz)
{
	int ret = 0;

	int i = 0, j = 0;

	while ((i + 4 <= insz) && (j + 3 <= outsz))
	{
		unsigned int combined = (find_in_alphabet(in[i]) << 18) + (find_in_alphabet(in[i + 1]) << 12) +
								(find_in_alphabet(in[i + 2]) << 6) + find_in_alphabet(in[i + 3]);
		i += 4;

		int k = 2;
		unsigned int mask = 0xFF << (8 * 2);
		while (k >= 0)
		{
			unsigned int extract = (combined & mask) >> (8 * k);
			mask = mask >> 8;
			k--;

			out[j] = extract;
			j++;
		}
	}

	if (i != insz)
	{
		std::cout << "\nInput in not multiple of four\n";
	}

	if ((i - 1 >= 0) && (in[i - 1] == '='))
	{
		j--;
	}
	if ((i - 2 >= 0) && (in[i - 2] == '='))
	{
		j--;
	}

	return j;
}