#pragma once

inline int base64_dec_bufsz(int len)
{
	return ((len * 3) + 3) / 4;
}

inline int base64_enc_bufsz(int len)
{
	return ((len * 4) + 2) / 3;
}

int hextobase64(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz);

int base64tohex(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz);
