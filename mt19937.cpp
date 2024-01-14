
#include "mt19937.h"
#include <stdint.h>
#include <iostream>

/**
 * nw - r = 19937
 * w = 32
 * 19937 / 32 = 623
 * n = 624
 * r = 624 * 32 - 19937 = 19968 - 19937 = 31
 */

const uint32_t w = 32;
const uint32_t n = 624;
const uint32_t r = 31;
const uint32_t f = 1812433253u;
const uint32_t m = 397;

const uint32_t a = 0x9908B0DF;
const uint32_t b = 0x9D2C5680;
const uint32_t c = 0xEFC60000;
const uint32_t d = 0xFFFFFFFF;
const uint32_t l = 18;
const uint32_t s = 7;
const uint32_t t = 15;
const uint32_t u = 11;

static uint32_t MT[n];
static uint32_t index = n + 1;
const uint32_t lower_mask = (1u << r) - 1; // That is, the binary number of r 1's
const uint32_t upper_mask = ~lower_mask;

static void twist();


// Initialize the generator from a seed
void mt19937_seed(unsigned int seed)
{
	/*
    index := n
    MT[0] := seed
    for i from 1 to (n - 1) { // loop over each element
        MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
    }
	*/
    index = n;
    MT[0] = seed;
    for (uint32_t i = 1; i < n; i++)
    {
        MT[i] = f * ( MT[i - 1] ^ (MT[i - 1] >> (w - 2)) ) + i;
    }
}

// Extract a tempered value based on MT[index]
// calling twist() every n numbers
unsigned int mt19937_gen()
{
    /*
    if index >= n {
        if index > n {
           error "Generator was never seeded"
           // Alternatively, seed with constant value; 5489 is used in reference C code
         }
         twist()
    }
 
    int y := MT[index]
    y := y xor ((y >> u) and d)
    y := y xor ((y << s) and b)
    y := y xor ((y << t) and c)
    y := y xor (y >> l)
 
    index := index + 1
    return lowest w bits of (y)
    */
    if (index >= n)
    {
        if (index > n)
        {
            std::cout << "MT19937 generator was never seeded\n";
            mt19937_seed(5489);
        }
        twist();
    }

    uint32_t y = MT[index];
    y = y ^ ((y >> u) /*& d*/);
    y = y ^ ((y << s) & b);
    y = y ^ ((y << t) & c);
    y = y ^ (y >> l);

    index++;

	return (uint32_t)y;
}

// Generate the next n values from the series x_i
static void twist()
{
    /*
    for i from 0 to (n-1) {
        int x := (MT[i] and upper_mask)
                | (MT[(i+1) mod n] and lower_mask)
        int xA := x >> 1
        if (x mod 2) != 0 { // lowest bit of x is 1
            xA := xA xor a
        }
        MT[i] := MT[(i + m) mod n] xor xA
    }
    index := 0
    */
    for (uint32_t i = 0; i < n; i++)
    {
        uint32_t x = (MT[i] & upper_mask) |
            (MT[(i + 1) % n] & lower_mask);
        uint32_t xA = x >> 1;
        if ((x & 1) != 0) // lowest bit of x is 1
        {
            xA = xA ^ a;
        }
        MT[i] = MT[(i + m) % n] ^ xA;
    }
    index = 0;
}