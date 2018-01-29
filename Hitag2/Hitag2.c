// Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm by I.C. Wiener 2006-2007.
// For educational purposes only.
// No warranties or guarantees of any kind.
// This code is released into the public domain by its author.

#include <stdio.h>

// Basic macros:

#define u8			unsigned char
#define u32			unsigned int
#define u64			unsigned long long
#define s32			signed int

#define rev8(x)			((((x)>>7)&1)+((((x)>>6)&1)<<1)+((((x)>>5)&1)<<2)+((((x)>>4)&1)<<3)+((((x)>>3)&1)<<4)+((((x)>>2)&1)<<5)+((((x)>>1)&1)<<6)+(((x)&1)<<7))
#define rev16(x)		(rev8 (x)+(rev8 (x>> 8)<< 8))
#define rev32(x)		(rev16(x)+(rev16(x>>16)<<16))
#define rev64(x)		(rev32(x)+(rev32(x>>32)<<32))
#define bit(x,n)		(((x)>>(n))&1)
#define bit32(x,n)		((((x)[(n)>>5])>>((n)))&1)
#define inv32(x,i,n)		((x)[(i)>>5]^=((u32)(n))<<((i)&31))
#define rotl64(x, n)		((((u64)(x))<<((n)&63))+(((u64)(x))>>((0-(n))&63)))
#define i4(x,a,b,c,d)		((u32)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))


// Single bit Hitag2 functions:

#define i4(x,a,b,c,d)   ((u32)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))

static const u32 ht2_f4a = 0x2C79;      // 0010 1100 0111 1001
static const u32 ht2_f4b = 0x6671;      // 0110 0110 0111 0001
static const u32 ht2_f5c = 0x7907287B;  // 0111 1001 0000 0111 0010 1000 0111 1011

// Bitslice Hitag2 functions:

#define ht2bs_4a(a,b,c,d)   (~(((a|b)&c)^(a|d)^b))
#define ht2bs_4b(a,b,c,d)   (~(((d|c)&(a^b))^(d|a|b)))
#define ht2bs_5c(a,b,c,d,e) (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c))))

#define uf20bs              u32     // choose your own type/width
/*
static uf20bs f20bs (const uf20bs *x)
{
    return ht2bs_5c (
        ht2bs_4a(x[ 1],x[ 2],x[ 4],x[ 5]),
        ht2bs_4b(x[ 7],x[11],x[13],x[14]),
        ht2bs_4b(x[16],x[20],x[22],x[25]),
        ht2bs_4b(x[27],x[28],x[30],x[32]),
        ht2bs_4a(x[33],x[42],x[43],x[45]));
}

static void hitag2bs_init (uf20bs *x, const uf20bs *key, const uf20bs *serial, const uf20bs *IV)
{
    u64                 i, r;
    
    for (i = 0; i < 32; i++) x[i] = serial[i];
    for (i = 0; i < 16; i++) x[32+i] = key[i];
    
    for (r = 0; r < 32; r++)
    {
        for (i = 0; i < 47; i++) x[i] = x[i+1];
        x[47] = f20bs (x) ^ IV[i] ^ key[16+i];
    }
}

static uf20bs hitag2bs_round (uf20bs *x)
{
    uf20bs              y;
    u32                 i;
    
    y = x[ 0] ^ x[ 2] ^ x[ 3] ^ x[ 6] ^ x[ 7] ^ x[ 8] ^ x[16] ^ x[22]
      ^ x[23] ^ x[26] ^ x[30] ^ x[41] ^ x[42] ^ x[43] ^ x[46] ^ x[47];
    
    for (i = 0; i < 47; i++) x[i] = x[i+1];
    x[47] = y;
    
    return f20bs (x);
}*/

// "MIKRON"     =  O  N  M  I  K  R
// Key          = 4F 4E 4D 49 4B 52     - Secret 48-bit key
// Serial       = 49 43 57 69           - Serial number of the tag, transmitted in clear
// Random       = 65 6E 45 72           - Random IV, transmitted in clear
//~28~DC~80~31  = D7 23 7F CE           - Authenticator value = inverted first 4 bytes of the keystream

// The code below must print out "D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6".
// The inverse of the first 4 bytes is sent to the tag to authenticate.
// The rest is encrypted by XORing it with the subsequent keystream.
static u64 f20(const u64 x)
{
	u64	i5;

	i5 = ((ht2_f4a >> i4 (x, 1, 2, 4, 5)) & 1)* 1
	   + ((ht2_f4b >> i4 (x, 7,11,13,14)) & 1)* 2
	   + ((ht2_f4b >> i4 (x,16,20,22,25)) & 1)* 4
	   + ((ht2_f4b >> i4 (x,27,28,30,32)) & 1)* 8
	   + ((ht2_f4a >> i4 (x,33,42,43,45)) & 1)*16;

	return (ht2_f5c >> i5) & 1;
}

static u64 hitag2_init (const u64 key, const u32 serial, const u32 IV)
{
    u32                 i=0;
    u64                 x = ((key & 0xFFFF) << 32) + serial;

    for (i = 0; i < 32; i++)
    {
        x >>= 1;
        x += (u64) (f20 (x) ^ (((IV >> i) ^ (key >> (i+16))) & 1)) << 47;
    }
    return x;
}

static u64 hitag2_round (u64 *state)
{
    u64                 x = *state;

    x = (x >>  1) +
     ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
      ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
      ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
      ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

    *state = x;
    return f20 (x);
}



static u32 hitag2_byte (u64 * x)
{
    u64                 i, c;
    
    for (i = 0, c = 0; i < 8; i++) c += (u32) hitag2_round (x) << (i^7);
    return c;
}

int main (void)
{
    u32                 i;
    u64                 state;
    
   // state = hitag2_init (rev64 (0x69257F8FBFC6), rev32 (0xe6b46a03), rev32 (0x80883f3c));
     state = hitag2_init (rev64 (0x4F4E4D494B52), rev32 (0x49435769), rev32 (0x656E4572));
    for (i = 0; i < 16; i++) printf ("%X ", hitag2_byte (&state));
    printf ("\n");
    return 0;
} 
