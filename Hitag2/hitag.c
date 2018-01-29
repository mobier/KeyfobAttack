#include<stdio.h>
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

static const u32 ht2_f4a = 0x2C79;		// 0010 1100 0111 1001
static const u32 ht2_f4b = 0x6671;		// 0110 0110 0111 0001
static const u32 ht2_f5c = 0x7907287B;	// 0111 1001 0000 0111 0010 1000 0111 1011


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

u64 hitag2_init(const u64 key, const u32 serial, const u32 IV)
{
	u32 i = 0;
	u64 x = ((key & 0xFFFF) << 32) + serial;

	for (i = 0; i < 32; i++)
	{
		x >>= 1;
		x += (u64) (f20 (x) ^ (((IV >> i) ^ (key >> (i+16))) & 1)) << 47;
	}
	return x;
}

u64 hitag2_find_key(u64 initial_state, const u32 serial, const u32 IV)
{
	u64 last_bit = 0;
	u64 key = 0;
	u64 state = 0;
	s32 i = 31;

	state = initial_state;

	for (i = 31; i >= 0; i--)
	{
		last_bit = (state >> 47);

		key = key + (((last_bit ^ f20(state) ^ (IV >> i)) & 1) << (i + 16));
		state = (state << 1) + (u64) ((serial >> i) & 1);
	}
	
	key = key ^ ((state >> 32) & 0xFFFF);
	
	return key;
}

void hitag2_prev_state(u64 *state)
{
	u64 x = *state;

	x = (x <<  1) +
	(((x >>  47) ^ (x >>  1) ^ (x >>  2) ^ (x >>  5)
	  ^ (x >>  6) ^ (x >>  7) ^ (x >> 15) ^ (x >> 21)
	  ^ (x >> 22) ^ (x >> 25) ^ (x >> 29) ^ (x >> 40)
	  ^ (x >> 41) ^ (x >> 42) ^ (x >> 45) ^ (x >> 46)) & 1);

	*state = x & 0xFFFFFFFFFFFFULL;
}

void hitag2_next_state(u64 *state)
{
	u64 x = *state;

	x = (x >>  1) +
	 ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
	  ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
	  ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
	  ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

	*state = x;
}


static u64 hitag2_round(u64 *state)
{
	u64 x = *state;

	x = (x >>  1) +
	 ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
	  ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
	  ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
	  ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

	*state = x;
	return f20(x);
}

static u64 hitag2_byte(u64 * x)
{
	u64 i;
	u64 c;

	for (i = 0, c = 0; i < 8; i++) c += (u64) hitag2_round(x) << (7 - i);
	return c;
}

u64 hitag2_prefix(u64 * x, u32 bits)
{
	u64 i;
	u64 prefix = 0;

	for (i = 0; i < (bits/8); i++)
	{
		prefix += (u64) hitag2_byte (x) << ((bits/8) - 1 - i)*8;
	}

	return prefix;
}
int main(void){
u32 i;
u64 state;
//state = hitag2_init (rev64 (0x4F4E4D494B52), rev32 (0x49435769), rev32 (0x656E4572));
state = hitag2_init (rev64 (0x4F4E4D494B52UL), rev32 (0x49435769), rev32 (0x656E4572));
    for (i = 0; i < 16; i++) printf ("%llX", hitag2_byte (&state));
    printf ("\n");
    return 0;
}

