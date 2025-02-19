#include <u.h>
#include <libc.h>

static const u32int RC[24] = {
	0x00000001,
	0x00008082,
	0x0000808a,
	0x80008000,
	0x0000808b,
	0x80000001,
	0x80008081,
	0x00008009,
	0x0000008a,
	0x00000088,
	0x80008009,
	0x8000000a,
	0x8000808b,
	0x0000008b,
	0x00008089,
	0x00008003,
	0x00008002,
	0x00000080,
	0x0000800a,
	0x8000000a,
	0x80008081,
	0x00008080,
	0x80000001,
	0x80008008
};
void
keccak_p800(u32int *state, usize round_count)
{
	u32int t1;

	if(round_count > 22){
		fprint(2, "keccak_p800: invalid round count %uzd\n", round_count);
		abort();
	}

	u32int *round_consts = &RC[22-round_count];
	for(usize idx = 0; idx < round_count; ++idx){
		u32int array[5] = {0, 0, 0, 0, 0};

		array[0] ^= state[0];
		array[0] ^= state[5];
		array[0] ^= state[10];
		array[0] ^= state[15];
		array[0] ^= state[20];
		array[1] ^= state[1];
		array[1] ^= state[6];
		array[1] ^= state[11];
		array[1] ^= state[16];
		array[1] ^= state[21];
		array[2] ^= state[2];
		array[2] ^= state[7];
		array[2] ^= state[12];
		array[2] ^= state[17];
		array[2] ^= state[22];
		array[3] ^= state[3];
		array[3] ^= state[8];
		array[3] ^= state[13];
		array[3] ^= state[18];
		array[3] ^= state[23];
		array[4] ^= state[4];
		array[4] ^= state[9];
		array[4] ^= state[14];
		array[4] ^= state[19];
		array[4] ^= state[24];
		t1 = array[1];
		t1 = (t1<<1)|(t1>>31);
		t1 = array[4]^t1;
		state[0] ^= t1;
		state[5] ^= t1;
		state[10] ^= t1;
		state[15] ^= t1;
		state[20] ^= t1;
		t1 = array[2];
		t1 = (t1<<1)|(t1>>31);
		t1 = array[0]^t1;
		state[1] ^= t1;
		state[6] ^= t1;
		state[11] ^= t1;
		state[16] ^= t1;
		state[21] ^= t1;
		t1 = array[3];
		t1 = (t1<<1)|(t1>>31);
		t1 = array[1]^t1;
		state[2] ^= t1;
		state[7] ^= t1;
		state[12] ^= t1;
		state[17] ^= t1;
		state[22] ^= t1;
		t1 = array[4];
		t1 = (t1<<1)|(t1>>31);
		t1 = array[2]^t1;
		state[3] ^= t1;
		state[8] ^= t1;
		state[13] ^= t1;
		state[18] ^= t1;
		state[23] ^= t1;
		t1 = array[0];
		t1 = (t1<<1)|(t1>>31);
		t1 = array[3]^t1;
		state[4] ^= t1;
		state[9] ^= t1;
		state[14] ^= t1;
		state[19] ^= t1;
		state[24] ^= t1;

		/* rho and pi */
		t1 = state[1];
		array[0] = state[10];
		state[10] = (t1<<1)|(t1>>31);
		t1 = array[0];
		array[0] = state[7];
		state[7] = (t1<<3)|(t1>>29);
		t1 = array[0];
		array[0] = state[11];
		state[11] = (t1<<6)|(t1>>26);
		t1 = array[0];
		array[0] = state[17];
		state[17] = (t1<<10)|(t1>>22);
		t1 = array[0];
		array[0] = state[18];
		state[18] = (t1<<15)|(t1>>17);
		t1 = array[0];
		array[0] = state[3];
		state[3] = (t1<<21)|(t1>>11);
		t1 = array[0];
		array[0] = state[5];
		state[5] = (t1<<28)|(t1>>4);
		t1 = array[0];
		array[0] = state[16];
		state[16] = (t1<<4)|(t1>>28);
		t1 = array[0];
		array[0] = state[8];
		state[8] = (t1<<13)|(t1>>19);
		t1 = array[0];
		array[0] = state[21];
		state[21] = (t1<<23)|(t1>>9);
		t1 = array[0];
		array[0] = state[24];
		state[24] = (t1<<2)|(t1>>30);
		t1 = array[0];
		array[0] = state[4];
		state[4] = (t1<<14)|(t1>>18);
		t1 = array[0];
		array[0] = state[15];
		state[15] = (t1<<27)|(t1>>5);
		t1 = array[0];
		array[0] = state[23];
		state[23] = (t1<<9)|(t1>>23);
		t1 = array[0];
		array[0] = state[19];
		state[19] = (t1<<24)|(t1>>8);
		t1 = array[0];
		array[0] = state[13];
		state[13] = (t1<<8)|(t1>>24);
		t1 = array[0];
		array[0] = state[12];
		state[12] = (t1<<25)|(t1>>7);
		t1 = array[0];
		array[0] = state[2];
		state[2] = (t1<<11)|(t1>>21);
		t1 = array[0];
		array[0] = state[20];
		state[20] = (t1<<30)|(t1>>2);
		t1 = array[0];
		array[0] = state[14];
		state[14] = (t1<<18)|(t1>>14);
		t1 = array[0];
		array[0] = state[22];
		state[22] = (t1<<7)|(t1>>25);
		t1 = array[0];
		array[0] = state[9];
		state[9] = (t1<<29)|(t1>>3);
		t1 = array[0];
		array[0] = state[6];
		state[6] = (t1<<20)|(t1>>12);
		t1 = array[0];
		array[0] = state[1];
		state[1] = (t1<<12)|(t1>>20);

		/* chi */
		array[0] = state[0];
		array[1] = state[1];
		array[2] = state[2];
		array[3] = state[3];
		array[4] = state[4];
		state[0] = array[0]^((~array[1])&array[2]);
		state[1] = array[1]^((~array[2])&array[3]);
		state[2] = array[2]^((~array[3])&array[4]);
		state[3] = array[3]^((~array[4])&array[0]);
		state[4] = array[4]^((~array[0])&array[1]);
		array[0] = state[5];
		array[1] = state[6];
		array[2] = state[7];
		array[3] = state[8];
		array[4] = state[9];
		state[5] = array[0]^((~array[1])&array[2]);
		state[6] = array[1]^((~array[2])&array[3]);
		state[7] = array[2]^((~array[3])&array[4]);
		state[8] = array[3]^((~array[4])&array[0]);
		state[9] = array[4]^((~array[0])&array[1]);
		array[0] = state[10];
		array[1] = state[11];
		array[2] = state[12];
		array[3] = state[13];
		array[4] = state[14];
		state[10] = array[0]^((~array[1])&array[2]);
		state[11] = array[1]^((~array[2])&array[3]);
		state[12] = array[2]^((~array[3])&array[4]);
		state[13] = array[3]^((~array[4])&array[0]);
		state[14] = array[4]^((~array[0])&array[1]);
		array[0] = state[15];
		array[1] = state[16];
		array[2] = state[17];
		array[3] = state[18];
		array[4] = state[19];
		state[15] = array[0]^((~array[1])&array[2]);
		state[16] = array[1]^((~array[2])&array[3]);
		state[17] = array[2]^((~array[3])&array[4]);
		state[18] = array[3]^((~array[4])&array[0]);
		state[19] = array[4]^((~array[0])&array[1]);
		array[0] = state[20];
		array[1] = state[21];
		array[2] = state[22];
		array[3] = state[23];
		array[4] = state[24];
		state[20] = array[0]^((~array[1])&array[2]);
		state[21] = array[1]^((~array[2])&array[3]);
		state[22] = array[2]^((~array[3])&array[4]);
		state[23] = array[3]^((~array[4])&array[0]);
		state[24] = array[4]^((~array[0])&array[1]);

		/* iota */
		state[0] ^= round_consts[idx];
	}
}
