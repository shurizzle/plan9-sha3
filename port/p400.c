#include <u.h>
#include <libc.h>

static const u16int RC[24] = {
	0x0001,
	0x8082,
	0x808a,
	0x8000,
	0x808b,
	0x0001,
	0x8081,
	0x8009,
	0x008a,
	0x0088,
	0x8009,
	0x000a,
	0x808b,
	0x008b,
	0x8089,
	0x8003,
	0x8002,
	0x0080,
	0x800a,
	0x000a,
	0x8081,
	0x8080,
	0x0001,
	0x8008
};

void
keccak_p400(u16int *state, usize round_count)
{
	u16int t1, array[5], *round_consts;

	if(round_count > 20){
		fprint(2, "keccak_p400: invalid round count %uzd\n", round_count);
		abort();
	}

	round_consts = &RC[20-round_count];
	for(usize idx = 0; idx < round_count; ++idx){
		array[0] = state[0];
		array[0] ^= state[5];
		array[0] ^= state[10];
		array[0] ^= state[15];
		array[0] ^= state[20];
		array[1] = state[1];
		array[1] ^= state[6];
		array[1] ^= state[11];
		array[1] ^= state[16];
		array[1] ^= state[21];
		array[2] = state[2];
		array[2] ^= state[7];
		array[2] ^= state[12];
		array[2] ^= state[17];
		array[2] ^= state[22];
		array[3] = state[3];
		array[3] ^= state[8];
		array[3] ^= state[13];
		array[3] ^= state[18];
		array[3] ^= state[23];
		array[4] = state[4];
		array[4] ^= state[9];
		array[4] ^= state[14];
		array[4] ^= state[19];
		array[4] ^= state[24];
		t1 = array[1];
		t1 = (t1<<1)|(t1>>15);
		t1 = array[4]^t1;
		state[0] ^= t1;
		state[5] ^= t1;
		state[10] ^= t1;
		state[15] ^= t1;
		state[20] ^= t1;
		t1 = array[2];
		t1 = (t1<<1)|(t1>>15);
		t1 = array[0]^t1;
		state[1] ^= t1;
		state[6] ^= t1;
		state[11] ^= t1;
		state[16] ^= t1;
		state[21] ^= t1;
		t1 = array[3];
		t1 = (t1<<1)|(t1>>15);
		t1 = array[1]^t1;
		state[2] ^= t1;
		state[7] ^= t1;
		state[12] ^= t1;
		state[17] ^= t1;
		state[22] ^= t1;
		t1 = array[4];
		t1 = (t1<<1)|(t1>>15);
		t1 = array[2]^t1;
		state[3] ^= t1;
		state[8] ^= t1;
		state[13] ^= t1;
		state[18] ^= t1;
		state[23] ^= t1;
		t1 = array[0];
		t1 = (t1<<1)|(t1>>15);
		t1 = array[3]^t1;
		state[4] ^= t1;
		state[9] ^= t1;
		state[14] ^= t1;
		state[19] ^= t1;
		state[24] ^= t1;

		/* rho and pi */
		t1 = state[1];
		array[0] = state[10];
		state[10] = (t1<<1)|(t1>>15);
		t1 = array[0];
		array[0] = state[7];
		state[7] = (t1<<3)|(t1>>13);
		t1 = array[0];
		array[0] = state[11];
		state[11] = (t1<<6)|(t1>>10);
		t1 = array[0];
		array[0] = state[17];
		state[17] = (t1<<10)|(t1>>6);
		t1 = array[0];
		array[0] = state[18];
		state[18] = (t1<<15)|(t1>>1);
		t1 = array[0];
		array[0] = state[3];
		state[3] = (t1<<5)|(t1>>11);
		t1 = array[0];
		array[0] = state[5];
		state[5] = (t1<<12)|(t1>>4);
		t1 = array[0];
		array[0] = state[16];
		state[16] = (t1<<4)|(t1>>12);
		t1 = array[0];
		array[0] = state[8];
		state[8] = (t1<<13)|(t1>>3);
		t1 = array[0];
		array[0] = state[21];
		state[21] = (t1<<7)|(t1>>9);
		t1 = array[0];
		array[0] = state[24];
		state[24] = (t1<<2)|(t1>>14);
		t1 = array[0];
		array[0] = state[4];
		state[4] = (t1<<14)|(t1>>2);
		t1 = array[0];
		array[0] = state[15];
		state[15] = (t1<<11)|(t1>>5);
		t1 = array[0];
		array[0] = state[23];
		state[23] = (t1<<9)|(t1>>7);
		t1 = array[0];
		array[0] = state[19];
		state[19] = (t1<<8)|(t1>>8);
		t1 = array[0];
		array[0] = state[13];
		state[13] = (t1<<8)|(t1>>8);
		t1 = array[0];
		array[0] = state[12];
		state[12] = (t1<<9)|(t1>>7);
		t1 = array[0];
		array[0] = state[2];
		state[2] = (t1<<11)|(t1>>5);
		t1 = array[0];
		array[0] = state[20];
		state[20] = (t1<<14)|(t1>>2);
		t1 = array[0];
		array[0] = state[14];
		state[14] = (t1<<2)|(t1>>14);
		t1 = array[0];
		array[0] = state[22];
		state[22] = (t1<<7)|(t1>>9);
		t1 = array[0];
		array[0] = state[9];
		state[9] = (t1<<13)|(t1>>3);
		t1 = array[0];
		array[0] = state[6];
		state[6] = (t1<<4)|(t1>>12);
		t1 = array[0];
		array[0] = state[1];
		state[1] = (t1<<12)|(t1>>4);

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
