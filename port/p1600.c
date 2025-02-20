#include <u.h>
#include <libc.h>

static const u64int RC[24] = {
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};
void
keccak_p1600(u64int *state, usize round_count)
{
	u64int t1;

	if(round_count > 24){
		fprint(2, "keccak_p1600: invalid round count %uzd\n", round_count);
		abort();
	}

	u64int *round_consts = &RC[24-round_count];
	for(usize idx = 0; idx < round_count; ++idx){
		u64int array[5] = {0, 0, 0, 0, 0};

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
		t1 = (t1<<1)|(t1>>63);
		t1 = array[4]^t1;
		state[0] ^= t1;
		state[5] ^= t1;
		state[10] ^= t1;
		state[15] ^= t1;
		state[20] ^= t1;
		t1 = array[2];
		t1 = (t1<<1)|(t1>>63);
		t1 = array[0]^t1;
		state[1] ^= t1;
		state[6] ^= t1;
		state[11] ^= t1;
		state[16] ^= t1;
		state[21] ^= t1;
		t1 = array[3];
		t1 = (t1<<1)|(t1>>63);
		t1 = array[1]^t1;
		state[2] ^= t1;
		state[7] ^= t1;
		state[12] ^= t1;
		state[17] ^= t1;
		state[22] ^= t1;
		t1 = array[4];
		t1 = (t1<<1)|(t1>>63);
		t1 = array[2]^t1;
		state[3] ^= t1;
		state[8] ^= t1;
		state[13] ^= t1;
		state[18] ^= t1;
		state[23] ^= t1;
		t1 = array[0];
		t1 = (t1<<1)|(t1>>63);
		t1 = array[3]^t1;
		state[4] ^= t1;
		state[9] ^= t1;
		state[14] ^= t1;
		state[19] ^= t1;
		state[24] ^= t1;

		/* rho and pi */
		t1 = state[1];
		array[0] = state[10];
		state[10] = (t1<<1)|(t1>>63);
		t1 = array[0];
		array[0] = state[7];
		state[7] = (t1<<3)|(t1>>61);
		t1 = array[0];
		array[0] = state[11];
		state[11] = (t1<<6)|(t1>>58);
		t1 = array[0];
		array[0] = state[17];
		state[17] = (t1<<10)|(t1>>54);
		t1 = array[0];
		array[0] = state[18];
		state[18] = (t1<<15)|(t1>>49);
		t1 = array[0];
		array[0] = state[3];
		state[3] = (t1<<21)|(t1>>43);
		t1 = array[0];
		array[0] = state[5];
		state[5] = (t1<<28)|(t1>>36);
		t1 = array[0];
		array[0] = state[16];
		state[16] = (t1<<36)|(t1>>28);
		t1 = array[0];
		array[0] = state[8];
		state[8] = (t1<<45)|(t1>>19);
		t1 = array[0];
		array[0] = state[21];
		state[21] = (t1<<55)|(t1>>9);
		t1 = array[0];
		array[0] = state[24];
		state[24] = (t1<<2)|(t1>>62);
		t1 = array[0];
		array[0] = state[4];
		state[4] = (t1<<14)|(t1>>50);
		t1 = array[0];
		array[0] = state[15];
		state[15] = (t1<<27)|(t1>>37);
		t1 = array[0];
		array[0] = state[23];
		state[23] = (t1<<41)|(t1>>23);
		t1 = array[0];
		array[0] = state[19];
		state[19] = (t1<<56)|(t1>>8);
		t1 = array[0];
		array[0] = state[13];
		state[13] = (t1<<8)|(t1>>56);
		t1 = array[0];
		array[0] = state[12];
		state[12] = (t1<<25)|(t1>>39);
		t1 = array[0];
		array[0] = state[2];
		state[2] = (t1<<43)|(t1>>21);
		t1 = array[0];
		array[0] = state[20];
		state[20] = (t1<<62)|(t1>>2);
		t1 = array[0];
		array[0] = state[14];
		state[14] = (t1<<18)|(t1>>46);
		t1 = array[0];
		array[0] = state[22];
		state[22] = (t1<<39)|(t1>>25);
		t1 = array[0];
		array[0] = state[9];
		state[9] = (t1<<61)|(t1>>3);
		t1 = array[0];
		array[0] = state[6];
		state[6] = (t1<<20)|(t1>>44);
		t1 = array[0];
		array[0] = state[1];
		state[1] = (t1<<44)|(t1>>20);

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
