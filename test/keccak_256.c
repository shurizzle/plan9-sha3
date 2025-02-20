static void
test_keccak_256(void)
{
	static const uchar data1[1] = {
		204
	};
	static const uchar data2[64] = {
		233, 38, 174, 139, 10, 246, 229, 49, 118, 219, 255, 204, 42, 107, 136, 198, 189, 118, 95, 147, 157, 61, 23, 138, 155, 222, 158, 243, 170, 19, 28, 97, 227, 28, 30, 66, 205, 250, 244, 180, 220, 222, 87, 154, 55, 225, 80, 239, 190, 245, 85, 91, 76, 28, 180, 4, 57, 216, 53, 167, 36, 226, 250, 231
	};
	static const struct { uchar *data; usize len; uchar digest[32]; } cases[3] = {
		{nil, 0, {197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
		{data1, 1, {238, 173, 109, 191, 199, 52, 10, 86, 202, 237, 192, 68, 105, 106, 22, 136, 112, 84, 154, 106, 127, 111, 86, 150, 30, 132, 165, 75, 217, 151, 11, 138}},
		{data2, 64, {87, 66, 113, 205, 19, 149, 158, 141, 222, 174, 91, 251, 219, 2, 163, 253, 245, 79, 43, 171, 253, 12, 190, 184, 147, 8, 42, 151, 73, 87, 208, 193}},
	};

	uchar digest[32];
	for(usize i = 0; i < 3; ++i){
		keccak_256(cases[i].data, cases[i].len, digest, nil);
		if(memcmp(digest, cases[i].digest, 32) != 0){
			fail = smprint("keccak_256: case %uzd failed", i);
			return;
		}
		usize cmaxlen = 17;
		if(cases[i].len < 17) cmaxlen = cases[i].len;
		for(usize c = 1; c < cmaxlen; ++c){
			uchar *m = cases[i].data;
			usize l = cases[i].len;
			DigestState *state = nil;
			while(l >= c){
				state = keccak_256(m, c, nil, state);
				m += c;
				l -= c;
			}
			state = keccak_256(m, l, digest, state);
			free(state);
			if(memcmp(digest, cases[i].digest, 32) != 0){
				fail = smprint("keccak_256: case %uzd failed", i);
				return;
			}
		}
	}
}
