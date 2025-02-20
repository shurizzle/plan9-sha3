static void
test_keccak_384(void)
{
	static const struct { uchar *data; usize len; uchar digest[48]; } cases[1] = {
		{nil, 0, {44, 35, 20, 106, 99, 162, 154, 207, 153, 231, 59, 136, 248, 194, 78, 170, 125, 198, 10, 167, 113, 120, 12, 204, 0, 106, 251, 250, 143, 226, 71, 155, 45, 210, 178, 19, 98, 51, 116, 65, 172, 18, 181, 21, 145, 25, 87, 255}},
	};

	uchar digest[48];
	for(usize i = 0; i < 1; ++i){
		keccak_384(cases[i].data, cases[i].len, digest, nil);
		if(memcmp(digest, cases[i].digest, 48) != 0){
			fail = smprint("keccak_384: case %uzd failed", i);
			return;
		}
		usize cmaxlen = 17;
		if(cases[i].len < 17) cmaxlen = cases[i].len;
		for(usize c = 1; c < cmaxlen; ++c){
			uchar *m = cases[i].data;
			usize l = cases[i].len;
			DigestState *state = nil;
			while(l >= c){
				state = keccak_384(m, c, nil, state);
				m += c;
				l -= c;
			}
			state = keccak_384(m, l, digest, state);
			free(state);
			if(memcmp(digest, cases[i].digest, 48) != 0){
				fail = smprint("keccak_384: case %uzd failed", i);
				return;
			}
		}
	}
}
