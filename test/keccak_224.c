static void
test_keccak_224(void)
{
	static const struct { uchar *data; usize len; uchar digest[28]; } cases[1] = {
		{nil, 0, {247, 24, 55, 80, 43, 168, 225, 8, 55, 189, 216, 211, 101, 173, 184, 85, 145, 137, 86, 2, 252, 85, 43, 72, 183, 57, 10, 189}},
	};

	uchar digest[28];
	for(usize i = 0; i < 1; ++i){
		keccak_224(cases[i].data, cases[i].len, digest, nil);
		if(memcmp(digest, cases[i].digest, 28) != 0){
			fail = smprint("keccak_224: case %uzd failed", i);
			return;
		}
		usize cmaxlen = 17;
		if(cases[i].len < 17) cmaxlen = cases[i].len;
		for(usize c = 1; c < cmaxlen; ++c){
			uchar *m = cases[i].data;
			usize l = cases[i].len;
			DigestState *state = nil;
			while(l >= c){
				state = keccak_224(m, c, nil, state);
				m += c;
				l -= c;
			}
			state = keccak_224(m, l, digest, state);
			free(state);
			if(memcmp(digest, cases[i].digest, 28) != 0){
				fail = smprint("keccak_224: case %uzd failed", i);
				return;
			}
		}
	}
}
