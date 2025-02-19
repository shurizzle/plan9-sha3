void
test_turboshake_128(void)
{
	static const uchar output0[32] = {
		90, 34, 58, 211, 11, 59, 140, 102, 162, 67, 4, 140, 252, 237, 67, 15, 84, 231, 82, 146, 135, 209, 81, 80, 185, 115, 19, 58, 223, 172, 106, 47
	};
	static const uchar output1[64] = {
		90, 34, 58, 211, 11, 59, 140, 102, 162, 67, 4, 140, 252, 237, 67, 15, 84, 231, 82, 146, 135, 209, 81, 80, 185, 115, 19, 58, 223, 172, 106, 47, 254, 39, 8, 231, 48, 97, 224, 154, 64, 0, 22, 139, 169, 200, 202, 24, 19, 25, 143, 123, 190, 212, 152, 75, 65, 133, 242, 194, 88, 14, 230, 35
	};
	static const uchar output2[32] = {
		117, 147, 162, 128, 32, 163, 196, 174, 13, 96, 95, 214, 31, 94, 181, 110, 204, 210, 124, 195, 209, 47, 240, 159, 120, 54, 151, 114, 164, 96, 197, 93
	};
	static const uchar output3[32] = {
		26, 194, 212, 80, 252, 59, 66, 5, 209, 157, 167, 191, 202, 27, 55, 81, 60, 8, 3, 87, 122, 199, 22, 127, 6, 254, 44, 225, 240, 239, 57, 229
	};
	static const uchar output4[32] = {
		172, 189, 74, 165, 117, 7, 4, 59, 206, 229, 90, 211, 244, 133, 4, 216, 21, 231, 7, 254, 130, 238, 61, 173, 109, 88, 82, 200, 146, 11, 144, 94
	};
	static const uchar output5[32] = {
		122, 77, 232, 177, 217, 39, 166, 130, 185, 41, 97, 1, 3, 240, 233, 100, 85, 155, 215, 69, 66, 207, 173, 116, 14, 227, 217, 176, 54, 70, 158, 10
	};
	static const uchar output6[32] = {
		116, 82, 237, 14, 216, 96, 170, 143, 232, 231, 150, 153, 236, 227, 36, 248, 217, 50, 113, 70, 54, 16, 218, 118, 128, 30, 188, 238, 79, 202, 254, 66
	};
	static const uchar output7[32] = {
		202, 95, 31, 62, 234, 201, 146, 205, 194, 171, 235, 202, 14, 33, 103, 101, 219, 247, 121, 195, 193, 9, 70, 5, 90, 148, 171, 50, 114, 87, 53, 34
	};
	static const uchar output8[32] = {
		233, 136, 25, 63, 185, 17, 159, 17, 205, 52, 70, 121, 20, 226, 162, 109, 169, 189, 249, 108, 139, 239, 7, 106, 238, 173, 26, 137, 123, 134, 99, 131
	};
	static const uchar output9[32] = {
		156, 15, 251, 152, 126, 238, 237, 173, 250, 85, 148, 137, 135, 117, 109, 9, 11, 103, 204, 182, 18, 54, 227, 6, 172, 138, 36, 222, 29, 10, 247, 116
	};
	static const uchar data10[1] = {
		255
	};
	static const uchar output10[32] = {
		142, 201, 198, 100, 101, 237, 13, 74, 108, 53, 209, 53, 6, 113, 141, 104, 122, 37, 203, 5, 199, 76, 202, 30, 66, 80, 26, 189, 131, 135, 74, 103
	};
	static const uchar data11[3] = {
		255, 255, 255
	};
	static const uchar output11[32] = {
		61, 3, 152, 139, 181, 158, 104, 24, 81, 161, 146, 244, 41, 174, 3, 152, 142, 143, 68, 75, 192, 96, 54, 163, 241, 167, 210, 204, 215, 88, 209, 116
	};
	static const uchar data12[7] = {
		255, 255, 255, 255, 255, 255, 255
	};
	static const uchar output12[32] = {
		5, 217, 174, 103, 61, 95, 14, 72, 187, 43, 87, 232, 128, 33, 161, 168, 61, 112, 186, 133, 146, 58, 160, 76, 18, 232, 246, 91, 161, 249, 69, 149
	};
	static const struct { uchar separator; uchar *data; usize dlen; uchar *digest; usize len; usize truncate; } cases[13] = {
		{7, nil, 0, output0, 32, 0},
		{7, nil, 0, output1, 64, 0},
		{7, nil, 0, output2, 32, 10000},
		{7, nil, 1, output3, 32, 0},
		{7, nil, 17, output4, 32, 0},
		{7, nil, 289, output5, 32, 0},
		{7, nil, 4913, output6, 32, 0},
		{7, nil, 83521, output7, 32, 0},
		{7, nil, 1419857, output8, 32, 0},
		{7, nil, 24137569, output9, 32, 0},
		{6, data10, 1, output10, 32, 0},
		{6, data11, 3, output11, 32, 0},
		{6, data12, 7, output12, 32, 0},
	};

	uchar *digest = malloc(10032);
	for(usize i = 0; i < 13; ++i){
		uchar *buf = nil, *data = cases[i].data;
		if(cases[i].data == nil && cases[i].len != 0){
			buf = malloc(cases[i].dlen);
			if(buf == nil) sysfatal("%r");
			for(usize n = 0; n < cases[i].dlen; ++n)
				buf[n] = (uchar)(n % 0xFB);
			data = buf;
		}
		turboshake_128(data, cases[i].dlen, digest,
				cases[i].len + cases[i].truncate,
				turboshake_init(cases[i].separator, nil));
		if(memcmp(digest + cases[i].truncate, cases[i].digest, cases[i].len) != 0){
			fail = smprint("turboshake_128: case %uzd failed", i);
			free(digest);
			free(buf);
			return;
		}
		usize cmaxlen = 17;
		if(cases[i].dlen < 17) cmaxlen = cases[i].dlen;
		for(usize c = 1; c < cmaxlen; ++c){
			uchar *m = data;
			usize l = cases[i].dlen;
			DigestState *state = turboshake_init(cases[i].separator, nil);
			while(l >= c){
				turboshake_128(m, c, nil, 0, state);
				m += c;
				l -= c;
			}
			turboshake_128(m, l, digest, cases[i].len + cases[i].truncate, state);
			if(memcmp(digest + cases[i].truncate, cases[i].digest, cases[i].len) != 0){
				fail = smprint("turboshake_128: case %uzd failed", i);
				free(digest);
				free(buf);
				return;
			}
		}
		free(buf);
	}
	free(digest);
}
