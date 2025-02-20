static void
test_keccak_512(void)
{
	static const struct { uchar *data; usize len; uchar digest[64]; } cases[1] = {
		{nil, 0, {14, 171, 66, 222, 76, 60, 235, 146, 53, 252, 145, 172, 255, 231, 70, 178, 156, 41, 168, 195, 102, 183, 198, 14, 78, 103, 196, 102, 243, 106, 67, 4, 192, 15, 169, 202, 249, 216, 121, 118, 186, 70, 155, 203, 224, 103, 19, 180, 53, 240, 145, 239, 39, 105, 251, 22, 12, 218, 179, 61, 54, 112, 104, 14}},
	};

	uchar digest[64];
	for(usize i = 0; i < 1; ++i){
		keccak_512(cases[i].data, cases[i].len, digest, nil);
		if(memcmp(digest, cases[i].digest, 64) != 0){
			fail = smprint("keccak_512: case %uzd failed", i);
			return;
		}
	}
}
