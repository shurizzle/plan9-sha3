#include <u.h>
#include <libc.h>
#include <libsec.h>

static char *fail = nil;

enum
{
	SHA3_224dlen=	28,	/* SHA3-224 digest length */
	SHA3_256dlen=	32,	/* SHA3-256 digest length */
	SHA3_384dlen=	48,	/* SHA3-384 digest length */
	SHA3_512dlen=	64,	/* SHA3-512 digest length */
};

void	keccak_f200(u8int *data);
void	keccak_f400(u16int *data);
void	keccak_f800(u32int *data);
void	keccak_f1600(u64int *data);
DigestState*	sha3_224(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_256(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_384(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_512(uchar*, ulong, uchar*, DigestState*);

static void
test_keccak_f200(void)
{
	/* Test vectors are copied from XKCP (eXtended Keccak Code Package) */
	/* https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-200-IntermediateValues.txt */
	static const u8int state_first[] = {
		0x3C, 0x28, 0x26, 0x84, 0x1C, 0xB3, 0x5C, 0x17, 0x1E, 0xAA, 0xE9, 0xB8,
		0x11, 0x13, 0x4C, 0xEA, 0xA3, 0x85, 0x2C, 0x69, 0xD2, 0xC5, 0xAB, 0xAF,
		0xEA,
	};
	static const u8int state_second[] = {
		0x1B, 0xEF, 0x68, 0x94, 0x92, 0xA8, 0xA5, 0x43, 0xA5, 0x99, 0x9F, 0xDB,
		0x83, 0x4E, 0x31, 0x66, 0xA1, 0x4B, 0xE8, 0x27, 0xD9, 0x50, 0x40, 0x47,
		0x9E,
	};

	u8int state[25];

	assert(sizeof(state) == sizeof(state_first));
	assert(sizeof(state) == sizeof(state_second));
	memset(state, 0, sizeof(state));
	keccak_f200(state);
	if(memcmp(state, state_first, sizeof(state)) != 0){
		fail = "state != state_first";
		return;
	}
	keccak_f200(state);
	if(memcmp(state, state_second, sizeof(state)) != 0){
		fail = "state != state_second";
		return;
	}
}

static void
test_keccak_f400(void)
{
	/* Test vectors are copied from XKCP (eXtended Keccak Code Package) */
	/* https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-400-IntermediateValues.txt */
	static const u16int state_first[] = {
		0x09F5, 0x40AC, 0x0FA9, 0x14F5, 0xE89F, 0xECA0, 0x5BD1, 0x7870, 0xEFF0,
		0xBF8F, 0x0337, 0x6052, 0xDC75, 0x0EC9, 0xE776, 0x5246, 0x59A1, 0x5D81,
		0x6D95, 0x6E14, 0x633E, 0x58EE, 0x71FF, 0x714C, 0xB38E,
	};
	static const u16int state_second[] = {
		0xE537, 0xD5D6, 0xDBE7, 0xAAF3, 0x9BC7, 0xCA7D, 0x86B2, 0xFDEC, 0x692C,
		0x4E5B, 0x67B1, 0x15AD, 0xA7F7, 0xA66F, 0x67FF, 0x3F8A, 0x2F99, 0xE2C2,
		0x656B, 0x5F31, 0x5BA6, 0xCA29, 0xC224, 0xB85C, 0x097C,
	};

	u16int state[25];

	assert(sizeof(state) == sizeof(state_first));
	assert(sizeof(state) == sizeof(state_second));
	memset(state, 0, sizeof(state));
	keccak_f400(state);
	if(memcmp(state, state_first, sizeof(state)) != 0){
		fail = "state != state_first";
		return;
	}
	keccak_f400(state);
	if(memcmp(state, state_second, sizeof(state)) != 0){
		fail = "state != state_second";
		return;
	}
}

static void
test_keccak_f800(void)
{
	/* Test vectors are copied from XKCP (eXtended Keccak Code Package) */
	/* https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt */
	static const u32int state_first[] = {
		0xE531D45D, 0xF404C6FB, 0x23A0BF99, 0xF1F8452F, 0x51FFD042, 0xE539F578, 0xF00B80A7,
		0xAF973664, 0xBF5AF34C, 0x227A2424, 0x88172715, 0x9F685884, 0xB15CD054, 0x1BF4FC0E,
		0x6166FA91, 0x1A9E599A, 0xA3970A1F, 0xAB659687, 0xAFAB8D68, 0xE74B1015, 0x34001A98,
		0x4119EFF3, 0x930A0E76, 0x87B28070, 0x11EFE996,
	};
	static const u32int state_second[] = {
		0x75BF2D0D, 0x9B610E89, 0xC826AF40, 0x64CD84AB, 0xF905BDD6, 0xBC832835, 0x5F8001B9,
		0x15662CCE, 0x8E38C95E, 0x701FE543, 0x1B544380, 0x89ACDEFF, 0x51EDB5DE, 0x0E9702D9,
		0x6C19AA16, 0xA2913EEE, 0x60754E9A, 0x9819063C, 0xF4709254, 0xD09F9084, 0x772DA259,
		0x1DB35DF7, 0x5AA60162, 0x358825D5, 0xB3783BAB,
	};

	u32int state[25];

	assert(sizeof(state) == sizeof(state_first));
	assert(sizeof(state) == sizeof(state_second));
	memset(state, 0, sizeof(state));
	keccak_f800(state);
	if(memcmp(state, state_first, sizeof(state)) != 0){
		fail = "state != state_first";
		return;
	}
	keccak_f800(state);
	if(memcmp(state, state_second, sizeof(state)) != 0){
		fail = "state != state_second";
		return;
	}
}

static void
test_keccak_f1600(void)
{
	/* Test vectors are copied from XKCP (eXtended Keccak Code Package) */
	/* https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt */
	static const u64int state_first[] = {
		0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE,
		0xBD1547306F80494D, 0x8B284E056253D057, 0xFF97A42D7F8E6FD4,
		0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76, 0xAD30A6F71B19059C,
		0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
		0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F,
		0x05E5635A21D9AE61, 0x64BEFEF28CC970F2, 0x613670957BC46611,
		0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8, 0x940C7922AE3A2614,
		0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
		0xEAF1FF7B5CECA249,
	};
	static const u64int state_second[] = {
		0x2D5C954DF96ECB3C, 0x6A332CD07057B56D, 0x093D8D1270D76B6C,
		0x8A20D9B25569D094, 0x4F9C4F99E5E7F156, 0xF957B9A2DA65FB38,
		0x85773DAE1275AF0D, 0xFAF4F247C3D810F7, 0x1F1B9EE6F79A8759,
		0xE4FECC0FEE98B425, 0x68CE61B6B9CE68A1, 0xDEEA66C4BA8F974F,
		0x33C43D836EAFB1F5, 0xE00654042719DBD9, 0x7CF8A9F009831265,
		0xFD5449A6BF174743, 0x97DDAD33D8994B40, 0x48EAD5FC5D0BE774,
		0xE3B8C8EE55B7B03C, 0x91A0226E649E42E9, 0x900E3129E7BADD7B,
		0x202A9EC5FAA3CCE8, 0x5B3402464E1C3DB6, 0x609F4E62A44C1059,
		0x20D06CD26A8FBF5C,
	};

	u64int state[25];

	assert(sizeof(state) == sizeof(state_first));
	assert(sizeof(state) == sizeof(state_second));
	memset(state, 0, sizeof(state));
	keccak_f1600(state);
	if(memcmp(state, state_first, sizeof(state)) != 0){
		fail = "state != state_first";
		return;
	}
	keccak_f1600(state);
	if(memcmp(state, state_second, sizeof(state)) != 0){
		fail = "state != state_second";
		return;
	}
}

#include "sha3_224.c"
#include "sha3_256.c"
#include "sha3_384.c"
#include "sha3_512.c"

void
main(void)
{
	static const struct { char *name; void(*f)(void); } TESTS[] = {
		{"kekkac_f200",  test_keccak_f200},
		{"kekkac_f400",  test_keccak_f400},
		{"kekkac_f800",  test_keccak_f800},
		{"kekkac_f1600", test_keccak_f1600},
		{"sha3_224",     test_sha3_224},
		{"sha3_256",     test_sha3_256},
		{"sha3_384",     test_sha3_384},
		{"sha3_512",     test_sha3_512},
	};
	usize max = 0;
	for(usize i = 0; i < nelem(TESTS); ++i){
		usize l = strlen(TESTS[i].name);
		if(l > max)
			max = l;
	}
	for(usize i = 0; i < nelem(TESTS); ++i){
		fprint(2, "%s...", TESTS[i].name);
		usize dots = max-strlen(TESTS[i].name);
		for(usize n = 0; n < dots; ++n)
			fprint(2, ".");
		fprint(2, " ");

		(TESTS[i].f)();

		if(fail == nil)
			fprint(2, "OK\n");
		else{
			fprint(2, "FAIL\n");
			if(strlen(fail) > 0)
				sysfatal("%s", fail);
			else
				exits("error");
		}
	}
	exits(nil);
}
