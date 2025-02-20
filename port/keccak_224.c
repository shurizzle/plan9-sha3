#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc KECCAK_224 = {
	.size = 28,
	.rate = 144/8,
	.rounds = 24,
	.pad = 1,
};

DigestState*
keccak_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_224);
}
