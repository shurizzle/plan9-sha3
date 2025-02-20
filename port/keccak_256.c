#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc KECCAK_256 = {
	.size = 32,
	.rate = 136/8,
	.rounds = 24,
	.pad = 1,
};

DigestState*
keccak_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_256);
}
