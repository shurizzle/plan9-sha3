#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc SHA3_256 = {
	.size = 32,
	.rate = 25-2*32/8,
	.rounds = 24,
	.pad = 6,
};

DigestState*
sha3_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_256);
}
