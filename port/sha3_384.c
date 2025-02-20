#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc SHA3_384 = {
	.size = 48,
	.rate = 25-2*48/8,
	.rounds = 24,
	.pad = 6,
};

DigestState*
sha3_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_384);
}
