#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc SHA3_512 = {
	.size = 64,
	.rate = 25-2*64/8,
	.rounds = 24,
	.pad = 6,
};

DigestState*
sha3_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_512);
}
