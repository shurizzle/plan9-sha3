#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc CSHAKE_128 = {
	.size = 0,
	.rate = 168/8,
	.rounds = 24,
	.pad = 0,
};

DigestState*
cshake_128(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &CSHAKE_128);
}
