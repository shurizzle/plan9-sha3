#include <u.h>
#include <libsec.h>
#include "common.h"

static const SHA3Desc SHAKE_256 = {
	.size = 0,
	.rate = 136/8,
	.rounds = 24,
	.pad = 0x1f,
};

DigestState*
shake_256(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &SHAKE_256);
}
