#include <u.h>
#include <libc.h>
#include <libsec.h>
#include "common.h"

DigestState*
_sha3xof(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *state, const SHA3Desc *desc)
{
	usize brate;
	SHA3_state *s;

	s = _sha3run(data, dlen, digest, (SHA3_state*)state, desc);

	if(s == nil || digest == nil)
		return (DigestState*)s;

	brate = desc->rate*8;
	while(len > brate){
		memcpy(digest, s->state, brate);
		keccak_p1600(s->state, desc->rounds);
		digest += brate;
		len -= brate;
	}
	memcpy(digest, s->state, len);

	if(s->malloced == 1)
		free(s);
	return nil;
}
