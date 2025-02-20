#include <u.h>
#include <libc.h>
#include <libsec.h>
#include "common.h"

SHA3_state*
_sha3run(const uchar *data, ulong dlen, uchar *digest, SHA3_state *s,
		const SHA3Desc *desc)
{
	if(s == nil){
		s = mallocz(sizeof(DigestState), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}

	absorb(data, dlen, desc->rate, desc->rounds);

	if(digest == nil)
		return s;

	s->buf[s->blen++] = desc->pad == 0 ? s->separator : desc->pad;
	while(s->blen < 8)
		s->buf[s->blen++] = 0;
	s->state[s->len++] ^= readu64(s->buf);
	s->state[desc->rate-1] ^= 0x8000000000000000ULL;
	keccak_p1600(s->state, desc->rounds);

	if(desc->size == 0)
		return s;

	memcpy(digest, s->state, desc->size);

	if(s->malloced == 1)
		free(s);
	return nil;
}
