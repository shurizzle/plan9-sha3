#include <u.h>
#include <libc.h>
#include <libsec.h>
#include "common.h"

#define leftencode(v)                                                          \
	do{                                                                          \
		nbuf[1] = (uchar)((v) >> 56);                                              \
		nbuf[2] = (uchar)((v) >> 48);                                              \
		nbuf[3] = (uchar)((v) >> 40);                                              \
		nbuf[4] = (uchar)((v) >> 32);                                              \
		nbuf[5] = (uchar)((v) >> 24);                                              \
		nbuf[6] = (uchar)((v) >> 16);                                              \
		nbuf[7] = (uchar)((v) >> 8);                                               \
		nbuf[8] = (uchar)(v);                                                      \
		len = 0;                                                                   \
		for(n = 1; n < 8 && nbuf[n] == 0; ++n) len++;                              \
		nbuf[len] = (uchar)(8-len);                                                \
		b = &nbuf[len];                                                            \
		len = 9-len;                                                               \
	}while(0)

static SHA3_state*
cshake_init_name(uchar *name, usize nlen, uchar *customization, usize clen,
		usize rate, SHA3_state *s)
{
	u64int v64;
	uchar nbuf[9], *b;
	usize len, n;

	assert((nlen&7) == 0);

	if(s == nil){
		s = mallocz(sizeof(*s), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}else{
		char m = s->malloced;
		memset(s, 0, sizeof(*s));
		s->malloced = m;
	}

	if(nlen == 0 && clen == 0){
		s->separator = 0x1f;
		return s;
	}

	s->separator = 4;

	v64 = (u64int)rate*8;
	leftencode(v64);
	absorb(b, len, rate, 24);

	v64 = (u64int)nlen*8;
	leftencode(v64);
	absorb(b, len, rate, 24);

	len = nlen;
	b = name;
	absorb(b, len, rate, 24);

	v64 = (u64int)clen*8;
	leftencode(v64);
	absorb(b, len, rate, 24);

	len = clen;
	b = customization;
	absorb(b, len, rate, 24);

	if(s->blen != 0){
		while(s->blen < 8)
			s->buf[s->blen++] = 0;
		s->blen = 0;
		s->state[s->len++] ^= readu64(s->buf);
	}
	if(s->len != 0)
		keccak_p1600(s->state, 24);
	s->len = 0;

	return s;
}

DigestState*
cshake_128_init_name(uchar *name, usize nlen, uchar *customization,
		usize clen, DigestState *s)
{
	return (DigestState*)cshake_init_name(name, nlen, customization, clen,
			168/8, (SHA3_state*)s);
}

DigestState*
cshake_256_init_name(uchar *name, usize nlen, uchar *customization,
		usize clen, DigestState *s)
{
	return (DigestState*)cshake_init_name(name, nlen, customization, clen,
			136/8, (SHA3_state*)s);
}
