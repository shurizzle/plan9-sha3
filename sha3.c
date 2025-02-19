#include <u.h>
#include <libc.h>
#include <libsec.h>

#define readu64(b)                                                             \
		(((u64int)(b)[0]) |                                                        \
		(((u64int)(b)[1]) <<  8) |                                                 \
		(((u64int)(b)[2]) << 16) |                                                 \
		(((u64int)(b)[3]) << 24) |                                                 \
		(((u64int)(b)[4]) << 32) |                                                 \
		(((u64int)(b)[5]) << 40) |                                                 \
		(((u64int)(b)[6]) << 48) |                                                 \
		(((u64int)(b)[7]) << 56))

#define absorb(v, l, r, rounds)                                                \
	do{                                                                          \
		if(s->blen != 0){                                                          \
			while(s->blen < 8 && l > 0){                                             \
				s->buf[s->blen++] = v[0];                                              \
				v += 1;                                                                \
				l -= 1;                                                                \
			}                                                                        \
			if(s->blen == 8){                                                        \
				s->blen = 0;                                                           \
				s->state[s->len++] ^= readu64(s->buf);                                 \
				if(s->len == r){                                                       \
					s->len = 0;                                                          \
					keccak_p1600(s->state, rounds);                                      \
				}                                                                      \
			}                                                                        \
		}                                                                          \
		while(l >= 8){                                                             \
			s->state[s->len++] ^= readu64(v);                                        \
			v += 8;                                                                  \
			l -= 8;                                                                  \
			if(s->len == r){                                                         \
				s->len = 0;                                                            \
				keccak_p1600(s->state, rounds);                                        \
			}                                                                        \
		}                                                                          \
		while(l > 0){                                                              \
			s->buf[s->blen++] = v[0];                                                \
			v += 1;                                                                  \
			l -= 1;                                                                  \
		}                                                                          \
	}while(0)

typedef struct SHA3_state SHA3_state;
struct SHA3_state
{
	uvlong	len;
	u64int	state[25];
	uchar	buf[8];
	uchar	separator;
	uchar	_pad[111];
	int	blen;
	char	malloced;
	char	seeded;
};

typedef struct SHA3Desc SHA3Desc;
struct SHA3Desc
{
	usize size;
	usize rate;
	usize rounds;
	uchar pad;
};

void	keccak_p1600(u64int*, usize);

static SHA3_state*
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

static const SHA3Desc SHA3_224 = {
	.size = 28,
	.rate = 25-2*28/8,
	.rounds = 24,
	.pad = 6,
};

static const SHA3Desc SHA3_256 = {
	.size = 32,
	.rate = 25-2*32/8,
	.rounds = 24,
	.pad = 6,
};

static const SHA3Desc SHA3_384 = {
	.size = 48,
	.rate = 25-2*48/8,
	.rounds = 24,
	.pad = 6,
};

static const SHA3Desc SHA3_512 = {
	.size = 64,
	.rate = 25-2*64/8,
	.rounds = 24,
	.pad = 6,
};

static const SHA3Desc KECCAK_224 = {
	.size = 28,
	.rate = 144/8,
	.rounds = 24,
	.pad = 1,
};

static const SHA3Desc KECCAK_256 = {
	.size = 32,
	.rate = 136/8,
	.rounds = 24,
	.pad = 1,
};

static const SHA3Desc KECCAK_384 = {
	.size = 48,
	.rate = 104/8,
	.rounds = 24,
	.pad = 1,
};

static const SHA3Desc KECCAK_512 = {
	.size = 64,
	.rate = 72/8,
	.rounds = 24,
	.pad = 1,
};

static const SHA3Desc KECCAK_256FULL = {
	.size = 200,
	.rate = 136/8,
	.rounds = 24,
	.pad = 1,
};

static const SHA3Desc SHAKE_128 = {
	.size = 0,
	.rate = 168/8,
	.rounds = 24,
	.pad = 0x1f,
};

static const SHA3Desc SHAKE_256 = {
	.size = 0,
	.rate = 136/8,
	.rounds = 24,
	.pad = 0x1f,
};

static const SHA3Desc TURBOSHAKE_128 = {
	.size = 0,
	.rate = 168/8,
	.rounds = 12,
	.pad = 0,
};

static const SHA3Desc TURBOSHAKE_256 = {
	.size = 0,
	.rate = 136/8,
	.rounds = 12,
	.pad = 0,
};

static const SHA3Desc CSHAKE_128 = {
	.size = 0,
	.rate = 168/8,
	.rounds = 24,
	.pad = 0,
};

static const SHA3Desc CSHAKE_256 = {
	.size = 0,
	.rate = 136/8,
	.rounds = 24,
	.pad = 0,
};

DigestState*
sha3_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_224);
}

DigestState*
sha3_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_256);
}

DigestState*
sha3_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_384);
}

DigestState*
sha3_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &SHA3_512);
}

DigestState*
keccak_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_224);
}

DigestState*
keccak_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_256);
}

DigestState*
keccak_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_384);
}

DigestState*
keccak_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_512);
}

DigestState*
keccak_256full(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)_sha3run(data, dlen, digest, (SHA3_state*)s, &KECCAK_256FULL);
}

static DigestState*
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

DigestState*
shake_128(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &SHAKE_128);
}

DigestState*
shake_256(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &SHAKE_256);
}

DigestState*
turboshake_init(uchar separator, DigestState *s)
{
	assert(separator > 0 && separator < 0x80);
	if(s == nil){
		s = mallocz(sizeof(*s), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}else{
		char malloced = s->malloced;
		memset(s, 0, sizeof(*s));
		s->malloced = malloced;
	}
	((SHA3_state*)s)->separator = separator;
	return s;
}

DigestState*
turboshake_128(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &TURBOSHAKE_128);
}

DigestState*
turboshake_256(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &TURBOSHAKE_256);
}

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

DigestState*
cshake_128_init(uchar *customization, usize len, DigestState *s)
{
	return cshake_128_init_name(nil, 0, customization, len, s);
}

DigestState*
cshake_256_init(uchar *customization, usize len, DigestState *s)
{
	return cshake_256_init_name(nil, 0, customization, len, s);
}

DigestState*
cshake_128(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &CSHAKE_128);
}

DigestState*
cshake_256(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return _sha3xof(data, dlen, digest, len, s, &CSHAKE_256);
}
