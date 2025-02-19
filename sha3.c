#include <u.h>
#include <libc.h>
#include <libsec.h>

typedef struct SHA3_state SHA3_state;
struct SHA3_state
{
	uvlong	len;
	u64int	state[25];
	uchar	buf[120];
	int	blen;
	char	malloced;
	char	seeded;
};

typedef struct SHA3Desc SHA3Desc;
struct SHA3Desc
{
	usize size;
	usize rate;
	u8int pad;
};

void	keccak_f1600(u64int *data);

static SHA3_state*
sha3(const uchar *data, ulong dlen, uchar *digest, SHA3_state *s,
		const SHA3Desc *desc)
{
	if(s == nil){
		s = mallocz(sizeof(DigestState), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}

	if(s->blen != 0){
		while(s->blen < 8 && dlen > 0){
			s->buf[s->blen++] = *data;
			data += 1;
			dlen -= 1;
		}

		if(s->blen == 8){
			s->blen = 0;
			s->state[s->len++] ^= ((u64int)s->buf[0]) |
				(((u64int)s->buf[1]) <<  8) |
				(((u64int)s->buf[2]) << 16) |
				(((u64int)s->buf[3]) << 24) |
				(((u64int)s->buf[4]) << 32) |
				(((u64int)s->buf[5]) << 40) |
				(((u64int)s->buf[6]) << 48) |
				(((u64int)s->buf[7]) << 56);
			if(s->len == desc->rate){
				s->len = 0;
				keccak_f1600(s->state);
			}
		}
	}

	while(dlen > 7){
		s->state[s->len++] ^= ((u64int)data[0]) |
			(((u64int)data[1]) <<  8) |
			(((u64int)data[2]) << 16) |
			(((u64int)data[3]) << 24) |
			(((u64int)data[4]) << 32) |
			(((u64int)data[5]) << 40) |
			(((u64int)data[6]) << 48) |
			(((u64int)data[7]) << 56);
		data += 8;
		dlen -= 8;
		if(s->len == desc->rate){
			s->len = 0;
			keccak_f1600(s->state);
		}
	}

	while(dlen > 0){
		s->buf[s->blen++] = *data;
		data += 1;
		dlen -= 1;
	}

	if(digest == nil)
		return s;

	s->buf[s->blen++] = desc->pad;
	while(s->blen < 8)
		s->buf[s->blen++] = 0;
	s->state[s->len++] ^= ((u64int)s->buf[0]) |
		(((u64int)s->buf[1]) <<  8) |
		(((u64int)s->buf[2]) << 16) |
		(((u64int)s->buf[3]) << 24) |
		(((u64int)s->buf[4]) << 32) |
		(((u64int)s->buf[5]) << 40) |
		(((u64int)s->buf[6]) << 48) |
		(((u64int)s->buf[7]) << 56);
	s->state[desc->rate-1] ^= 0x8000000000000000ULL;
	keccak_f1600(s->state);

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
	.pad = 6,
};

static const SHA3Desc SHA3_256 = {
	.size = 32,
	.rate = 25-2*32/8,
	.pad = 6,
};

static const SHA3Desc SHA3_384 = {
	.size = 48,
	.rate = 25-2*48/8,
	.pad = 6,
};

static const SHA3Desc SHA3_512 = {
	.size = 64,
	.rate = 25-2*64/8,
	.pad = 6,
};

static const SHA3Desc KECCAK_224 = {
	.size = 28,
	.rate = 144/8,
	.pad = 1,
};

static const SHA3Desc KECCAK_256 = {
	.size = 32,
	.rate = 136/8,
	.pad = 1,
};

static const SHA3Desc KECCAK_384 = {
	.size = 48,
	.rate = 104/8,
	.pad = 1,
};

static const SHA3Desc KECCAK_512 = {
	.size = 64,
	.rate = 72/8,
	.pad = 1,
};

static const SHA3Desc KECCAK_256FULL = {
	.size = 200,
	.rate = 136/8,
	.pad = 1,
};

static const SHA3Desc SHAKE_128 = {
	.size = 0,
	.rate = 168/8,
	.pad = 0x1f,
};

static const SHA3Desc SHAKE_256 = {
	.size = 0,
	.rate = 136/8,
	.pad = 0x1f,
};

DigestState*
sha3_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &SHA3_224);
}

DigestState*
sha3_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &SHA3_256);
}

DigestState*
sha3_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &SHA3_384);
}

DigestState*
sha3_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &SHA3_512);
}

DigestState*
keccak_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &KECCAK_224);
}

DigestState*
keccak_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &KECCAK_256);
}

DigestState*
keccak_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &KECCAK_384);
}

DigestState*
keccak_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &KECCAK_512);
}

DigestState*
keccak_256full(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, &KECCAK_256FULL);
}

static DigestState*
sha3xof(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *state, const SHA3Desc *desc)
{
	usize brate;
	SHA3_state *s;

	s = sha3(data, dlen, digest, (SHA3_state*)state, desc);

	if(s == nil || digest == nil)
		return (DigestState*)s;

	brate = desc->rate*8;
	while(len > brate){
		memcpy(digest, s->state, brate);
		keccak_f1600(s->state);
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
	return sha3xof(data, dlen, digest, len, s, &SHAKE_128);
}

DigestState*
shake_256(const uchar *data, ulong dlen, uchar *digest, ulong len,
		DigestState *s)
{
	return sha3xof(data, dlen, digest, len, s, &SHAKE_256);
}
