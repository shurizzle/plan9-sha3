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

void	keccak_f1600(u64int *data);

static SHA3_state*
sha3(const uchar *data, ulong dlen, uchar *digest, SHA3_state *s, usize size)
{
	usize flen;

	if(s == nil){
		s = mallocz(sizeof(DigestState), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}

	flen = 25-2*size/8;

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
			if(s->len == flen){
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
		if(s->len == flen){
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

	s->buf[s->blen++] = 6;
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
	s->state[flen-1] ^= 0x8000000000000000ULL;
	keccak_f1600(s->state);
	memcpy(digest, s->state, size);

	if(s->malloced == 1)
		free(s);
	return nil;
}

DigestState*
sha3_224(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, 28);
}

DigestState*
sha3_256(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, 32);
}

DigestState*
sha3_384(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, 48);
}

DigestState*
sha3_512(const uchar *data, ulong dlen, uchar *digest, DigestState *s)
{
	return (DigestState*)sha3(data, dlen, digest, (SHA3_state*)s, 64);
}
