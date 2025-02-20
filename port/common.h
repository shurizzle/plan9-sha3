#ifdef littleendian
# define readu64(b) (*((u64int*)b))
#else
# define readu64(b)                                                            \
		(((u64int)(b)[0]) |                                                        \
		(((u64int)(b)[1]) <<  8) |                                                 \
		(((u64int)(b)[2]) << 16) |                                                 \
		(((u64int)(b)[3]) << 24) |                                                 \
		(((u64int)(b)[4]) << 32) |                                                 \
		(((u64int)(b)[5]) << 40) |                                                 \
		(((u64int)(b)[6]) << 48) |                                                 \
		(((u64int)(b)[7]) << 56))
#endif

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
SHA3_state	*_sha3run(const uchar*, ulong, uchar*, SHA3_state*,
		const SHA3Desc*);
DigestState	*_sha3xof(const uchar*, ulong, uchar*, ulong, DigestState*,
		const SHA3Desc*);
