#pragma	lib	"libsha3.a"

enum
{
	SHA3_224dlen=	28,	/* SHA3-224 digest length */
	SHA3_256dlen=	32,	/* SHA3-256 digest length */
	SHA3_384dlen=	48,	/* SHA3-384 digest length */
	SHA3_512dlen=	64,	/* SHA3-512 digest length */
};

typedef struct DigestState SHA3_224state;
typedef struct DigestState SHA3_256state;
typedef struct DigestState SHA3_384state;
typedef struct DigestState SHA3_512state;

void	keccak_p200(u8int *data, usize round_count);
void	keccak_f200(u8int *data);
void	keccak_p400(u16int *data, usize round_count);
void	keccak_f400(u16int *data);
void	keccak_f800(u32int *data, usize round_count);
void	keccak_f800(u32int *data);
void	keccak_f1600(u64int *data, usize round_count);
void	keccak_f1600(u64int *data);

DigestState*	sha3_224(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_256(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_384(uchar*, ulong, uchar*, DigestState*);
DigestState*	sha3_512(uchar*, ulong, uchar*, DigestState*);
