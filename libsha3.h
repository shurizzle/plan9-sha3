#pragma	lib	"libsha3.a"

enum
{
	SHA3_224dlen=				28,	/* SHA3-224 digest length */
	SHA3_256dlen=				32,	/* SHA3-256 digest length */
	SHA3_384dlen=				48,	/* SHA3-384 digest length */
	SHA3_512dlen=				64,	/* SHA3-512 digest length */
	KECCAK_224dlen=			28,	/* KECCAK-224 digest length */
	KECCAK_256dlen=			32,	/* KECCAK-256 digest length */
	KECCAK_384dlen=			48,	/* KECCAK-384 digest length */
	KECCAK_512dlen=			64,	/* KECCAK-512 digest length */
	KECCAK_256FULLdlen=	32,	/* KECCAK-256-FULL digest length */
};

typedef struct DigestState SHA3_224state;
typedef struct DigestState SHA3_256state;
typedef struct DigestState SHA3_384state;
typedef struct DigestState SHA3_512state;
typedef struct DigestState KECCAK_224state;
typedef struct DigestState KECCAK_256state;
typedef struct DigestState KECCAK_384state;
typedef struct DigestState KECCAK_512state;
typedef struct DigestState KECCAK_256FULLstate;
typedef struct DigestState SHAKE_128state;
typedef struct DigestState SHAKE_256state;
typedef struct DigestState TurboSHAKE_128state;
typedef struct DigestState TurboSHAKE_256state;
typedef struct DigestState CSHAKE_128state;
typedef struct DigestState CSHAKE_256state;

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
DigestState*	keccak_224(uchar*, ulong, uchar*, DigestState*);
DigestState*	keccak_256(uchar*, ulong, uchar*, DigestState*);
DigestState*	keccak_384(uchar*, ulong, uchar*, DigestState*);
DigestState*	keccak_512(uchar*, ulong, uchar*, DigestState*);
DigestState*	keccak_256full(uchar*, ulong, uchar*, DigestState*);
DigestState*	shake_128(uchar*, ulong, uchar*, ulong, DigestState*);
DigestState*	shake_256(uchar*, ulong, uchar*, ulong, DigestState*);
DigestState*	turboshake_init(uchar, DigestState*);
DigestState*	turboshake_128(uchar*, ulong, uchar*, ulong, DigestState*);
DigestState*	turboshake_256(uchar*, ulong, uchar*, ulong, DigestState*);
DigestState*	cshake_128_init_name(uchar*, usize, uchar*, usize, DigestState*);
DigestState*	cshake_256_init_name(uchar*, usize, uchar*, usize, DigestState*);
DigestState*	cshake_128_init(uchar*, usize, DigestState*);
DigestState*	cshake_256_init(uchar*, usize, DigestState*);
DigestState*	cshake_128(uchar*, ulong, uchar*, ulong, DigestState*);
DigestState*	cshake_256(uchar*, ulong, uchar*, ulong, DigestState*);
