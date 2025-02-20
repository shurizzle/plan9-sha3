#include <u.h>

extern void keccak_p1600(u64int *state, usize round_count);

void
keccak_f1600(u64int *state)
{
	keccak_p1600(state, 24);
}
