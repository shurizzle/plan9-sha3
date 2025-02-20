#include <u.h>

extern void keccak_p400(u16int *state, usize round_count);

void
keccak_f400(u16int *state)
{
	keccak_p400(state, 20);
}
