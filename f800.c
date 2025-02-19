#include <u.h>

extern void keccak_p800(u32int *state, usize round_count);

void
keccak_f800(u32int *state)
{
	keccak_p800(state, 22);
}
