#include <u.h>

extern void keccak_p200(u8int *state, usize round_count);

void
keccak_f200(u8int *state)
{
	keccak_p200(state, 18);
}
