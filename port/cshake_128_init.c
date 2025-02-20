#include <u.h>
#include <libsec.h>
#include "common.h"

DigestState*	cshake_128_init_name(uchar*, usize, uchar*, usize, DigestState*);
DigestState*
cshake_128_init(uchar *customization, usize len, DigestState *s)
{
	return cshake_128_init_name(nil, 0, customization, len, s);
}
