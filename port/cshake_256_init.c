#include <u.h>
#include <libsec.h>
#include "common.h"

DigestState*	cshake_256_init_name(uchar*, usize, uchar*, usize, DigestState*);
DigestState*
cshake_256_init(uchar *customization, usize len, DigestState *s)
{
	return cshake_256_init_name(nil, 0, customization, len, s);
}
