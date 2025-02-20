#include <u.h>
#include <libc.h>
#include <libsec.h>
#include "common.h"

DigestState*
turboshake_init(uchar separator, DigestState *s)
{
	assert(separator > 0 && separator < 0x80);
	if(s == nil){
		s = mallocz(sizeof(*s), 1);
		if(s == nil)
			return nil;
		s->malloced = 1;
	}else{
		char malloced = s->malloced;
		memset(s, 0, sizeof(*s));
		s->malloced = malloced;
	}
	((SHA3_state*)s)->separator = separator;
	return s;
}
