#include <u.h>
#include <libc.h>
#include <bio.h>

static const char *RC[] = {
	"0000000000000001",
	"0000000000008082",
	"800000000000808a",
	"8000000080008000",
	"000000000000808b",
	"0000000080000001",
	"8000000080008081",
	"8000000000008009",
	"000000000000008a",
	"0000000000000088",
	"0000000080008009",
	"000000008000000a",
	"000000008000808b",
	"800000000000008b",
	"8000000000008089",
	"8000000000008003",
	"8000000000008002",
	"8000000000000080",
	"000000000000800a",
	"800000008000000a",
	"8000000080008081",
	"8000000000008080",
	"0000000080000001",
	"8000000080008008"
};

static const u32int RHO[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27,
	41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const usize PI_[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

void
print_rc(Biobuf *bp, char *t, usize width)
{
	usize off = 16-width*2;
	Bprint(bp, "static const %s RC[24] = {\n", t);
	for(usize i = 0; i < nelem(RC); ++i){
		if(i != 0)
			Bprint(bp, ",\n");
		Bprint(bp, "\t0x%s", RC[i]+off);
	}
	Bprint(bp, "\n};\n");
}

void
print_rotl(Biobuf *bp, char *expr, u32int n, usize width)
{
	n = n%((u32int)width * 8);
	if(n == 0){
		Bprint(bp, "%s", expr);
		return;
	}
	Bprint(bp, "(%s<<%uld)|(%s>>%uld)", expr, n, expr, width*8-n);
}

void
print_pn(Biobuf *bp, char *t, usize width, usize f_round_count)
{
	Bprint(bp, "#include <u.h>\n#include <libc.h>\n\n");
	print_rc(bp, t, width);
	Bprint(bp, "\nvoid\nkeccak_p%uzd(%s *state, usize round_count)\n{\n",
			width*200, t);
	Bprint(bp, "\t%s t1, array[5], *round_consts;\n\n", t);
	Bprint(bp, "\tif(round_count > %uzd){\n", f_round_count);
	Bprint(bp, "\t\tfprint(2, \"keccak_p%uzd: invalid round count %%uzd\\n\""
			", round_count);\n", width*200);
	Bprint(bp, "\t\tabort();\n");
	Bprint(bp, "\t}\n\n");
	Bprint(bp, "\tround_consts = &RC[%uzd-round_count];\n", f_round_count);
	Bprint(bp, "\tfor(usize idx = 0; idx < round_count; ++idx){\n");

	for(usize x = 0; x < 5; ++x)
		for(usize y = 0; y < 5; ++y)
			Bprint(bp, "\t\tarray[%uzd] %s= state[%uzd];\n",
					x, y == 0 ? "" : "^", 5*y+x);

	for(usize x = 0; x < 5; ++x){
		Bprint(bp, "\t\tt1 = array[%uzd];\n", (x+1)%5);
		Bprint(bp, "\t\tt1 = (t1<<1)|(t1>>%uzd);\n", width*8-1);
		Bprint(bp, "\t\tt1 = array[%uzd]^t1;\n", (x+4)%5);
		for(usize y = 0; y < 5; ++y)
			Bprint(bp, "\t\tstate[%uzd] ^= t1;\n", 5*y+x);
	}

	Bprint(bp, "\n\t\t/* rho and pi */\n");
	Bprint(bp, "\t\tt1 = state[1];\n");
	Bprint(bp, "\t\tarray[0] = state[%uzd];\n", PI_[0]);
	Bprint(bp, "\t\tstate[%uzd] = ", PI_[0]);
	print_rotl(bp, "t1", RHO[0], width);
	Bprint(bp, ";\n");
	for(usize x = 1; x < 24; ++x){
		Bprint(bp, "\t\tt1 = array[0];\n");
		Bprint(bp, "\t\tarray[0] = state[%uzd];\n", PI_[x]);
		Bprint(bp, "\t\tstate[%uzd] = ", PI_[x]);
		print_rotl(bp, "t1", RHO[x], width);
		Bprint(bp, ";\n");
	}

	Bprint(bp, "\n\t\t/* chi */\n");
	for(usize y_step = 0; y_step < 5; ++y_step){
		usize y = 5*y_step;
		for(usize x = 0; x < 5; ++x)
			Bprint(bp, "\t\tarray[%uzd] = state[%uzd];\n", x, y+x);

		for(usize x = 0; x < 5; ++x){
			Bprint(bp, "\t\tstate[%uzd] = array[%uzd]^"
					"((~array[%uzd])&array[%uzd]);\n",
					y+x, x, (x+1)%5, (x+2)%5);
		}
	}

	Bprint(bp, "\n\t\t/* iota */\n");
	Bprint(bp, "\t\tstate[0] ^= round_consts[idx];\n");

	Bprint(bp, "\t}\n");
	Bprint(bp, "}\n");
}

void
print_fn(Biobuf *bp, char *t, usize width, usize f_round_count)
{
	Bprint(bp, "#include <u.h>\n\n");
	Bprint(bp, "extern void keccak_p%uzd(%s *state, usize round_count);\n\n",
			width*200, t);
	Bprint(bp, "void\nkeccak_f%uzd(%s *state)\n{\n", width*200, t);
	Bprint(bp, "\tkeccak_p%uzd(state, %uzd);\n", width*200, f_round_count);
	Bprint(bp, "}\n");
}

void
gen1(char *t, usize width, usize f_round_count)
{
	char buf[128];
	sprint(buf, "p%uzd.c", width*200);
	Biobuf *bp = Bopen(buf, OWRITE);
	print_pn(bp, t, width, f_round_count);
	Bterm(bp);
	buf[0] = 'f';
	bp = Bopen(buf, OWRITE);
	print_fn(bp, t, width, f_round_count);
	Bterm(bp);
}

void
main(void)
{
	gen1("u8int",  1, 18);
	gen1("u16int", 2, 20);
	gen1("u32int", 4, 22);
	gen1("u64int", 8, 24);
	exits(nil);
}
