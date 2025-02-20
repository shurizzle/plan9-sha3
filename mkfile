</$objtype/mkfile

LIB=libsha3.a

OFILES=\
	port/p200.$O\
	port/f200.$O\
	port/p400.$O\
	port/f400.$O\
	port/p800.$O\
	port/f800.$O\
	port/p1600.$O\
	port/f1600.$O\
	$objtype/_sha3run.$O\
	port/_sha3xof.$O\
	port/sha3_224.$O\
	port/sha3_256.$O\
	port/sha3_384.$O\
	port/sha3_512.$O\
	port/keccak_224.$O\
	port/keccak_256.$O\
	port/keccak_384.$O\
	port/keccak_512.$O\
	port/keccak_256full.$O\
	port/shake_128.$O\
	port/shake_256.$O\
	port/turboshake_init.$O\
	port/turboshake_128.$O\
	port/turboshake_256.$O\
	$objtype/cshake_init_name.$O\
	port/cshake_128_init.$O\
	port/cshake_256_init.$O\
	port/cshake_128.$O\
	port/cshake_256.$O\

HFILES=\
	common.h\

</sys/src/cmd/mklib

%.$O: %.c
	$CC $CFLAGS -o $stem.$O $stem.c

test:VQ: $LIB
	if(! ~ $LIBDIR '/*' && ! ~ $LIBDIR '#*')
		__dir=`{pwd}^'/'$LIBDIR
	if not
		__dir=$LIBDIR
	if(test -d ./test)
		cd test && mk $MKFLAGS 'LIB='$__dir/$LIB test
	if not
		status=()

clean:V:
	test -d ./test && @{cd test && mk $MKFLAGS clean}
	rm -f *.[056789qvt] port/*.[056789qvt] $objtype/*.[056789qvt] *.a[056789qvt] y.tab.? y.output y.error $CLEANFILES
