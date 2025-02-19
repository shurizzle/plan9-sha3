</$objtype/mkfile

LIB=libsha3.a

OFILES=\
	p200.$O\
	f200.$O\
	p400.$O\
	f400.$O\
	p800.$O\
	f800.$O\
	p1600.$O\
	f1600.$O\
	sha3.$O\

</sys/src/cmd/mklib

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
	rm -f *.[056789qvt] *.a[056789qvt] y.tab.? y.output y.error $CLEANFILES
