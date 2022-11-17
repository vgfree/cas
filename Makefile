all:
	cd tools && ./cas_version_gen.sh build
	cd libcas && make all
	cd cascli && make all

clean:
	cd libcas && make clean
	cd cascli && make clean

distclean:
	cd libcas && make distclean
	cd cascli && make distclean
