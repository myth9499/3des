all:libdes.a dofile
.PHONY:all
libdes.a:libdes.o leoDES2.o
	ar	crv libdes.a libdes.o leoDES2.o
libdes.o:libdes.c
	cc  -c libdes.c 
leoDES2.o:leoDES2.c
	cc  -c leoDES2.c 
dofile.o:dofile.c
	cc  -c dofile.c 
dofile:dofile.o
	cc  -o dofile dofile.c -I ./ -L ./ -ldes
