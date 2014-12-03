all:libdes.a dofile
.PHONY:all
libdes.a:libdes.o leoDES2.o
	ar	crv libdes.a libdes.o leoDES2.o
libdes.o:libdes.c
	cc  -g -c libdes.c 
leoDES2.o:leoDES2.c
	cc  -g -c leoDES2.c 
dofile.o:dofile.c
	cc  -g -c dofile.c 
dofile:dofile.o
	cc  -g -o dofile dofile.c -I ./ -L ./ -ldes
