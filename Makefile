CC=gcc
CFLAGS=-Wall -Wextra -g -O -c
OUT=build

build: src/*.c include/*.h
	$(CC) src/*.c $(CFLAGS)
	ar -cvq libexalt.a *.o

clean: 
	rm -f *.o libexalt.a


