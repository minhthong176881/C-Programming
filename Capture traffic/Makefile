CFLAGS = -c -Wall
CC = gcc
LIBS =  -lpcap

all: server

server: tpool.o server.o
	${CC} tpool.o server.o -o server.out

tpool.o: tpool.c
	${CC} ${CFLAGS} tpool.c 

server.o: server.c
	${CC} ${CFLAGS} server.c

clean:
	rm -f *.o *~ *.out