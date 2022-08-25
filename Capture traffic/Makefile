CFLAGS = -c -Wall
CC = gcc
LIBS =  -lpcap

all: mirror

mirror: mirror.o capture.o adapter.o helper.o
	${CC} mirror.o capture.o adapter.o helper.o ${LIBS} -o mirror

mirror.o: mirror.c
	${CC} ${CFLAGS} mirror.c ${LIBS}

capture.o: capture.c
	${CC} ${CFLAGS} capture.c ${LIBS}

adapter.o: adapter.c
	${CC} ${CFLAGS} adapter.c ${LIBS}

helper.o: helper.c
	${CC} ${CFLAGS} helper.c ${LIBS}

clean:
	rm -f *.o *~ *.out