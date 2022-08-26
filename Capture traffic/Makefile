CFLAGS = -c -Wall
CC = gcc
LIBS =  -lpcap -lpthread

all: mirror

mirror: mirror.o capture.o build.o adapter.o helper.o
	${CC} mirror.o capture.o build.o adapter.o helper.o ${LIBS} -o mirror

mirror.o: mirror.c
	${CC} ${CFLAGS} mirror.c ${LIBS}

capture.o: capture.c
	${CC} ${CFLAGS} capture.c ${LIBS}

build.o: build.c
	${CC} ${CFLAGS} build.c ${LIBS}

adapter.o: adapter.c
	${CC} ${CFLAGS} adapter.c ${LIBS}

helper.o: helper.c
	${CC} ${CFLAGS} helper.c ${LIBS}

clean:
	rm -f *.o *~ *.out